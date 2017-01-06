/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016, 2017 Ahmed Samy <asamy@protonmail.com>
 *
 * kmap_virt() from KSplice:
 *	Copyright (C) 2007-2009  Ksplice, Inc.
 *	Authors: Jeff Arnold, Anders Kaseorg, Tim Abbott
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; If not, see <http://www.gnu.org/licenses/>.
*/
#ifdef __linux__
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/io.h>
#include <linux/ioport.h>
#else
#include <ntddk.h>
#endif

#include "ksm.h"
#include "mm.h"
#include "compiler.h"

#ifdef __linux__
extern struct resource iomem_resource;

struct remap_region {
	struct vm_struct *area;
	struct list_head link;
};
static LIST_HEAD(remap_list);

static inline struct remap_region *find_remap_region(void *addr)
{
	struct remap_region *r;

	list_for_each_entry(r, &remap_list, link)
		if (r->area->addr == addr)
			return r;

	return NULL;
}

void *mm_remap(u64 phys, size_t size)
{
	/*
	 * Since we can't use ioremap() for physical RAM, we are just going to
	 * allocate some memory then re-map it using the VM API.  Just like
	 * ioremap()...
	 *
	 * Note that we can't just allocate from other APIs and just use
	 * ioremap_page_range() here, this will generate #UD because the VA may
	 * be already mapped.
	 *
	 * This is guaranteed to allocate via swappers PGD (init_mm).
	 */
	unsigned long vaddr;
	unsigned long last;
	unsigned long offset;
	struct vm_struct *area;
	struct remap_region *region;

	region = mm_alloc_pool(sizeof(*region));
	if (!region)
		return NULL;

	area = __get_vm_area(size, VM_IOREMAP | VM_LOCKED, VMALLOC_START, VMALLOC_END);
	if (!area)
		goto err_region;

	offset = phys & ~PAGE_MASK;
	phys &= PHYSICAL_PAGE_MASK;
	last = phys + size - 1;
	size = PAGE_ALIGN(last + 1) - phys;

	area->phys_addr = phys;
	vaddr = (unsigned long)area->addr;

	/* Just assume RW mapping.  */
	if (ioremap_page_range(vaddr, vaddr + size, phys, PAGE_KERNEL_IO))
		goto err_area;

	region->area = area;
	list_add(&region->link, &remap_list);
	return (void *)(vaddr + offset);

err_area:
	free_vm_area(area);
err_region:
	mm_free_pool(region, sizeof(*region));
	return NULL;
}

void mm_unmap(void *vaddr, size_t size)
{
	struct remap_region *region;
	void *addr = (void *)((unsigned long)vaddr & PAGE_MASK);

	region = find_remap_region(addr);
	if (!region) {
		printk(KERN_ERR "mm_unmap(): bad address %p\n", addr);
		dump_stack();
		return;
	}

	free_vm_area(region->area);
	list_del(&region->link);
	mm_free_pool(region, sizeof(*region));
}

/*
 *  Original:
 *	 * map_writable creates a shadow page mapping of the range
 *	 [addr, addr + len) so that we can write to code mapped read-only.
 *
 *	 It is similar to a generalized version of x86's text_poke.  But
 *	 because one cannot use vmalloc/vfree() inside stop_machine, we use
 *	 map_writable to map the pages before stop_machine, then use the
 *	 mapping inside stop_machine, and unmap the pages afterwards.
 *
 *	https://github.com/jirislaby/ksplice
 *	kmodsrc/ksplice.c
 *
 * Converted to take a page protection instead.
 */
void *kmap_virt(void *addr, size_t len, pgprot_t prot)
{
	int i;
	void *vaddr;
	int nr_pages = DIV_ROUND_UP(offset_in_page(addr) + len, PAGE_SIZE);
	struct page **pages = kmalloc(nr_pages * sizeof(*pages), GFP_KERNEL);
	void *page_addr = (void *)((unsigned long)addr & PAGE_MASK);

	if (!pages)
		return NULL;

	for (i = 0; i < nr_pages; ++i) {
		if (!__module_address((unsigned long)page_addr)) {
			pages[i] = virt_to_page(page_addr);
			WARN_ON(!PageReserved(pages[i]));
		} else {
			/* Modules are allocated via vmalloc() which is
			 * non-contiguous.  */
			pages[i] = vmalloc_to_page(page_addr);
		}

		if (!pages[i]) {
			kfree(pages);
			return NULL;
		}

		page_addr += PAGE_SIZE;
	}

	vaddr = vmap(pages, nr_pages, VM_MAP, prot);
	kfree(pages);
	if (!vaddr)
		return NULL;

	return vaddr + offset_in_page(addr);
}

static void iter_resource(struct pmem_range *ranges,
			  struct resource *resource,
			  const char *match,
			  int *curr)
{
	struct resource *tmp;
	if (*curr >= MAX_RANGES)
		return;

	for (tmp = resource; tmp && *curr < MAX_RANGES; tmp = tmp->child) {
		if (strcmp(tmp->name, match) == 0) {
			ranges[*curr].start = tmp->start;
			ranges[*curr].end = tmp->end;
			++*curr;
		}

		if (tmp->sibling)
			iter_resource(ranges, tmp->sibling, match, curr);
	}
}

int mm_cache_ram_ranges(struct pmem_range *ranges, int *range_count)
{
	iter_resource(ranges, &iomem_resource, "System RAM", range_count);
	return 0;
}
#else

int mm_cache_ram_ranges(struct pmem_range *ranges, int *range_count)
{
	int run;
	uintptr_t addr;
	uintptr_t size;
	PPHYSICAL_MEMORY_RANGE pm_ranges;

	pm_ranges = MmGetPhysicalMemoryRanges();
	if (!pm_ranges)
		return ERR_NOMEM;

	for (run = 0; run < MAX_RANGES; ++run) {
		addr = pm_ranges[run].BaseAddress.QuadPart;
		size = pm_ranges[run].NumberOfBytes.QuadPart;
		if (!addr && !size)
			break;

		ranges[run].start = addr;
		ranges[run].end = addr + size;
	}

	*range_count = run;
	ExFreePool(pm_ranges);
	return 0;
}
#endif

