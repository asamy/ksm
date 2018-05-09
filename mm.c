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

void *mm_remap(u64 phys, size_t size)
{
	unsigned long offset = addr_offset(phys);
	struct page *page;
	void *ret;

	/* For now this supports one-page at a time.  */
	WARN_ON(size > PAGE_SIZE);

	page = pfn_to_page(phys >> PAGE_SHIFT);
	ret = vmap(&page, 1, VM_LOCKED, PAGE_KERNEL);
	if (!ret)
		return NULL;

	return (void *)(ret + offset);
}

void mm_unmap(void *vaddr, size_t size)
{
	void *addr = (void *)((unsigned long)vaddr & PAGE_MASK);
	vunmap(addr);
}

void *mm_remap_iomem(u64 phys, size_t size)
{
	return ioremap(phys, size);
}

void mm_unmap_iomem(void *addr, size_t size)
{
	return iounmap((void __iomem __force *)addr);
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

static inline void make_mtrr_range(struct mtrr_range *range, bool fixed, u8 type,
				   u64 start, u64 end)
{
	range->fixed = fixed;
	range->type = type;
	range->start = start;
	range->end = end;
}

void mm_cache_mtrr_ranges(struct mtrr_range *ranges, int *range_count, u8 *def_type)
{
	u64 def, cap;
	u64 msr;
	u32 val;
	u64 base;
	u64 offset;
	int num_var;
	int idx = 0;
	int i;
	u32 len;

	def = __readmsr(MSR_MTRRdefType);
	*def_type = def & 0xFF;

	cap = __readmsr(MSR_MTRRcap);
	num_var = cap & 0xFF;

	if ((cap >> 8) & 1 && (def >> 10) & 1) {
		/* Read fixed range MTRRs.  */
		for (msr = __readmsr(MSR_MTRRfix64K_00000), offset = 0, base = 0;
		     msr != 0; msr >>= 8, offset += 0x10000, base += offset)
			make_mtrr_range(&ranges[idx++], true, msr & 0xff, base, base + 0x10000 - 1);

		for (val = MSR_MTRRfix16K_80000, offset = 0; val <= MSR_MTRRfix16K_A0000; ++val)
			for (msr = __readmsr(val), base = 0x80000;
			     msr != 0; msr >>= 8, offset += 0x4000, base += offset)
				make_mtrr_range(&ranges[idx++], true, msr & 0xff, base, base + 0x4000 - 1);

		for (val = MSR_MTRRfix4K_C0000, offset = 0; val <= MSR_MTRRfix4K_F8000; ++val)
			for (msr = __readmsr(val), base = 0xC0000;
			     msr != 0; msr >>= 8, offset += 0x1000, base += offset)
				make_mtrr_range(&ranges[idx++], true, msr & 0xff, base, base + 0x1000 - 1);
	}

	for (i = 0; i < num_var; i++) {
		msr = __readmsr(MSR_MTRR_PHYS_MASK + i * 2);
		if (!((msr >> 11) & 1))
			continue;

		len = 1 << __ffs64(msr & PAGE_PA_MASK);
		base = __readmsr(MSR_MTRR_PHYS_BASE + i * 2);
		make_mtrr_range(&ranges[idx++], false,
				base & 0xff,
				base & PAGE_PA_MASK,
				(base & PAGE_PA_MASK) + len - 1);
	}

	*range_count = idx;
}
