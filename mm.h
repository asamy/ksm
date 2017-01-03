/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016 Ahmed Samy <asamy@protonmail.com>
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
#ifndef __MM_H
#define __MM_H

#ifdef __linux__
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/sched.h>
#endif

#ifndef PXI_SHIFT
#define PXI_SHIFT		39
#endif

#ifndef PPI_SHIFT
#define PPI_SHIFT		30
#endif

#ifndef PDI_SHIFT
#define PDI_SHIFT		21
#endif

#ifndef PTI_SHIFT
#define PTI_SHIFT		12
#endif

#ifndef PTE_SHIFT
#define PTE_SHIFT		3
#endif

#define VA_BITS			48
#define VA_MASK			((1ULL << VA_BITS) - 1)
#define VA_SHIFT		16

#ifndef PTX_MASK
#define PTX_MASK		0x1FF
#endif

#ifndef PPI_MASK
#define PPI_MASK		0x3FFFF
#endif

#ifndef PDI_MASK
#define PDI_MASK		0x7FFFFFF
#endif

#ifndef PTI_MASK
#define PTI_MASK		0xFFFFFFFFF
#endif

#ifndef __linux__
/* be in the same boat  */
typedef struct { unsigned long long pgd; } pgd_t;
typedef struct { unsigned long long pud; } pud_t;
typedef struct { unsigned long long pmd; } pmd_t;
typedef struct { unsigned long long pte; } pte_t;

extern uintptr_t pxe_base;
extern uintptr_t ppe_base;
extern uintptr_t pde_base;
extern uintptr_t pte_base;
#endif

#define PAGE_PRESENT		0x1
#define PAGE_WRITE		0x2
#define PAGE_USER		0x4
#define PAGE_WRITETHRU		0x8
#define PAGE_CACHEDISABLE	0x10
#define PAGE_ACCESSED		0x20
#define PAGE_DIRTY		0x40
#define PAGE_LARGE		0x80
#define PAGE_GLOBAL		0x100
#define PAGE_COPYONWRITE	0x200
#define PAGE_PROTOTYPE		0x400
#define PAGE_TRANSIT		0x800
#define PAGE_PA_MASK		(0xFFFFFFFFFULL << PAGE_SHIFT)
#define PAGE_PA(page)		((page) & PAGE_PA_MASK)
#define PAGE_FN(page)		(((page) >> PTI_SHIFT) & PTI_MASK)
#define PAGE_PPA(pte)		(PAGE_PA(pte->pte))
#define PAGE_PFN(pte)		(PAGE_FN(pte->pte))
#define PAGE_SOFT_WS_IDX_SHIFT	52
#define PAGE_SOFT_WS_IDX_MASK	0xFFF
#define PAGE_NX			0x8000000000000000
#define PAGE_LPRESENT		(PAGE_PRESENT | PAGE_LARGE)

#define PGF_PRESENT		0x1	/* present fault  */
#define PGF_WRITE		0x2	/* write fault  */
#define PGF_SP			0x4	/* supervisor fault (SMEP, SMAP)  */
#define PGF_RSVD		0x8	/* reserved bit was set fault  */
#define PGF_FETCH		0x10	/* fetch fault  */
#define PGF_PK			0x20	/* Protection key fault  */
#define PGF_SGX			0x40	/* SGX induced fault  */

#define __pxe_idx(addr)		(((addr) >> PXI_SHIFT) & PTX_MASK)
#define __ppe_idx(addr)		(((addr) >> PPI_SHIFT) & PTX_MASK)
#define __pde_idx(addr)		(((addr) >> PDI_SHIFT) & PTX_MASK)
#define __pte_idx(addr)		(((addr) >> PTI_SHIFT) & PTX_MASK)

#ifndef __linux__
#define __pa(va)	\
	MmGetPhysicalAddress((void *)(va)).QuadPart
#define __va(pa)	\
	(uintptr_t *)MmGetVirtualForPhysical((PHYSICAL_ADDRESS) { .QuadPart = (uintptr_t)(pa) })
#endif

#define page_align(addr)	((uintptr_t)(addr) & ~(PAGE_SIZE - 1))
static inline bool page_aligned(uintptr_t addr)
{
	return (addr & (PAGE_SIZE - 1)) == 0;
}

static inline size_t round_to_pages(size_t size)
{
	return (size >> PAGE_SHIFT) + ((size & (PAGE_SIZE - 1)) != 0);
}

static inline u16 addr_offset(uintptr_t addr)
{
	/* Get the lower 12 bits which represent the offset  */
	return addr & (PAGE_SIZE - 1);
}

static inline bool same_page(uintptr_t a1, uintptr_t a2)
{
	return page_align(a1) == page_align(a2);
}

static inline bool is_canonical_addr(u64 addr)
{
	return (s64)addr >> 47 == (s64)addr >> 63;
}

static inline bool pte_large(pte_t pte)
{
	return pte.pte & PAGE_LARGE;
}

#ifndef __linux__
static inline bool pte_present(pte_t pte)
{
	return pte.pte & (PAGE_PRESENT | PAGE_GLOBAL);
}

static inline bool pte_trans(pte_t pte)
{
	return pte.pte & PAGE_TRANSIT;
}

static inline bool pte_prototype(pte_t pte)
{
	return pte.pte & PAGE_PROTOTYPE;
}

static inline bool pte_large_present(pte_t pte)
{
	return (pte.pte & PAGE_LPRESENT) == PAGE_LPRESENT;
}

static inline bool pte_swapper(pte_t pte)
{
	if (!pte_present(pte))
		return false;

	return pte_trans(pte) && !pte_prototype(pte);
}

static inline pgd_t *va_to_pgd(uintptr_t va)
{
	uintptr_t off = (va >> PXI_SHIFT) & PTX_MASK;
	return (pgd_t *)pxe_base + off;
}

static inline pud_t *va_to_pud(uintptr_t va)
{
	uintptr_t off = (va >> PPI_SHIFT) & PPI_MASK;
	return (pud_t *)ppe_base + off;
}

static inline pmd_t *va_to_pmd(uintptr_t va)
{
	uintptr_t off = (va >> PDI_SHIFT) & PDI_MASK;
	return (pmd_t *)pde_base + off;
}

static inline pte_t *va_to_pte(uintptr_t va)
{
	uintptr_t off = (va >> PTI_SHIFT) & PTI_MASK;
	return (pte_t *)pte_base + off;
}

static inline uintptr_t __pte_to_va(pte_t pte)
{
	return (((pte.pte - pte_base) << (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> VA_SHIFT);
}

static inline bool consult_vad(u64 va)
{
	return !pte_present(*(pte_t *)va_to_pmd(va)) || va_to_pte(va)->pte == 0;
}

static inline bool is_software_pte(pte_t pte)
{
	return !pte_trans(pte) && !pte_prototype(pte);
}

static inline bool is_subsection_pte(pte_t pte)
{
	return !pte_present(pte) && pte_prototype(pte);
}

static inline bool is_demandzero_pte(pte_t pte)
{
	return !pte_present(pte) && !pte_prototype(pte) && !pte_trans(pte);
}

static inline bool is_phys(uintptr_t va)
{
	return pte_present(*(pte_t *)va_to_pgd(va)) && pte_present(*(pte_t *)va_to_pud(va)) &&
		(pte_large_present(*(pte_t *)va_to_pmd(va)) || (pte_present(*va_to_pte(va))));
}
#else
static inline pgd_t *va_to_pgd(uintptr_t va)
{
	return pgd_offset(current->mm, va);
}

static inline pud_t *va_to_pud(uintptr_t va)
{
	return pud_offset(va_to_pgd(va), va);
}

static inline pmd_t *va_to_pmd(uintptr_t va)
{
	return pmd_offset(va_to_pud(va), va);
}

static inline pte_t *va_to_pte(uintptr_t va)
{
	return pte_offset_kernel(va_to_pmd(va), va);
}

static inline uintptr_t __pte_to_va(pte_t pte)
{
	struct page *page = pfn_to_page(PAGE_FN(pte.pte));
	if (!page)
		return 0;

	return (uintptr_t)page_address(page);
}

static inline void __stosq(unsigned long long *a, unsigned long x, unsigned long count)
{
	/* Generates stosq anyway...  */
	memset(a, x, count << 3);
}
#endif

static inline void *pte_to_va(pte_t pte)
{
	return (void *)__pte_to_va(pte);
}

static inline u64 *page_addr(pte_t *pte)
{
	if (!pte_present(*pte))
		return 0;

	return __va(PAGE_PPA(pte));
}

static inline u64 va_to_pa(uintptr_t va)
{
	pte_t *pte = (pte_t *)va_to_pmd(va);
	if (!pte_large(*pte))
		pte = va_to_pte(va);

	if (!pte_present(*pte))
		return 0;

	return PAGE_PPA(pte) | addr_offset(va);
}

#ifdef __linux__
static inline pte_t *__cr3_resolve_va(uintptr_t cr3, uintptr_t va)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = pgd_offset(current->mm, va);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return 0;

	pud = pud_offset(pgd, va);
	if (pud_none(*pud) || pud_bad(*pud))
		return 0;

	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return 0;

	pte = pte_offset_kernel(pmd, va);
	return pte;
}
#else
static inline pte_t *__cr3_resolve_va(u64 cr3, u64 va)
{
	/* NB: You can also use va_to_pte / va_to_pmd, etc.  */
	pte_t *pml4 = (pte_t *)__va(cr3 & PAGE_PA_MASK);
	pgd_t *pdpt = page_addr(&pml4[__pxe_idx(va)]);
	if (!pdpt)
		return 0;

	pud_t *pdt = page_addr(&pdpt[__ppe_idx(va)]);
	if (!pdt)
		return 0;

	pmd_t *pdte = &pdt[__pde_idx(va)];
	if (!pte_present(*(pte_t *)pdte))
		return 0;

	if (pte_large(*(pte_t *)pdte))
		return pdte;

	pte_t *pt = page_addr(pdte);
	if (pt)
		return &pt[__pte_idx(va)];

	return 0;
}

static inline u64 cr3_resolve_va(uintptr_t cr3, uintptr_t va)
{
	pte_t *pte = __cr3_resolve_va(cr3, va);
	if (!pte_present(*pte))
		return 0;

	return PAGE_PPA(pte) | addr_offset(va);
}
#endif

static inline void *mm_alloc_page(void)
{
#ifndef __linux__
	void *v = ExAllocatePool(NonPagedPool, PAGE_SIZE);
	if (v)
		__stosq(v, 0, PAGE_SIZE >> 3);

	return v;
#else
	return (void *)get_zeroed_page(GFP_KERNEL);
#endif
}

static inline void __mm_free_page(void *v)
{
#ifndef __linux__
	ExFreePool(v);
#else
	free_page((unsigned long)v);
#endif
}

static inline void mm_free_page(void *v)
{
	__stosq(v, 0, PAGE_SIZE >> 3);
	__mm_free_page(v);
}

static inline void *mm_alloc_pool(size_t size)
{
#ifndef __linux__
	void *v = ExAllocatePool(NonPagedPool, size);
	if (v)
		__stosq(v, 0, size >> 3);

	return v;
#else
	return kmalloc(size, GFP_KERNEL | __GFP_ZERO);
#endif
}

static inline void mm_free_pool(void *v, size_t size)
{
	if (size)
		__stosq(v, 0, size >> 3);

#ifdef __linux__
	kfree(v);
#else
	ExFreePool(v);
#endif
}

#ifndef __linux__
static inline void *mm_remap(u64 phys, size_t size)
{
	return MmMapIoSpace((PHYSICAL_ADDRESS) { .QuadPart = phys }, size, MmNonCached);
}

static inline void mm_unmap(void *addr, size_t size)
{
	return MmUnmapIoSpace(addr, size);
}
#else
extern void *mm_remap(u64 phys, size_t size);
extern void mm_unmap(void *addr, size_t size);
extern void *kmap_virt(void *addr, size_t len, pgprot_t prot);
static inline void *kmap_exec(void *addr, size_t len)
{
	return kmap_virt(addr, len, PAGE_KERNEL_EXEC);
}

static inline void *kmap_write(void *addr, size_t len)
{
	return kmap_virt(addr, len, PAGE_KERNEL);
}
#endif
#endif
