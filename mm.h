/* Several helper memory management functions regarding
  * paging and page tarnsition state.  */
#ifndef __MM_H
#define __MM_H

#ifndef PXI_SHIFT
#define PXI_SHIFT			39
#endif

#ifndef PPI_SHIFT
#define PPI_SHIFT			30
#endif

#ifndef PDI_SHIFT
#define PDI_SHIFT			21
#endif

#ifndef PTI_SHIFT
#define PTI_SHIFT			12
#endif

#ifndef PTE_SHIFT
#define PTE_SHIFT			3
#endif

#define VA_BITS				48
#define VA_MASK				((1ULL << VA_BITS) - 1)
#define VA_SHIFT			16

#ifndef PTX_MASK
#define PTX_MASK			0x1FF
#endif

#ifndef PPI_MASK
#define PPI_MASK			0x3FFFF
#endif

#ifndef PDI_MASK
#define PDI_MASK			0x7FFFFFF
#endif

#ifndef PTI_MASK
#define PTI_MASK			0xFFFFFFFFF
#endif

extern uintptr_t pxe_base;
extern uintptr_t ppe_base;
extern uintptr_t pde_base;
extern uintptr_t pte_base;

static uintptr_t pxe_top = 0xFFFFF6FB7DBEDFFFULL;
static uintptr_t ppe_top = 0xFFFFF6FB7DBFFFFFULL;
static uintptr_t pde_top = 0xFFFFF6FB7FFFFFFFULL;
static uintptr_t pte_top = 0xFFFFF6FFFFFFFFFFULL;

#define PAGE_PRESENT			0x1
#define PAGE_WRITE			0x2
#define PAGE_OWNER			0x4
#define PAGE_WRITETHRU			0x8
#define PAGE_CACHEDISABLE		0x10
#define PAGE_ACCESSED			0x20
#define PAGE_DIRTY			0x40
#define PAGE_LARGE			0x80
#define PAGE_GLOBAL			0x100
#define PAGE_COPYONWRITE		0x200
#define PAGE_PROTOTYPE			0x400
#define PAGE_TRANSIT			0x800
#define PAGE_MASK			(0xFFFFFFFFFULL << PAGE_SHIFT)
#define PAGE_PA(page)			((page) & PAGE_MASK)
#define PAGE_FN(page)			(((page) >> PTI_SHIFT) & PTI_MASK)
#define PAGE_SOFT_WS_IDX_SHIFT		52
#define PAGE_SOFT_WS_IDX_MASK		0xFFF
#define PAGE_NX				0x8000000000000000
#define PAGE_LPRESENT			(PAGE_PRESENT | PAGE_LARGE)

#define __pxe_idx(phys)			(((phys) >> PXI_SHIFT) & PTX_MASK)
#define __ppe_idx(phys)			(((phys) >> PPI_SHIFT) & PTX_MASK)
#define __pde_idx(phys)			(((phys) >> PDI_SHIFT) & PTX_MASK)
#define __pte_idx(phys)			(((phys) >> PTI_SHIFT) & PTX_MASK)

#define __pa(va)			(uintptr_t)MmGetPhysicalAddress((void *)(va)).QuadPart
#define __va(pa)			(uintptr_t *)MmGetVirtualForPhysical((PHYSICAL_ADDRESS) { .QuadPart = (pa) })

static inline uintptr_t *page_addr(uintptr_t *page)
{
	if (!*page)
		return 0;

	return __va(PAGE_PA(*page));
}

static inline int pte_soft_ws_idx(uintptr_t *pte)
{
	return (*pte >> PAGE_SOFT_WS_IDX_SHIFT) & PAGE_SOFT_WS_IDX_MASK;
}

static inline bool pte_present(uintptr_t *pte)
{
	return *pte & PAGE_PRESENT;
}

static inline bool pte_large(uintptr_t *pte)
{
	return *pte & PAGE_LARGE;
}

static inline bool pte_trans(uintptr_t *pte)
{
	return *pte & PAGE_TRANSIT;
}

static inline bool pte_prototype(uintptr_t *pte)
{
	return *pte & PAGE_PROTOTYPE;
}

static inline bool pte_large_present(uintptr_t *pte)
{
	return (*pte & PAGE_LPRESENT) == PAGE_LPRESENT;
}

static inline bool pte_swapper(uintptr_t *pte)
{
	if (pte_present(pte))
		return false;

	return pte_trans(pte) && !pte_prototype(pte);
}

static inline uintptr_t *va_to_pxe(uintptr_t va)
{
	uintptr_t off = (va >> PXI_SHIFT) & PTX_MASK;
	return (uintptr_t *)pxe_base + off;
}

static inline uintptr_t *va_to_ppe(uintptr_t va)
{
	uintptr_t off = (va >> PPI_SHIFT) & PPI_MASK;
	return (uintptr_t *)ppe_base + off;
}

static inline uintptr_t *va_to_pde(uintptr_t va)
{
	uintptr_t off = (va >> PDI_SHIFT) & PDI_MASK;
	return (uintptr_t *)pde_base + off;
}

static inline uintptr_t *va_to_pte(uintptr_t va)
{
	uintptr_t off = (va >> PTI_SHIFT) & PTI_MASK;
	return (uintptr_t *)pte_base + off;
}

static inline uintptr_t __pte_to_va(uintptr_t *pte)
{
	return ((((uintptr_t)pte - pte_base) << (PAGE_SHIFT + VA_SHIFT - PTE_SHIFT)) >> VA_SHIFT);
}

static inline void *pte_to_va(uintptr_t *pte)
{
	return (void *)__pte_to_va(pte);
}

static inline u16 addr_offset(uintptr_t va)
{
	/* Get the lower 12 bits which represent the offset  */
	return va & (PAGE_SIZE - 1);
}

static inline uintptr_t va_to_pa(uintptr_t va)
{
	uintptr_t *pte = va_to_pde(va);
	if (!pte_large(pte))
		pte = va_to_pte(va);

	if (!pte_present(pte))
		return 0;

	return PAGE_PA(*pte) | addr_offset(va);
}

static inline bool consult_vad(uintptr_t va)
{
	return !pte_present(va_to_pde(va)) || *va_to_pte(va) == 0;
}

static inline bool is_software_pte(uintptr_t *pte)
{
	return !pte_trans(pte) && !pte_prototype(pte);
}

static inline bool is_subsection_pte(uintptr_t *pte)
{
	return !pte_present(pte) && pte_prototype(pte);
}

static inline bool is_demandzero_pte(uintptr_t *pte)
{
	return !pte_present(pte) && !pte_prototype(pte) && !pte_trans(pte);
}

static inline bool is_phys(uintptr_t va)
{
	return pte_present(va_to_pxe(va)) && pte_present(va_to_ppe(va)) &&
		(pte_large_present(va_to_pde(va)) || pte_present(va_to_pte(va)));
}

/* Transitition page  (Unique defines only...)  */
#define PTT_PROTECTION_SHIFT	5
#define PTT_PROTECTION_MASK	0x1F

static inline u8 ptt_protection(uintptr_t *pte)
{
	return (*pte >> PTT_PROTECTION_SHIFT) & PTT_PROTECTION_MASK;
}

/* Prototype PTE  (Unique defines only...)  */
#define PRT_PROTECTION_SHIFT		11
#define PRT_PROTECTION_MASK		0x3F
#define PRT_PROTO_ADDRESS_SHIFT		VA_SHIFT
#define PRT_PROTO_ADDRESS_MASK		VA_MASK
#define PRT_READONLY			0x100

static inline u8 prt_prot(uintptr_t *pte)
{
	return (*pte >> PRT_PROTECTION_SHIFT) & PRT_PROTECTION_MASK;
}

static inline uintptr_t prt_addr(uintptr_t *pte)
{
	return (*pte >> PRT_PROTO_ADDRESS_SHIFT) & PRT_PROTO_ADDRESS_MASK;
}

static inline bool prt_ro(uintptr_t *pte)
{
	return *pte & PRT_READONLY;
}

static inline bool prt_is_vad(uintptr_t *pte)
{
	return prt_addr(pte) == 0xFFFFFFFF0000;
}

/* Software PTE  */
#define SPTE_PF_LO_SHIFT	1			/* Number of page file (up to 16) */
#define SPTE_PF_LO_MASK		0x1F
#define SPTE_PF_HI_SHIFT	32			/* Page file offset (multiple of PAGE_SIZE)  */
#define SPTE_PF_HI_MASK		0xFFFFFFFF
#define SPTE_IN_STORE_MASK	0x400000
#define SPTE_PROTECTION_SHIFT	5
#define SPTE_PROTECTION_MASK	0x1F

static inline bool spte_in_store(uintptr_t *spte)
{
	return *spte & SPTE_IN_STORE_MASK;
}

static inline bool spte_prot(uintptr_t *spte)
{
	return (*spte >> SPTE_PROTECTION_SHIFT) & SPTE_PROTECTION_MASK;
}

static inline u32 spte_pg_hi(uintptr_t *spte)
{
	return (*spte >> SPTE_PF_HI_SHIFT) & SPTE_PF_HI_MASK;
}

static inline u32 spte_pg_lo(uintptr_t *spte)
{
	return (*spte >> SPTE_PF_LO_SHIFT) & SPTE_PF_LO_MASK;
}

#if 0
/* Subsection prototype PTE  */
#define SSP_SUBST_ADDR_SHIFT	VA_SHIFT
#define SSP_SUBST_ADDR_MASK	VA_MASK

struct subsection {
	void *ctl_area;
	void *subst_base;
	struct subsection *next;
	u32 nr_ptes;
	PMM_AVL_TABLE global_per_session_head;
	u32 unused_ptes;
	u64 pad_union_unnamed;
	u32 starting_sector;
	u32 nr_full_sectors;
};

static inline uintptr_t subst_addr(uintptr_t *pte)
{
	return (*pte >> SSP_SUBST_ADDR_SHIFT) & SSP_SUBST_ADDR_MASK;
}
#endif

static __forceinline void *mm_alloc_pool(POOL_TYPE type, size_t size)
{
	void *v = ExAllocatePool(type, size);
	if (v)
		memset(v, 0, size);

	return v;
}

static __forceinline void mm_free_pool(void *v, size_t size)
{
	memset(v, 0, size);
	ExFreePool(v);
}

static __forceinline void __mm_free_pool(void *v)
{
	ExFreePool(v);
}

#endif
