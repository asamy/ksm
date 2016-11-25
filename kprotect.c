/*
 * ksm - a really simple and fast x64 hypervisor
 * Copyright (C) 2016 Ahmed Samy <f.fallen45@gmail.com>
 *
 * kprotect.c - protect driver sensitive pages.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include <ntddk.h>
#include <intrin.h>

#include "ksm.h"
#include "pe.h"
#include "dpc.h"

/*
 * This code shouldn't really be relayed upon, it can cause endless havoc
 * and is not well tested.
 */
static void *vpage;
static uintptr_t hpa;
extern uintptr_t g_driver_base;
extern uintptr_t g_driver_size;

bool kprotect_init_eptp(struct vcpu *vcpu, uintptr_t gpa)
{
	/* Get this CPU's EPT  */
	struct ept *ept = &vcpu->ept;

	/* EXHOOK execute only, redirect to normal page:  */
	ept_alloc_page(ept, EPT4(ept, EPTP_EXHOOK), EPT_ACCESS_EXEC, gpa);

	/* RWHOOK readwrite only, redirect to zero page:  */
	uintptr_t *epte = ept_alloc_page(ept, EPT4(ept, EPTP_RWHOOK), EPT_ACCESS_RW, gpa);
	__set_epte_ar_pfn(epte, EPT_ACCESS_RW, hpa >> PAGE_SHIFT);

	/* NORMAL readwrite only, redirect to normal page:  */
	epte = ept_alloc_page(ept, EPT4(ept, EPTP_NORMAL), EPT_ACCESS_RW, gpa);

	__invept_all();
	return true;
}

u16 kprotect_select_eptp(struct ept *ept, u64 rip, u8 ac)
{
	if (ac & EPT_ACCESS_EXEC)
		return EPTP_EXHOOK;

	if (rip >= g_driver_base && rip < g_driver_base + g_driver_size)
		return EPTP_NORMAL;

	return EPTP_RWHOOK;
}

STATIC_DEFINE_DPC(kprotect_page, __vmx_vmcall, HYPERCALL_KPROTECT, ctx);
static void kprotect_driver_pages(void)
{
	size_t pages[512];
	size_t count = 0;

	/*
	 * Protect only executable driver pages for now...
	 * I'll improve this later.
	 *
	 * This has multiple problems, most notably:
	 *	.text section (specifically on CL) will contain
	 *	strings, causing the print interface to cause a lot
	 *	of violations.
	 */
	PIMAGE_NT_HEADERS hdr = RtlImageNtHeader((void *)g_driver_base);
	PIMAGE_SECTION_HEADER first = (PIMAGE_SECTION_HEADER)(hdr + 1);
	PIMAGE_SECTION_HEADER last = first + hdr->FileHeader.NumberOfSections - 1;
	for (PIMAGE_SECTION_HEADER sec = last; sec >= first && count < 512; --sec) {
		if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE))
			continue;

		uintptr_t sec_base = (uintptr_t)PAGE_ALIGN(g_driver_base + (uintptr_t)sec->VirtualAddress);
		uintptr_t sec_size = sec->Misc.VirtualSize;
		uintptr_t nr_pages = BYTES_TO_PAGES(sec_size);
		VCPU_DEBUG("%s: has %d pages (addr %p)\n", sec->Name, nr_pages, sec_base);

		uintptr_t *head_page = va_to_pte(sec_base);
		uintptr_t *tail_page = head_page + nr_pages;
		for (uintptr_t *page = head_page; page < tail_page; ++page) {
			uintptr_t va = __pte_to_va(page);
			if (is_phys(va)) {
				uintptr_t *map = va_to_pte(va);
				uintptr_t spa = PAGE_PA(*map);
				uintptr_t poff = sec_base + ((page - head_page) << PAGE_SHIFT);

				/*
				 * For obvious reasons, ignore __ept_violation, otherwise
				 * we will cause havoc.
				 */
				if (PAGE_ALIGN(poff) != PAGE_ALIGN(__ept_violation))
					pages[count++] = spa;
			}
		}
	}

	/* Protect MSR and IO bitmaps  */
	pages[count++] = __pa(ksm.msr_bitmap);
	pages[count++] = __pa(ksm.io_bitmap_a);
	pages[count++] = __pa(ksm.io_bitmap_b);

	for (size_t i = 0; i < count; ++i)
		STATIC_CALL_DPC(kprotect_page, (void *)pages[i]);
}

NTSTATUS kprotect_init(void)
{
	vpage = mm_alloc_pool(NonPagedPool, PAGE_SIZE);
	if (!vpage)
		return STATUS_NO_MEMORY;

	hpa = __pa(vpage);
	kprotect_driver_pages();
	return STATUS_SUCCESS;
}

NTSTATUS kprotect_exit(void)
{
	__mm_free_pool(vpage);
	return STATUS_SUCCESS;
}
