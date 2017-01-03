/*
 * VT-x based stuff here, only defines, etc...
 * Hacked from the Linux kernel.
 *
 * Partially taken from arch/x86/include/asm/virtext.h:
 *	CPU virtualization extensions handling
 *
 *	This should carry the code for handling CPU virtualization extensions
 *	that needs to live in the kernel core.
 *
 *	Author: Eduardo Habkost <ehabkost@redhat.com>
 *
 *	Copyright (C) 2008, Red Hat Inc.
 *	Contains code from KVM, Copyright (C) 2006 Qumranet, Inc.
 *
 *	This work is licensed under the terms of the GNU GPL, version 2.  See
 *	the COPYING file in the top-level directory.
 *
 * Along with modification from:
 *	Ahmed Samy, 2016 <asamy@protonmail.com>
 * Windows fixes, inline assembler intrinsics definitions
 * and updates from the Intel manual tables.
 *
 * Virtual VMCS layout From XEN:
 *	include/asm-x86/hvm/vmx/vvmx.h
 *	arch/x86/hvm/vmx/vvmx.c
 *
 * Copyright (c) 2010, Intel Corporation.
 * Author: Qing He <qing.he@intel.com>
 *         Eddie Dong <eddie.dong@intel.com>
 */
#ifndef __VMX_H
#define __VMX_H

#define CPU_BASED_VIRTUAL_INTR_PENDING          0x00000004
#define CPU_BASED_USE_TSC_OFFSETING             0x00000008
#define CPU_BASED_HLT_EXITING                   0x00000080
#define CPU_BASED_INVLPG_EXITING                0x00000200
#define CPU_BASED_MWAIT_EXITING                 0x00000400
#define CPU_BASED_RDPMC_EXITING                 0x00000800
#define CPU_BASED_RDTSC_EXITING                 0x00001000
#define CPU_BASED_CR3_LOAD_EXITING		0x00008000
#define CPU_BASED_CR3_STORE_EXITING		0x00010000
#define CPU_BASED_CR8_LOAD_EXITING              0x00080000
#define CPU_BASED_CR8_STORE_EXITING             0x00100000
#define CPU_BASED_TPR_SHADOW                    0x00200000
#define CPU_BASED_VIRTUAL_NMI_PENDING		0x00400000
#define CPU_BASED_MOV_DR_EXITING                0x00800000
#define CPU_BASED_UNCOND_IO_EXITING             0x01000000
#define CPU_BASED_USE_IO_BITMAPS                0x02000000
#define CPU_BASED_MONITOR_TRAP_FLAG             0x08000000
#define CPU_BASED_USE_MSR_BITMAPS               0x10000000
#define CPU_BASED_MONITOR_EXITING               0x20000000
#define CPU_BASED_PAUSE_EXITING                 0x40000000
#define CPU_BASED_ACTIVATE_SECONDARY_CONTROLS   0x80000000

#define SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES 0x00000001
#define SECONDARY_EXEC_ENABLE_EPT               0x00000002
#define SECONDARY_EXEC_DESC_TABLE_EXITING	0x00000004
#define SECONDARY_EXEC_RDTSCP			0x00000008
#define SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE   0x00000010
#define SECONDARY_EXEC_ENABLE_VPID              0x00000020
#define SECONDARY_EXEC_WBINVD_EXITING		0x00000040
#define SECONDARY_EXEC_UNRESTRICTED_GUEST	0x00000080
#define SECONDARY_EXEC_APIC_REGISTER_VIRT       0x00000100
#define SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY    0x00000200
#define SECONDARY_EXEC_PAUSE_LOOP_EXITING	0x00000400
#define SECONDARY_EXEC_RDRAND_EXITING		0x00000800
#define SECONDARY_EXEC_ENABLE_INVPCID		0x00001000
#define SECONDARY_EXEC_ENABLE_VMFUNC		0x00002000
#define SECONDARY_EXEC_SHADOW_VMCS              0x00004000
#define SECONDARY_EXEC_ENABLE_ENCLS_EXITING	0x00008000
#define SECONDARY_EXEC_ENABLE_PML               0x00020000
#define SECONDARY_EXEC_ENABLE_VE		0x00040000
#define SECONDARY_EXEC_CONCEAL_VMX_IPT		0x00080000
#define SECONDARY_EXEC_XSAVES			0x00100000
#define SECONDARY_EXEC_PCOMMIT			0x00200000
#define SECONDARY_EXEC_TSC_SCALING              0x02000000

#define PIN_BASED_EXT_INTR_MASK                 0x00000001
#define PIN_BASED_NMI_EXITING                   0x00000008
#define PIN_BASED_VIRTUAL_NMIS                  0x00000020
#define PIN_BASED_VMX_PREEMPTION_TIMER          0x00000040
#define PIN_BASED_POSTED_INTR                   0x00000080

#define VM_EXIT_SAVE_DEBUG_CONTROLS             0x00000004
#define VM_EXIT_HOST_ADDR_SPACE_SIZE            0x00000200
#define VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL      0x00001000
#define VM_EXIT_ACK_INTR_ON_EXIT                0x00008000
#define VM_EXIT_SAVE_IA32_PAT			0x00040000
#define VM_EXIT_LOAD_IA32_PAT			0x00080000
#define VM_EXIT_SAVE_IA32_EFER                  0x00100000
#define VM_EXIT_LOAD_IA32_EFER                  0x00200000
#define VM_EXIT_SAVE_VMX_PREEMPTION_TIMER       0x00400000
#define VM_EXIT_CLEAR_BNDCFGS                   0x00800000
#define VM_EXIT_CONCEAL_IPT			0x01000000

#define VM_ENTRY_LOAD_DEBUG_CONTROLS            0x00000004
#define VM_ENTRY_IA32E_MODE                     0x00000200
#define VM_ENTRY_SMM                            0x00000400
#define VM_ENTRY_DEACT_DUAL_MONITOR             0x00000800
#define VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL     0x00002000
#define VM_ENTRY_LOAD_IA32_PAT			0x00004000
#define VM_ENTRY_LOAD_IA32_EFER                 0x00008000
#define VM_ENTRY_LOAD_BNDCFGS                   0x00010000
#define VM_ENTRY_CONCEAL_IPT			0x00020000

#define VMX_MISC_PREEMPTION_TIMER_RATE_MASK	0x0000001f
#define VMX_MISC_SAVE_EFER_LMA			0x00000020
#define VMX_MISC_ACTIVITY_HLT			0x00000040

#define VM_FUNCTION_CTL_EPTP_SWITCHING		0x00000001

 /* VMCS Encodings */
enum vmcs_field {
	VIRTUAL_PROCESSOR_ID = 0x00000000,
	POSTED_INTR_NV = 0x00000002,
	EPTP_INDEX = 0x00000004,
	GUEST_ES_SELECTOR = 0x00000800,
	GUEST_CS_SELECTOR = 0x00000802,
	GUEST_SS_SELECTOR = 0x00000804,
	GUEST_DS_SELECTOR = 0x00000806,
	GUEST_FS_SELECTOR = 0x00000808,
	GUEST_GS_SELECTOR = 0x0000080a,
	GUEST_LDTR_SELECTOR = 0x0000080c,
	GUEST_TR_SELECTOR = 0x0000080e,
	GUEST_INTR_STATUS = 0x00000810,
	GUEST_PML_INDEX = 0x00000812,
	HOST_ES_SELECTOR = 0x00000c00,
	HOST_CS_SELECTOR = 0x00000c02,
	HOST_SS_SELECTOR = 0x00000c04,
	HOST_DS_SELECTOR = 0x00000c06,
	HOST_FS_SELECTOR = 0x00000c08,
	HOST_GS_SELECTOR = 0x00000c0a,
	HOST_TR_SELECTOR = 0x00000c0c,
	IO_BITMAP_A = 0x00002000,
	IO_BITMAP_A_HIGH = 0x00002001,
	IO_BITMAP_B = 0x00002002,
	IO_BITMAP_B_HIGH = 0x00002003,
	MSR_BITMAP = 0x00002004,
	MSR_BITMAP_HIGH = 0x00002005,
	VM_EXIT_MSR_STORE_ADDR = 0x00002006,
	VM_EXIT_MSR_STORE_ADDR_HIGH = 0x00002007,
	VM_EXIT_MSR_LOAD_ADDR = 0x00002008,
	VM_EXIT_MSR_LOAD_ADDR_HIGH = 0x00002009,
	VM_ENTRY_MSR_LOAD_ADDR = 0x0000200a,
	VM_ENTRY_MSR_LOAD_ADDR_HIGH = 0x0000200b,
	PML_ADDRESS = 0x0000200e,
	PML_ADDRESS_HIGH = 0x0000200f,
	TSC_OFFSET = 0x00002010,
	TSC_OFFSET_HIGH = 0x00002011,
	VIRTUAL_APIC_PAGE_ADDR = 0x00002012,
	VIRTUAL_APIC_PAGE_ADDR_HIGH = 0x00002013,
	APIC_ACCESS_ADDR = 0x00002014,
	APIC_ACCESS_ADDR_HIGH = 0x00002015,
	POSTED_INTR_DESC_ADDR = 0x00002016,
	POSTED_INTR_DESC_ADDR_HIGH = 0x00002017,
	VM_FUNCTION_CTRL = 0x00002018,
	VM_FUNCTION_CTRL_HIGH = 0x00002019,
	EPT_POINTER = 0x0000201a,
	EPT_POINTER_HIGH = 0x0000201b,
	EOI_EXIT_BITMAP0 = 0x0000201c,
	EOI_EXIT_BITMAP0_HIGH = 0x0000201d,
	EOI_EXIT_BITMAP1 = 0x0000201e,
	EOI_EXIT_BITMAP1_HIGH = 0x0000201f,
	EOI_EXIT_BITMAP2 = 0x00002020,
	EOI_EXIT_BITMAP2_HIGH = 0x00002021,
	EOI_EXIT_BITMAP3 = 0x00002022,
	EOI_EXIT_BITMAP3_HIGH = 0x00002023,
	EPTP_LIST_ADDRESS = 0x00002024,
	EPTP_LIST_ADDRESS_HIGH = 0x00002025,
	VMREAD_BITMAP = 0x00002026,
	VMREAD_BITMAP_HIGH = 0x00002027,
	VMWRITE_BITMAP = 0x00002028,
	VMWRITE_BITMAP_HIGH = 0x00002029,
	VE_INFO_ADDRESS = 0x0000202A,
	VE_INFO_ADDRESS_HIGH = 0x0000202B,
	XSS_EXIT_BITMAP = 0x0000202C,
	XSS_EXIT_BITMAP_HIGH = 0x0000202D,
	TSC_MULTIPLIER = 0x00002032,
	TSC_MULTIPLIER_HIGH = 0x00002033,
	GUEST_PHYSICAL_ADDRESS = 0x00002400,
	GUEST_PHYSICAL_ADDRESS_HIGH = 0x00002401,
	VMCS_LINK_POINTER = 0x00002800,
	VMCS_LINK_POINTER_HIGH = 0x00002801,
	GUEST_IA32_DEBUGCTL = 0x00002802,
	GUEST_IA32_DEBUGCTL_HIGH = 0x00002803,
	GUEST_IA32_PAT = 0x00002804,
	GUEST_IA32_PAT_HIGH = 0x00002805,
	GUEST_IA32_EFER = 0x00002806,
	GUEST_IA32_EFER_HIGH = 0x00002807,
	GUEST_IA32_PERF_GLOBAL_CTRL = 0x00002808,
	GUEST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002809,
	GUEST_PDPTR0 = 0x0000280a,
	GUEST_PDPTR0_HIGH = 0x0000280b,
	GUEST_PDPTR1 = 0x0000280c,
	GUEST_PDPTR1_HIGH = 0x0000280d,
	GUEST_PDPTR2 = 0x0000280e,
	GUEST_PDPTR2_HIGH = 0x0000280f,
	GUEST_PDPTR3 = 0x00002810,
	GUEST_PDPTR3_HIGH = 0x00002811,
	GUEST_BNDCFGS = 0x00002812,
	GUEST_BNDCFGS_HIGH = 0x00002813,
	HOST_IA32_PAT = 0x00002c00,
	HOST_IA32_PAT_HIGH = 0x00002c01,
	HOST_IA32_EFER = 0x00002c02,
	HOST_IA32_EFER_HIGH = 0x00002c03,
	HOST_IA32_PERF_GLOBAL_CTRL = 0x00002c04,
	HOST_IA32_PERF_GLOBAL_CTRL_HIGH = 0x00002c05,
	PIN_BASED_VM_EXEC_CONTROL = 0x00004000,
	CPU_BASED_VM_EXEC_CONTROL = 0x00004002,
	EXCEPTION_BITMAP = 0x00004004,
	PAGE_FAULT_ERROR_CODE_MASK = 0x00004006,
	PAGE_FAULT_ERROR_CODE_MATCH = 0x00004008,
	CR3_TARGET_COUNT = 0x0000400a,
	VM_EXIT_CONTROLS = 0x0000400c,
	VM_EXIT_MSR_STORE_COUNT = 0x0000400e,
	VM_EXIT_MSR_LOAD_COUNT = 0x00004010,
	VM_ENTRY_CONTROLS = 0x00004012,
	VM_ENTRY_MSR_LOAD_COUNT = 0x00004014,
	VM_ENTRY_INTR_INFO_FIELD = 0x00004016,
	VM_ENTRY_EXCEPTION_ERROR_CODE = 0x00004018,
	VM_ENTRY_INSTRUCTION_LEN = 0x0000401a,
	TPR_THRESHOLD = 0x0000401c,
	SECONDARY_VM_EXEC_CONTROL = 0x0000401e,
	PLE_GAP = 0x00004020,
	PLE_WINDOW = 0x00004022,
	VM_INSTRUCTION_ERROR = 0x00004400,
	VM_EXIT_REASON = 0x00004402,
	VM_EXIT_INTR_INFO = 0x00004404,
	VM_EXIT_INTR_ERROR_CODE = 0x00004406,
	IDT_VECTORING_INFO_FIELD = 0x00004408,
	IDT_VECTORING_ERROR_CODE = 0x0000440a,
	VM_EXIT_INSTRUCTION_LEN = 0x0000440c,
	VMX_INSTRUCTION_INFO = 0x0000440e,
	GUEST_ES_LIMIT = 0x00004800,
	GUEST_CS_LIMIT = 0x00004802,
	GUEST_SS_LIMIT = 0x00004804,
	GUEST_DS_LIMIT = 0x00004806,
	GUEST_FS_LIMIT = 0x00004808,
	GUEST_GS_LIMIT = 0x0000480a,
	GUEST_LDTR_LIMIT = 0x0000480c,
	GUEST_TR_LIMIT = 0x0000480e,
	GUEST_GDTR_LIMIT = 0x00004810,
	GUEST_IDTR_LIMIT = 0x00004812,
	GUEST_ES_AR_BYTES = 0x00004814,
	GUEST_CS_AR_BYTES = 0x00004816,
	GUEST_SS_AR_BYTES = 0x00004818,
	GUEST_DS_AR_BYTES = 0x0000481a,
	GUEST_FS_AR_BYTES = 0x0000481c,
	GUEST_GS_AR_BYTES = 0x0000481e,
	GUEST_LDTR_AR_BYTES = 0x00004820,
	GUEST_TR_AR_BYTES = 0x00004822,
	GUEST_INTERRUPTIBILITY_INFO = 0x00004824,
	GUEST_ACTIVITY_STATE = 0X00004826,
	GUEST_SMBASE = 0x00004828,
	GUEST_SYSENTER_CS = 0x0000482A,
	VMX_PREEMPTION_TIMER_VALUE = 0x0000482E,
	HOST_IA32_SYSENTER_CS = 0x00004c00,
	CR0_GUEST_HOST_MASK = 0x00006000,
	CR4_GUEST_HOST_MASK = 0x00006002,
	CR0_READ_SHADOW = 0x00006004,
	CR4_READ_SHADOW = 0x00006006,
	CR3_TARGET_VALUE0 = 0x00006008,
	CR3_TARGET_VALUE1 = 0x0000600a,
	CR3_TARGET_VALUE2 = 0x0000600c,
	CR3_TARGET_VALUE3 = 0x0000600e,
	EXIT_QUALIFICATION = 0x00006400,
	IO_RCX = 0x00006402,
	IO_RSI = 0x00006404,
	IO_RDI = 0x00006406,
	IO_RIP = 0x00006408,
	GUEST_LINEAR_ADDRESS = 0x0000640a,
	GUEST_CR0 = 0x00006800,
	GUEST_CR3 = 0x00006802,
	GUEST_CR4 = 0x00006804,
	GUEST_ES_BASE = 0x00006806,
	GUEST_CS_BASE = 0x00006808,
	GUEST_SS_BASE = 0x0000680a,
	GUEST_DS_BASE = 0x0000680c,
	GUEST_FS_BASE = 0x0000680e,
	GUEST_GS_BASE = 0x00006810,
	GUEST_LDTR_BASE = 0x00006812,
	GUEST_TR_BASE = 0x00006814,
	GUEST_GDTR_BASE = 0x00006816,
	GUEST_IDTR_BASE = 0x00006818,
	GUEST_DR7 = 0x0000681a,
	GUEST_RSP = 0x0000681c,
	GUEST_RIP = 0x0000681e,
	GUEST_RFLAGS = 0x00006820,
	GUEST_PENDING_DBG_EXCEPTIONS = 0x00006822,
	GUEST_SYSENTER_ESP = 0x00006824,
	GUEST_SYSENTER_EIP = 0x00006826,
	HOST_CR0 = 0x00006c00,
	HOST_CR3 = 0x00006c02,
	HOST_CR4 = 0x00006c04,
	HOST_FS_BASE = 0x00006c06,
	HOST_GS_BASE = 0x00006c08,
	HOST_TR_BASE = 0x00006c0a,
	HOST_GDTR_BASE = 0x00006c0c,
	HOST_IDTR_BASE = 0x00006c0e,
	HOST_IA32_SYSENTER_ESP = 0x00006c10,
	HOST_IA32_SYSENTER_EIP = 0x00006c12,
	HOST_RSP = 0x00006c14,
	HOST_RIP = 0x00006c16,
};

/*
* Interruption-information format
*/
#define INTR_INFO_VECTOR_MASK           0xff            /* 7:0 */
#define INTR_INFO_INTR_TYPE_MASK        0x700           /* 10:8 */
#define INTR_INFO_DELIVER_CODE_MASK     0x800           /* 11 */
#define INTR_INFO_UNBLOCK_NMI		0x1000		/* 12 */
#define INTR_INFO_VALID_MASK            0x80000000      /* 31 */
#define INTR_INFO_RESVD_BITS_MASK       0x7ffff000

#define VECTORING_INFO_VECTOR_MASK 		INTR_INFO_VECTOR_MASK
#define VECTORING_INFO_TYPE_MASK        	INTR_INFO_INTR_TYPE_MASK
#define VECTORING_INFO_DELIVER_CODE_MASK    	INTR_INFO_DELIVER_CODE_MASK
#define VECTORING_INFO_VALID_MASK       	INTR_INFO_VALID_MASK

#define INTR_TYPE_EXT_INTR              (0 << 8) /* external interrupt */
#define INTR_TYPE_NMI_INTR		(2 << 8) /* NMI */
#define INTR_TYPE_HARD_EXCEPTION	(3 << 8) /* processor exception */
#define INTR_TYPE_SOFT_INTR             (4 << 8) /* software interrupt */
#define INTR_TYPE_SOFT_EXCEPTION	(6 << 8) /* software exception */

/* GUEST_INTERRUPTIBILITY_INFO flags. */
#define GUEST_INTR_STATE_STI		0x00000001
#define GUEST_INTR_STATE_MOV_SS		0x00000002
#define GUEST_INTR_STATE_SMI		0x00000004
#define GUEST_INTR_STATE_NMI		0x00000008

/* GUEST_ACTIVITY_STATE flags */
#define GUEST_ACTIVITY_ACTIVE		0
#define GUEST_ACTIVITY_HLT		1
#define GUEST_ACTIVITY_SHUTDOWN		2
#define GUEST_ACTIVITY_WAIT_SIPI	3

/*
* Exit Qualifications for MOV for Control Register Access
*/
#define CONTROL_REG_ACCESS_NUM          0x7     /* 2:0, number of control reg.*/
#define CONTROL_REG_ACCESS_TYPE         0x30    /* 5:4, access type */
#define CONTROL_REG_ACCESS_REG          0xf00   /* 10:8, general purpose reg. */
#define LMSW_SOURCE_DATA_SHIFT 16
#define LMSW_SOURCE_DATA  (0xFFFF << LMSW_SOURCE_DATA_SHIFT) /* 16:31 lmsw source */

/*
* Exit Qualifications for MOV for Debug Register Access
*/
#define DEBUG_REG_ACCESS_NUM            0x7     /* 2:0, number of debug reg. */
#define DEBUG_REG_ACCESS_TYPE           0x10    /* 4, direction of access */
#define TYPE_MOV_TO_DR                  (0 << 4)
#define TYPE_MOV_FROM_DR                (1 << 4)
#define DEBUG_REG_ACCESS_REG(eq)        (((eq) >> 8) & 0xf) /* 11:8, general purpose reg. */


/*
* Exit Qualifications for APIC-Access
*/
#define APIC_ACCESS_OFFSET              0xfff   /* 11:0, offset within the APIC page */
#define APIC_ACCESS_TYPE                0xf000  /* 15:12, access type */
#define TYPE_LINEAR_APIC_INST_READ      (0 << 12)
#define TYPE_LINEAR_APIC_INST_WRITE     (1 << 12)
#define TYPE_LINEAR_APIC_INST_FETCH     (2 << 12)
#define TYPE_LINEAR_APIC_EVENT          (3 << 12)
#define TYPE_PHYSICAL_APIC_EVENT        (10 << 12)
#define TYPE_PHYSICAL_APIC_INST         (15 << 12)

/* segment AR in VMCS -- these are different from what LAR reports */
#define VMX_SEGMENT_AR_L_MASK (1 << 13)

#define VMX_AR_TYPE_ACCESSES_MASK 1
#define VMX_AR_TYPE_READABLE_MASK (1 << 1)
#define VMX_AR_TYPE_WRITEABLE_MASK (1 << 2)
#define VMX_AR_TYPE_CODE_MASK (1 << 3)
#define VMX_AR_TYPE_MASK 0x0f
#define VMX_AR_TYPE_BUSY_64_TSS 11
#define VMX_AR_TYPE_BUSY_32_TSS 11
#define VMX_AR_TYPE_BUSY_16_TSS 3
#define VMX_AR_TYPE_LDT 2

#define VMX_AR_UNUSABLE_MASK (1 << 16)
#define VMX_AR_S_MASK (1 << 4)
#define VMX_AR_P_MASK (1 << 7)
#define VMX_AR_L_MASK (1 << 13)
#define VMX_AR_DB_MASK (1 << 14)
#define VMX_AR_G_MASK (1 << 15)
#define VMX_AR_DPL_SHIFT 5
#define VMX_AR_DPL(ar) (((ar) >> VMX_AR_DPL_SHIFT) & 3)

#define VMX_AR_RESERVD_MASK 0xfffe0f00

#define VMX_VPID_EXTEND_INDIVIDUAL_ADDR		0
#define VMX_VPID_EXTENT_SINGLE_CONTEXT		1
#define VMX_VPID_EXTENT_ALL_CONTEXT		2
#define VMX_VPID_EXTEND_ALL_GLOBAL		3
#define VMX_VPID_EXTENT_SHIFT			40

#define VMX_EPT_EXTENT_CONTEXT			1
#define VMX_EPT_EXTENT_GLOBAL			2
#define VMX_EPT_EXTENT_SHIFT			24

#define VMX_EPT_EXECUTE_ONLY_BIT		(1ull)
#define VMX_EPT_PAGE_WALK_4_BIT			(1ull << 6)
#define VMX_EPTP_UC_BIT				(1ull << 8)
#define VMX_EPTP_WB_BIT				(1ull << 14)
#define VMX_EPT_2MB_PAGE_BIT			(1ull << 16)
#define VMX_EPT_1GB_PAGE_BIT			(1ull << 17)
#define VMX_EPT_INVEPT_BIT			(1ull << 20)
#define VMX_EPT_AD_BIT				    (1ull << 21)
#define VMX_EPT_EXTENT_CONTEXT_BIT		(1ull << 25)
#define VMX_EPT_EXTENT_GLOBAL_BIT		(1ull << 26)

#define VMX_VPID_INVVPID_BIT                    (1ull << 0) /* (32 - 32) */
#define VMX_VPID_EXTENT_SINGLE_CONTEXT_BIT      (1ull << 9) /* (41 - 32) */
#define VMX_VPID_EXTENT_GLOBAL_CONTEXT_BIT      (1ull << 10) /* (42 - 32) */

#define VMX_EPT_DEFAULT_GAW			3
#define VMX_EPT_MAX_GAW				0x4
#define VMX_EPT_MT_EPTE_SHIFT			3
#define VMX_EPT_GAW_EPTP_SHIFT			3
#define VMX_EPT_AD_ENABLE_BIT			(1ull << 6)
#define VMX_EPT_DEFAULT_MT			0x6ull
#define VMX_EPT_READABLE_MASK			0x1ull
#define VMX_EPT_WRITABLE_MASK			0x2ull
#define VMX_EPT_EXECUTABLE_MASK			0x4ull
#define VMX_EPT_IPAT_BIT    			(1ull << 6)
#define VMX_EPT_ACCESS_BIT				(1ull << 8)
#define VMX_EPT_DIRTY_BIT				(1ull << 9)

typedef struct {
	u64 vpid : 16;
	u64 rsvd : 48;
	u64 gva;
} invvpid_t;

typedef struct {
	u64 ptr;
	u64 gpa;
} invept_t;

#ifndef _MSC_VER
#define ASM_VMX_VMCLEAR_RAX       ".byte 0x66, 0x0f, 0xc7, 0x30"
#define ASM_VMX_VMLAUNCH          ".byte 0x0f, 0x01, 0xc2"
#define ASM_VMX_VMRESUME          ".byte 0x0f, 0x01, 0xc3"
#define ASM_VMX_VMPTRLD_RAX       ".byte 0x0f, 0xc7, 0x30"
#define ASM_VMX_VMXOFF            ".byte 0x0f, 0x01, 0xc4"
#define ASM_VMX_VMXON_RAX         ".byte 0xf3, 0x0f, 0xc7, 0x30"
#define ASM_VMX_INVEPT		  ".byte 0x66, 0x0f, 0x38, 0x80, 0x0A"
#define ASM_VMX_INVVPID		  ".byte 0x66, 0x0f, 0x38, 0x81, 0x0A"
#define ASM_VMX_VMFUNC		  ".byte 0x0f, 0x01, 0xd4"

static inline u8 __vmx_on(unsigned long long *pa)
{
	u8 error;
	__asm __volatile(ASM_VMX_VMXON_RAX "; setna %0"
			 : "=q" (error)
			 : "a"(pa), "m"(*pa)
			 : "memory", "cc");
	return error;
}

static inline u8 __vmx_off(void)
{
	u8 error;
	__asm __volatile(ASM_VMX_VMXOFF "; setna %0"
			 : "=q" (error)
			 : /* no reads  */
			 : "cc");
	return error;
}

static inline u8 __vmx_vmlaunch(void)
{
	u8 error;
	__asm __volatile(ASM_VMX_VMLAUNCH "; setna %0"
			 : "=q" (error) :: "cc");
	return error;
}

static inline u8 __vmx_vmclear(unsigned long long *pa)
{
	u8 error;
	__asm __volatile(ASM_VMX_VMCLEAR_RAX "; setna %0"
			 : "=qm" (error) : "a" (pa), "m" (*pa)
			 : "cc", "memory");
	return error;
}

static inline u8 __vmx_vmptrld(unsigned long long *pa)
{
	u8 error;
	__asm __volatile(ASM_VMX_VMPTRLD_RAX "; setna %0"
			 : "=qm" (error) : "a" (pa), "m" (*pa)
			 : "cc", "memory");
	return error;
}

static inline u8 __vmx_vmread(size_t field, size_t *value)
{
	size_t tmp;
	u8 error;
	__asm __volatile("vmread %[Field], %[Value]; setna %[Err]"
			 : [Value] "=r" (tmp), [Err] "=qm" (error)
			 : [Field] "r" (field)
			 : "cc");
	*value = tmp;
	return error;
}

static inline u8 __vmx_vmwrite(size_t field, size_t value)
{
	u8 error;
	__asm __volatile("vmwrite %[Value], %[Field]; setna %[Err]"
			 : [Err] "=qm" (error)
			 : [Value] "r" (value), [Field] "r" (field)
			 : "cc");
	return error;
}

static inline u8 __vmx_vmcall(uintptr_t hc, void *d)
{
	u8 error;
	__asm __volatile("vmcall; setna %0"
			 : "=q" (error) : "c" (hc), "d" (d)
			 : "cc");
	return error;
}

static inline u8 __vmx_vmfunc(u32 eptp, u32 func)
{
	u8 error;
	__asm __volatile(ASM_VMX_VMFUNC "; setna %0"
			 : "=q" (error) : "c" (eptp), "a" (func)
			 : "cc");
	return error;
}

static inline u8 __invept(int ext, const invept_t *i)
{
	u8 error;
	__asm __volatile(ASM_VMX_INVEPT "; setna %0"
			 : "=q" (error) : "d" (i), "c" (ext)
			 : "cc", "memory");
	return error;
}

static inline u8 __invvpid(int ext, const invvpid_t *i)
{
	u8 error;
	__asm __volatile(ASM_VMX_INVVPID "; setna %0"
			 : "=q" (error): "d" (i), "c" (ext)
			 : "cc", "memory");
	return error;
}
#else
extern u8 __invvpid(u32 type, const invvpid_t *i);
extern u8 __invept(u32 type, const invept_t *i);

extern u8 __vmx_vmcall(uintptr_t, void *);
extern u8 __vmx_vmfunc(u32, u32);
#endif

static const u32 supported_fields[] = {
	VIRTUAL_PROCESSOR_ID,
	EPTP_INDEX,
	GUEST_ES_SELECTOR,
	GUEST_CS_SELECTOR,
	GUEST_SS_SELECTOR,
	GUEST_DS_SELECTOR,
	GUEST_FS_SELECTOR,
	GUEST_GS_SELECTOR,
	GUEST_LDTR_SELECTOR,
	GUEST_TR_SELECTOR,
	GUEST_INTR_STATUS,
	GUEST_PML_INDEX,
	HOST_ES_SELECTOR,
	HOST_CS_SELECTOR,
	HOST_SS_SELECTOR,
	HOST_DS_SELECTOR,
	HOST_FS_SELECTOR,
	HOST_GS_SELECTOR,
	HOST_TR_SELECTOR,
	IO_BITMAP_A,
	IO_BITMAP_A_HIGH,
	IO_BITMAP_B,
	IO_BITMAP_B_HIGH,
	MSR_BITMAP,
	MSR_BITMAP_HIGH,
	PML_ADDRESS,
	PML_ADDRESS_HIGH,
	TSC_OFFSET,
	TSC_OFFSET_HIGH,
	VIRTUAL_APIC_PAGE_ADDR,
	VIRTUAL_APIC_PAGE_ADDR_HIGH,
	APIC_ACCESS_ADDR,
	APIC_ACCESS_ADDR_HIGH,
	POSTED_INTR_DESC_ADDR,
	POSTED_INTR_DESC_ADDR_HIGH,
	VM_FUNCTION_CTRL,
	VM_FUNCTION_CTRL_HIGH,
	EPT_POINTER,
	EPT_POINTER_HIGH,
	EOI_EXIT_BITMAP0,
	EOI_EXIT_BITMAP0_HIGH,
	EOI_EXIT_BITMAP1,
	EOI_EXIT_BITMAP1_HIGH,
	EOI_EXIT_BITMAP2,
	EOI_EXIT_BITMAP2_HIGH,
	EOI_EXIT_BITMAP3,
	EOI_EXIT_BITMAP3_HIGH,
	EPTP_LIST_ADDRESS,
	EPTP_LIST_ADDRESS_HIGH,
	VE_INFO_ADDRESS,
	VE_INFO_ADDRESS_HIGH,
	XSS_EXIT_BITMAP,
	XSS_EXIT_BITMAP_HIGH,
	TSC_MULTIPLIER,
	TSC_MULTIPLIER_HIGH,
	GUEST_PHYSICAL_ADDRESS,
	GUEST_PHYSICAL_ADDRESS_HIGH,
	VMCS_LINK_POINTER,
	VMCS_LINK_POINTER_HIGH,
	GUEST_IA32_DEBUGCTL,
	GUEST_IA32_DEBUGCTL_HIGH,
	GUEST_IA32_PAT,
	GUEST_IA32_PAT_HIGH,
	GUEST_IA32_EFER,
	GUEST_IA32_EFER_HIGH,
	GUEST_PDPTR0,
	GUEST_PDPTR0_HIGH,
	GUEST_PDPTR1,
	GUEST_PDPTR1_HIGH,
	GUEST_PDPTR2,
	GUEST_PDPTR2_HIGH,
	GUEST_PDPTR3,
	GUEST_PDPTR3_HIGH,
	GUEST_BNDCFGS,
	GUEST_BNDCFGS_HIGH,
	HOST_IA32_PAT,
	HOST_IA32_PAT_HIGH,
	HOST_IA32_EFER,
	HOST_IA32_EFER_HIGH,
	PIN_BASED_VM_EXEC_CONTROL,
	CPU_BASED_VM_EXEC_CONTROL,
	EXCEPTION_BITMAP,
	PAGE_FAULT_ERROR_CODE_MASK,
	PAGE_FAULT_ERROR_CODE_MATCH,
	CR3_TARGET_COUNT,
	VM_EXIT_CONTROLS,
	VM_EXIT_MSR_STORE_COUNT,
	VM_EXIT_MSR_LOAD_COUNT,
	VM_ENTRY_CONTROLS,
	VM_ENTRY_MSR_LOAD_COUNT,
	VM_ENTRY_INTR_INFO_FIELD,
	VM_ENTRY_EXCEPTION_ERROR_CODE,
	VM_ENTRY_INSTRUCTION_LEN,
	TPR_THRESHOLD,
	SECONDARY_VM_EXEC_CONTROL,
	VM_INSTRUCTION_ERROR,
	VM_EXIT_REASON,
	VM_EXIT_INTR_INFO,
	VM_EXIT_INTR_ERROR_CODE,
	IDT_VECTORING_INFO_FIELD,
	IDT_VECTORING_ERROR_CODE,
	VM_EXIT_INSTRUCTION_LEN,
	VMX_INSTRUCTION_INFO,
	GUEST_ES_LIMIT,
	GUEST_CS_LIMIT,
	GUEST_SS_LIMIT,
	GUEST_DS_LIMIT,
	GUEST_FS_LIMIT,
	GUEST_GS_LIMIT,
	GUEST_LDTR_LIMIT,
	GUEST_TR_LIMIT,
	GUEST_GDTR_LIMIT,
	GUEST_IDTR_LIMIT,
	GUEST_ES_AR_BYTES,
	GUEST_CS_AR_BYTES,
	GUEST_SS_AR_BYTES,
	GUEST_DS_AR_BYTES,
	GUEST_FS_AR_BYTES,
	GUEST_GS_AR_BYTES,
	GUEST_LDTR_AR_BYTES,
	GUEST_TR_AR_BYTES,
	GUEST_INTERRUPTIBILITY_INFO,
	GUEST_ACTIVITY_STATE,
	GUEST_SYSENTER_CS,
	HOST_IA32_SYSENTER_CS,
	CR0_GUEST_HOST_MASK,
	CR4_GUEST_HOST_MASK,
	CR0_READ_SHADOW,
	CR4_READ_SHADOW,
	CR3_TARGET_VALUE0,
	CR3_TARGET_VALUE1,
	CR3_TARGET_VALUE2,
	CR3_TARGET_VALUE3,
	EXIT_QUALIFICATION,
	GUEST_LINEAR_ADDRESS,
	GUEST_CR0,
	GUEST_CR3,
	GUEST_CR4,
	GUEST_ES_BASE,
	GUEST_CS_BASE,
	GUEST_SS_BASE,
	GUEST_DS_BASE,
	GUEST_FS_BASE,
	GUEST_GS_BASE,
	GUEST_LDTR_BASE,
	GUEST_TR_BASE,
	GUEST_GDTR_BASE,
	GUEST_IDTR_BASE,
	GUEST_DR7,
	GUEST_RSP,
	GUEST_RIP,
	GUEST_RFLAGS,
	GUEST_PENDING_DBG_EXCEPTIONS,
	GUEST_SYSENTER_ESP,
	GUEST_SYSENTER_EIP,
	HOST_CR0,
	HOST_CR3,
	HOST_CR4,
	HOST_FS_BASE,
	HOST_GS_BASE,
	HOST_TR_BASE,
	HOST_GDTR_BASE,
	HOST_IDTR_BASE,
	HOST_IA32_SYSENTER_ESP,
	HOST_IA32_SYSENTER_EIP,
	HOST_RSP,
	HOST_RIP,
};

/*
 * Virtual VMCS layout
 *
 * Since physical VMCS layout is unknown, a custom layout is used
 * for virtual VMCS seen by guest. It occupies a 4k page, and the
 * field is offset by an 9-bit offset into u64[], The offset is as
 * follow, which means every <width, type> pair has a max of 32
 * fields available.
 *
 *             9       7      5               0
 *             --------------------------------
 *     offset: | width | type |     index     |
 *             --------------------------------
 *
 * Also, since the lower range <width=0, type={0,1}> has only one
 * field: VPID, it is moved to a higher offset (63), and leaves the
 * lower range to non-indexed field like VMCS revision.
 *		-- End XEN
 *
 *		To make stuff more clear:
 *
 *	1. The VMCS encoding above is not actually the same as in
 *	   the sturcture, the first bit is the "access type", otherwise
 *	   they are all shifted 1 bit to the left.
 *
 *	2. The bits in these fields are also now documented in the
 *	   Intel manual, see below, some of which are quoted in comments.
 */
static inline u16 field_offset(u32 field)
{
	/*
	 * Intel manual:
	 *	- Index bits:
	 *		These fields are distinguished by their index value in bits 9:1.
	 *	- Access bit:
	 *		As noted in Section 24.11.2, each 32-bit field
	 *		allows only full access, meaning that bit 0 of its encoding is 0.
	 *		As noted in Section 24.11.2, every 64-bit field has two encodings,
	 *		which differ on bit 0, the access type. Thus, each such field has
	 *		an even encoding for full access and an odd encoding for high access.
	 */
	u16 index = (field >> 1) & 0x1F;
	u16 type = (field >> 10) & 3;
	u16 width = (field >> 13) & 3;

	u16 offset = index | type << 5 | width << 7;
	if (offset == 0)	/* VPID  */
		return 0x3F;

	return offset;
}

typedef enum {
	FIELD_U16 = 0,
	FIELD_U64 = 1,
	FIELD_U32 = 2,
	FIELD_NATURAL = 3,
} fwidth_t;

static inline fwidth_t field_width(u32 field)
{
	return (field >> 13) & 3;
}

typedef enum {
	/*
	 * According to the intel manual:
	 *	- A value of 0 in bits 11:10 of an encoding indicates a control field.
	 *	- A value of 1 in bits 11:10 of an encoding indicates a read-only data field.
	 *	- A value of 2 in bits 11:10 of an encoding indicates a field in the guest-state area
	 *	- A value of 3 in bits 11:10 of an encoding indicates a field in the host-state area.
	 */
	FIELD_CONTROL = 0,
	FIELD_READONLY = 1,
	FIELD_GUESTSTATE = 2,
	FIELD_HOSTSTATE = 3,
} ftype_t;

static inline ftype_t field_type(u32 field)
{
	return (field >> 10) & 3;
}

static inline bool field_ro(u32 field)
{
	return field_type(field) == FIELD_READONLY;
}

static inline bool field_supported(u32 field)
{
	if (field > HOST_RIP)
		return false;	/* quickie  */

	for (size_t i = 0; i < sizeof(supported_fields) / sizeof(supported_fields[0]); ++i)
		if (supported_fields[i] == field)
			return true;

	return false;
}

static inline void vmcs_check64(size_t field)
{
	if ((field & 0x6000) == 0 ||
	    (field & 0x6001) == 0x2001 ||
	    (field & 0x6000) == 0x4000 ||
	    (field & 0x6000) == 0x6000)
		dbgbreak();
}

static inline void vmcs_check32(size_t field)
{
#if 0
	if ((field & 0x6000) == 0 || (field & 0x6000) == 0x6000)
		dbgbreak();
#endif
}

static inline void vmcs_check16(size_t field)
{
	if ((field & 0x6001) == 0x2000 ||
	    (field & 0x6001) == 0x2001 ||
	    (field & 0x6000) == 0x4000 ||
	    (field & 0x6000) == 0x6000)
		dbgbreak();
}

static inline void vmcs_checkl(size_t field)
{
#if 0
	if ((field & 0x6000) == 0 ||
	    (field & 0x6001) == 0x2000 ||
	    (field & 0x6001) == 0x2001 ||
	    (field & 0x6000) == 0x4000)
		dbgbreak();
#endif
}

static inline size_t vmcs_read(size_t field)
{
	size_t value;
	vmcs_checkl(field);
	__vmx_vmread(field, &value);

	return value;
}

static inline size_t vmcs_readl(size_t field)
{
	return vmcs_read(field);
}

static inline u64 vmcs_read64(const size_t field)
{
	vmcs_check64(field);
	return (u64)vmcs_read(field);
}

static inline u32 vmcs_read32(size_t field)
{
	vmcs_check32(field);
	return (u32)vmcs_read(field);
}

static inline u16 vmcs_read16(size_t field)
{
	vmcs_check16(field);
	return (u16)vmcs_read32(field);
}

static inline u8 vmcs_write(size_t field, size_t value)
{
	vmcs_checkl(field);
	return __vmx_vmwrite(field, value);
}

static inline u8 vmcs_writel(size_t field, size_t value)
{
	return vmcs_write(field, value);
}

static inline u8 vmcs_write64(size_t field, u64 value)
{
	vmcs_check64(field);
	return __vmx_vmwrite(field, value);
}

static inline u8 vmcs_write32(size_t field, u32 value)
{
	vmcs_check32(field);
	return __vmx_vmwrite(field, value);
}

static inline u8 vmcs_write16(size_t field, u16 value)
{
	vmcs_check16(field);
	return __vmx_vmwrite(field, value);
}

static inline u8 __invept_all(void)
{
	return __invept(VMX_EPT_EXTENT_GLOBAL, &(invept_t) { 0, 0 });
}

static inline u8 __invept_gpa(u64 ptr, u64 gpa)
{
	return __invept(VMX_EPT_EXTENT_CONTEXT, &(invept_t) {
		.ptr = ptr,
		.gpa = gpa,
	});
}

static inline u8 __invvpid_all(void)
{
	return __invvpid(VMX_VPID_EXTENT_ALL_CONTEXT, &(invvpid_t) { 0, 0, 0 });
}

static inline u8 __invvpid_single(u16 vpid)
{
	return __invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, &(invvpid_t) {
		.vpid = vpid,
		.rsvd = 0,
		.gva = 0,
	});
}

static inline u8 __invvpid_no_global(u16 vpid)
{
	return __invvpid(VMX_VPID_EXTEND_ALL_GLOBAL, &(invvpid_t) {
		.vpid = vpid,
		.rsvd = 0,
		.gva = 0
	});
}

static inline u8 __invvpid_addr(u16 vpid, u64 gva)
{
	return __invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, &(invvpid_t) {
		.vpid = vpid,
		.rsvd = 0,
		.gva = gva
	});
}


/* avoid declared inside parameter list  */
struct vcpu;

/* Defined in assembly.  */
extern int __vmx_vminit(struct vcpu *);
extern void __vmx_entrypoint(void);
extern void __ept_violation(void);

/*
 * Exit Qualifications for entry failure during or after loading guest state
*/
#define ENTRY_FAIL_DEFAULT		0
#define ENTRY_FAIL_PDPTE		2
#define ENTRY_FAIL_NMI			3
#define ENTRY_FAIL_VMCS_LINK_PTR	4

/*
* VM-instruction error numbers
*/
enum vm_instruction_error_number {
	VMXERR_VMCALL_IN_VMX_ROOT_OPERATION = 1,
	VMXERR_VMCLEAR_INVALID_ADDRESS = 2,
	VMXERR_VMCLEAR_VMXON_POINTER = 3,
	VMXERR_VMLAUNCH_NONCLEAR_VMCS = 4,
	VMXERR_VMRESUME_NONLAUNCHED_VMCS = 5,
	VMXERR_VMRESUME_AFTER_VMXOFF = 6,
	VMXERR_ENTRY_INVALID_CONTROL_FIELD = 7,
	VMXERR_ENTRY_INVALID_HOST_STATE_FIELD = 8,
	VMXERR_VMPTRLD_INVALID_ADDRESS = 9,
	VMXERR_VMPTRLD_VMXON_POINTER = 10,
	VMXERR_VMPTRLD_INCORRECT_VMCS_REVISION_ID = 11,
	VMXERR_UNSUPPORTED_VMCS_COMPONENT = 12,
	VMXERR_VMWRITE_READ_ONLY_VMCS_COMPONENT = 13,
	VMXERR_VMXON_IN_VMX_ROOT_OPERATION = 15,
	VMXERR_ENTRY_INVALID_EXECUTIVE_VMCS_POINTER = 16,
	VMXERR_ENTRY_NONLAUNCHED_EXECUTIVE_VMCS = 17,
	VMXERR_ENTRY_EXECUTIVE_VMCS_POINTER_NOT_VMXON_POINTER = 18,
	VMXERR_VMCALL_NONCLEAR_VMCS = 19,
	VMXERR_VMCALL_INVALID_VM_EXIT_CONTROL_FIELDS = 20,
	VMXERR_VMCALL_INCORRECT_MSEG_REVISION_ID = 22,
	VMXERR_VMXOFF_UNDER_DUAL_MONITOR_TREATMENT_OF_SMIS_AND_SMM = 23,
	VMXERR_VMCALL_INVALID_SMM_MONITOR_FEATURES = 24,
	VMXERR_ENTRY_INVALID_VM_EXECUTION_CONTROL_FIELDS_IN_EXECUTIVE_VMCS = 25,
	VMXERR_ENTRY_EVENTS_BLOCKED_BY_MOV_SS = 26,
	VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID = 28,
};

#define VMX_EXIT_REASONS_FAILED_VMENTRY        0x80000000

#define EXIT_REASON_EXCEPTION_NMI       0
#define EXIT_REASON_EXTERNAL_INTERRUPT  1
#define EXIT_REASON_TRIPLE_FAULT        2
#define EXIT_REASON_INIT_SIGNAL 	3
#define EXIT_REASON_STARTUP_IPI 	4
#define EXIT_REASON_SMI_INTERRUPT 	5
#define EXIT_REASON_OTHER_SMI 		6
#define EXIT_REASON_PENDING_INTERRUPT   7
#define EXIT_REASON_NMI_WINDOW          8
#define EXIT_REASON_TASK_SWITCH         9
#define EXIT_REASON_CPUID               10
#define EXIT_REASON_GETSEC 		11
#define EXIT_REASON_HLT                 12
#define EXIT_REASON_INVD                13
#define EXIT_REASON_INVLPG              14
#define EXIT_REASON_RDPMC               15
#define EXIT_REASON_RDTSC               16
#define EXIT_REASON_RSM 		17
#define EXIT_REASON_VMCALL              18
#define EXIT_REASON_VMCLEAR             19
#define EXIT_REASON_VMLAUNCH            20
#define EXIT_REASON_VMPTRLD             21
#define EXIT_REASON_VMPTRST             22
#define EXIT_REASON_VMREAD              23
#define EXIT_REASON_VMRESUME            24
#define EXIT_REASON_VMWRITE             25
#define EXIT_REASON_VMOFF               26
#define EXIT_REASON_VMON                27
#define EXIT_REASON_CR_ACCESS           28
#define EXIT_REASON_DR_ACCESS           29
#define EXIT_REASON_IO_INSTRUCTION      30
#define EXIT_REASON_MSR_READ            31
#define EXIT_REASON_MSR_WRITE           32
#define EXIT_REASON_INVALID_STATE       33
#define EXIT_REASON_MSR_LOAD_FAIL       34
#define EXIT_REASON_UNKNOWN35 		35
#define EXIT_REASON_MWAIT_INSTRUCTION   36
#define EXIT_REASON_MONITOR_TRAP_FLAG   37
#define EXIT_REASON_UNKNOWN38 		38
#define EXIT_REASON_MONITOR_INSTRUCTION 39
#define EXIT_REASON_PAUSE_INSTRUCTION   40
#define EXIT_REASON_MCE_DURING_VMENTRY  41
#define EXIT_REASON_UNKNOWN42 		42
#define EXIT_REASON_TPR_BELOW_THRESHOLD 43
#define EXIT_REASON_APIC_ACCESS         44
#define EXIT_REASON_EOI_INDUCED         45
#define EXIT_REASON_GDT_IDT_ACCESS	46
#define EXIT_REASON_LDT_TR_ACCESS	47
#define EXIT_REASON_EPT_VIOLATION       48
#define EXIT_REASON_EPT_MISCONFIG       49
#define EXIT_REASON_INVEPT              50
#define EXIT_REASON_RDTSCP              51
#define EXIT_REASON_PREEMPTION_TIMER    52
#define EXIT_REASON_INVVPID             53
#define EXIT_REASON_WBINVD              54
#define EXIT_REASON_XSETBV              55
#define EXIT_REASON_APIC_WRITE          56
#define EXIT_REASON_RDRAND 		57
#define EXIT_REASON_INVPCID             58
#define EXIT_REASON_VMFUNC 		59
#define EXIT_REASON_ENCLS 		60
#define EXIT_REASON_RDSEED 		61
#define EXIT_REASON_PML_FULL            62
#define EXIT_REASON_XSAVES              63
#define EXIT_REASON_XRSTORS             64
#define EXIT_REASON_PCOMMIT             65

#define DR6_BD		(1 << 13)
#define DR6_BS		(1 << 14)
#define DR6_RTM		(1 << 16)
#define DR6_FIXED_1	0xfffe0ff0
#define DR6_INIT	0xffff0ff0
#define DR6_VOLATILE	0x0001e00f

#define DR7_BP_EN_MASK	0x000000ff
#define DR7_GE		(1 << 9)
#define DR7_GD		(1 << 13)
#define DR7_FIXED_1	0x00000400
#define DR7_VOLATILE	0xffff2bff

#endif
