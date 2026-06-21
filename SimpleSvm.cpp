/*!
    @file       SimpleSvm.cpp

    @brief      All C code.

    @author     Satoshi Tanda

    @copyright  Copyright (c) 2017-2020, Satoshi Tanda. All rights reserved.
 */
#define POOL_NX_OPTIN   0
#include "SimpleSvm.hpp"
#include "km/Svmkm.hpp"
#include "km/read.cpp"
#include "km/write.cpp"

 // Forward declarations required by Ptehook.cpp's #define aliases below
static NTSTATUS SvDispatchCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static NTSTATUS SvDispatchDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static VOID SvDriverUnload(_In_ PDRIVER_OBJECT DriverObject);
static volatile LONG g_IdtVectoringReinjects = 0;
static UINT64 g_CpuidEntryTsc[256];
static BOOLEAN g_RdtscTrapArmed[256];

// Calibrated bare-metal CPUID cost in TSC cycles. Set once at boot.
static UINT64 g_BareMetalCpuidCost = 0;

// Full CPUID snapshot captured at init, before VMRUN, before we are the
// hypervisor. Every CPUID VMEXIT is served entirely from these tables — no
// live __cpuidex calls in the hot path. This means:
//   • The guest always sees a consistent, pre-virtualization view of CPUID
//     regardless of whether Hyper-V, VMware, or bare metal is underneath.
//   • ECX[31] (hypervisor-present) is cleared in the leaf-1 entry at capture
//     time, so we never leak our own presence.
//   • VMware/NDIS/ExecutionContext drivers see whatever the host reported for
//     the 0x40000000+ range (Hyper-V identity if nested, zeros if bare metal)
//     and take the code path they were designed for.
//
// Standard leaves  0x00000000 – MaxStd  (up to 32 entries, sub-leaf 0)
// Extended leaves  0x80000000 – MaxExt  (up to 32 entries, sub-leaf 0)
// HV-range leaves  0x40000000 – 0x40000010  (17 entries)
// Anything outside those windows returns g_InvalidCpuidLeaf.
static int    g_StdCpuidCache[32][4] = {};
static int    g_ExtCpuidCache[32][4] = {};
static int    g_HvCpuidCache[17][4] = {};
static int    g_InvalidCpuidLeaf[4] = {};
static UINT32 g_MaxStdCpuidLeaf = 0;
static UINT32 g_MaxExtCpuidLeaf = 0;
// Hardware-supported XCR0 bitmask from CPUID.0Dh.0 (EAX:EDX combined).
// Used for SDM-compliant XSETBV validation without a hardcoded mask.
static UINT64 g_ValidXcr0Mask = 0;
// TRUE when running inside Hyper-V (VBS, Hyper-V VM, or any hypervisor that
// sets the hypervisor-present CPUID bit). Used to decide whether Hyper-V
// synthetic MSR accesses (0x40000000-0x4FFFFFFF) from the L2 guest should be
// forwarded from L1 host context rather than injecting #GP.
static BOOLEAN g_RunningUnderHyperV = FALSE;

// Bits in CR0 and CR4 that the hypervisor requires to remain set regardless
// of what the guest writes.  Captured from hardware at load time so that any
// bit the system had active when we took over is permanently preserved.
//
// CR0 mask keeps PE (bit 0), NE (bit 5), WP (bit 16), PG (bit 31) at minimum
// so the guest can never disable paging or write-protect.
// CR4 mask preserves everything that was set at load time (SMEP, SMAP, MCE,
// OSXSAVE, etc.).  If the guest tries to clear a required bit, we force it
// back silently; the guest shadow retains its intended value.
static ULONG64 g_HostRequiredCr0 = 0;
static ULONG64 g_HostRequiredCr4 = 0;
// Map Ptehook.cpp dispatch-name stubs to the actual Sv* implementations
// and pull in the PTE hook / cave-scanning code as a single translation unit.
#define DeviceCreate    SvDispatchCreateClose
#define DeviceClose     SvDispatchCreateClose
#define IoctlDispatch   SvDispatchDeviceControl
#define UnSupportedIO   SvDispatchCreateClose
#define DriverUnload    SvDriverUnload
#define SVM_INTERCEPT_MISC1_RDTSC       (1UL << 14)
#define SVM_INTERCEPT_MISC2_RDTSCP      (1UL << 5)
// AMD APM Vol.2 §15.9: XSETBV intercept is InterceptMisc2 bit 13.
#define SVM_INTERCEPT_MISC2_XSETBV      (1UL << 13)
// AMD APM Vol.2 §15.9: VMMCALL intercept is InterceptMisc2 bit 1.
#define SVM_INTERCEPT_MISC2_VMMCALL     (1UL << 1)
// AMD APM Vol.2 §15.12: VMEXIT_EXCEPTION_x = 0x40 + vector_number.
// #GP is vector 13 → 0x4D.  VMEXIT_EXCEPTION_DF (vector 8 = 0x48) and
// VMEXIT_EXCEPTION_DB (vector 1 = 0x41) are defined in SimpleSvm.hpp.

#include "km/Ptehook.cpp"
#undef DeviceCreate
#undef DeviceClose
#undef IoctlDispatch
#undef UnSupportedIO
#undef DriverUnload

// pml4inject depends on RegisterNptShadowPage from Ptehook.cpp above
#include "km/pml4inject.cpp"
// Physical PEB/LDR walk — module-base resolution without KeStackAttachProcess
#include "km/pebwalk.cpp"

// -----------------------------------------------------------------------
// Set SHADOW_PAGING_DISABLED to 1 to skip all NPT shadow-page wiring and
// RWX cave-stub creation.  Useful when testing bare-metal hypervisor
// launch without the extra NPT complexity.  Set to 0 to re-enable.
// -----------------------------------------------------------------------
#define SHADOW_PAGING_DISABLED 0

// -----------------------------------------------------------------------
// SV_MINIMAL_VMCB — when set to 1, the VMCB is configured with only the
// stock-SimpleSvm intercepts (CPUID + VMRUN). All extras (MSR/XSETBV/
// VMMCALL intercepts, CR3/CR4 intercept, #DF/#DB exception intercept)
// are skipped. Use this to bisect: if first-VMRUN completes with =1 but
// hangs with =0, the bug is in one of the disabled intercepts. The
// hypervisor will not provide stealth / MSR gating / unload-by-CPUID
// guarantees in this mode — diagnostic only.
// -----------------------------------------------------------------------
#define SV_MINIMAL_VMCB 0

#include <intrin.h>
#include <ntifs.h>
#include <stdarg.h>

EXTERN_C DRIVER_INITIALIZE DriverEntry;
static DRIVER_UNLOAD SvDriverUnload;
static CALLBACK_FUNCTION SvPowerCallbackRoutine;

EXTERN_C
VOID
_sgdt(
    _Out_ PVOID Descriptor
);

EXTERN_C
UINT16
SvReadTr(
    VOID
);

EXTERN_C VOID SvLoadTr(_In_ UINT16 Selector);
EXTERN_C UINT64 SvProbeVmmcall(_In_ UINT64 ProbeCmd);
EXTERN_C VOID SvLoadGdt(_In_ PVOID DescriptorTableRegister);

_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
DECLSPEC_NORETURN
EXTERN_C
VOID
NTAPI
SvLaunchVm(
    _In_ PVOID HostRsp
);

//
// x86-64 defined structures.
//

//
// See "2-Mbyte PML4E-Long Mode" and "2-Mbyte PDPE-Long Mode".
//
typedef struct _PML4_ENTRY_2MB
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT64 Valid : 1;               // [0]
            UINT64 Write : 1;               // [1]
            UINT64 User : 1;                // [2]
            UINT64 WriteThrough : 1;        // [3]
            UINT64 CacheDisable : 1;        // [4]
            UINT64 Accessed : 1;            // [5]
            UINT64 Reserved1 : 3;           // [6:8]
            UINT64 Avl : 3;                 // [9:11]
            UINT64 PageFrameNumber : 40;    // [12:51]
            UINT64 Reserved2 : 11;          // [52:62]
            UINT64 NoExecute : 1;           // [63]
        } Fields;
    };
} PML4_ENTRY_2MB, * PPML4_ENTRY_2MB,
PDPT_ENTRY_2MB, * PPDPT_ENTRY_2MB;
static_assert(sizeof(PML4_ENTRY_2MB) == 8,
    "PML4_ENTRY_1GB Size Mismatch");

//
// See "2-Mbyte PDE-Long Mode".
//
typedef struct _PD_ENTRY_2MB
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT64 Valid : 1;               // [0]
            UINT64 Write : 1;               // [1]
            UINT64 User : 1;                // [2]
            UINT64 WriteThrough : 1;        // [3]
            UINT64 CacheDisable : 1;        // [4]
            UINT64 Accessed : 1;            // [5]
            UINT64 Dirty : 1;               // [6]
            UINT64 LargePage : 1;           // [7]
            UINT64 Global : 1;              // [8]
            UINT64 Avl : 3;                 // [9:11]
            UINT64 Pat : 1;                 // [12]
            UINT64 Reserved1 : 8;           // [13:20]
            UINT64 PageFrameNumber : 31;    // [21:51]
            UINT64 Reserved2 : 11;          // [52:62]
            UINT64 NoExecute : 1;           // [63]
        } Fields;
    };
} PD_ENTRY_2MB, * PPD_ENTRY_2MB;
static_assert(sizeof(PD_ENTRY_2MB) == 8,
    "PDE_ENTRY_2MB Size Mismatch");

//
// See "GDTR and IDTR Format-Long Mode"
//
#include <pshpack1.h>
typedef struct _DESCRIPTOR_TABLE_REGISTER
{
    UINT16 Limit;
    ULONG_PTR Base;
} DESCRIPTOR_TABLE_REGISTER, * PDESCRIPTOR_TABLE_REGISTER;
static_assert(sizeof(DESCRIPTOR_TABLE_REGISTER) == 10,
    "DESCRIPTOR_TABLE_REGISTER Size Mismatch");
#include <poppack.h>

//
// See "Long-Mode Segment Descriptors" and some of definitions
// (eg, "Code-Segment Descriptor-Long Mode")
//
typedef struct _SEGMENT_DESCRIPTOR
{
    union
    {
        UINT64 AsUInt64;
        struct
        {
            UINT16 LimitLow;        // [0:15]
            UINT16 BaseLow;         // [16:31]
            UINT32 BaseMiddle : 8;  // [32:39]
            UINT32 Type : 4;        // [40:43]
            UINT32 System : 1;      // [44]
            UINT32 Dpl : 2;         // [45:46]
            UINT32 Present : 1;     // [47]
            UINT32 LimitHigh : 4;   // [48:51]
            UINT32 Avl : 1;         // [52]
            UINT32 LongMode : 1;    // [53]
            UINT32 DefaultBit : 1;  // [54]
            UINT32 Granularity : 1; // [55]
            UINT32 BaseHigh : 8;    // [56:63]
        } Fields;
    };
} SEGMENT_DESCRIPTOR, * PSEGMENT_DESCRIPTOR;
static_assert(sizeof(SEGMENT_DESCRIPTOR) == 8,
    "SEGMENT_DESCRIPTOR Size Mismatch");

typedef struct _SEGMENT_ATTRIBUTE
{
    union
    {
        UINT16 AsUInt16;
        struct
        {
            UINT16 Type : 4;        // [0:3]
            UINT16 System : 1;      // [4]
            UINT16 Dpl : 2;         // [5:6]
            UINT16 Present : 1;     // [7]
            UINT16 Avl : 1;         // [8]
            UINT16 LongMode : 1;    // [9]
            UINT16 DefaultBit : 1;  // [10]
            UINT16 Granularity : 1; // [11]
            UINT16 Reserved1 : 4;   // [12:15]
        } Fields;
    };
} SEGMENT_ATTRIBUTE, * PSEGMENT_ATTRIBUTE;
static_assert(sizeof(SEGMENT_ATTRIBUTE) == 2,
    "SEGMENT_ATTRIBUTE Size Mismatch");

//
// SimpleSVM specific structures.
//

typedef struct _PML4E_TREE
{
    DECLSPEC_ALIGN(PAGE_SIZE) PDPT_ENTRY_2MB PdptEntries[512];
    DECLSPEC_ALIGN(PAGE_SIZE) PD_ENTRY_2MB PdEntries[512][512];
} PML4E_TREE, * PPML4E_TREE;

// Number of PML4 entries to identity-map at startup.
// 1 entry = 512GB. AMD MMIO (SMU, PCIe extended config, IOMMU) commonly lives
// above 1TB on large-RAM systems. 4 entries = 2TB covers typical AMD configs.
#define NPT_PML4_COUNT 4

typedef struct _SHARED_VIRTUAL_PROCESSOR_DATA
{
    PVOID MsrPermissionsMap;
    DECLSPEC_ALIGN(PAGE_SIZE) PML4_ENTRY_2MB Pml4Entries[512];
    DECLSPEC_ALIGN(PAGE_SIZE) PML4E_TREE Pml4eTrees[NPT_PML4_COUNT];
} SHARED_VIRTUAL_PROCESSOR_DATA, * PSHARED_VIRTUAL_PROCESSOR_DATA;

typedef struct _VIRTUAL_PROCESSOR_DATA
{
    union
    {
        //
        //  Low     HostStackLimit[0]                        StackLimit
        //  ^       ...
        //  ^       HostStackLimit[KERNEL_STACK_SIZE - 2]    StackBase
        //  High    HostStackLimit[KERNEL_STACK_SIZE - 1]    StackBase
        //
        DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStackLimit[KERNEL_STACK_SIZE];
        struct
        {
            UINT8 StackContents[KERNEL_STACK_SIZE - (sizeof(PVOID) * 6) - sizeof(KTRAP_FRAME)];
            KTRAP_FRAME TrapFrame;
            UINT64 GuestVmcbPa;     // HostRsp
            UINT64 HostVmcbPa;
            struct _VIRTUAL_PROCESSOR_DATA* Self;
            PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData;
            SHADOW_STEP_STATE* ShadowStepState; // VMCB-owned state; preserves the existing 8-byte layout slot
            UINT64 Reserved1;
        } HostStackLayout;
    };

    DECLSPEC_ALIGN(PAGE_SIZE) VMCB GuestVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) VMCB HostVmcb;
    DECLSPEC_ALIGN(PAGE_SIZE) UINT8 HostStateArea[PAGE_SIZE];
} VIRTUAL_PROCESSOR_DATA, * PVIRTUAL_PROCESSOR_DATA;
static_assert(sizeof(VIRTUAL_PROCESSOR_DATA) == KERNEL_STACK_SIZE + PAGE_SIZE * 3,
    "VIRTUAL_PROCESSOR_DATA Size Mismatch");

typedef struct _GUEST_REGISTERS
{
    UINT64 R15;
    UINT64 R14;
    UINT64 R13;
    UINT64 R12;
    UINT64 R11;
    UINT64 R10;
    UINT64 R9;
    UINT64 R8;
    UINT64 Rdi;
    UINT64 Rsi;
    UINT64 Rbp;
    UINT64 Rsp;
    UINT64 Rbx;
    UINT64 Rdx;
    UINT64 Rcx;
    UINT64 Rax;
} GUEST_REGISTERS, * PGUEST_REGISTERS;

typedef struct _GUEST_CONTEXT
{
    PGUEST_REGISTERS VpRegs;
    BOOLEAN ExitVm;
} GUEST_CONTEXT, * PGUEST_CONTEXT;


//
// x86-64 defined constants.
//
#define IA32_MSR_PAT    0x00000277
#define IA32_MSR_EFER   0xc0000080

#define EFER_SVME       (1UL << 12)

#define RPL_MASK        3
#define DPL_SYSTEM      0

#define CPUID_FN8000_0001_ECX_SVM                   (1UL << 2)
#define CPUID_FN0000_0001_ECX_HYPERVISOR_PRESENT    (1UL << 31)
#define CPUID_FN8000_000A_EDX_NP                    (1UL << 0)
#define CPUID_FN8000_000A_EDX_FLUSH_BY_ASID         (1UL << 6)

// CPUID Fn8000_000A:EDX[6].  TLB_CONTROL=3 is legal only when this feature
// is exposed.  Nested VMware commonly exposes NPT but not FlushByAsid.
static BOOLEAN g_SvmFlushByAsidSupported = FALSE;

#define CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING          0x00000000
#define CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS       0x00000001
#define CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX    0x80000001
#define CPUID_SVM_FEATURES                                      0x8000000a
//
// The Microsoft Hypervisor interface defined constants.
//
#define CPUID_HV_VENDOR_AND_MAX_FUNCTIONS   0x40000000
#define CPUID_HV_INTERFACE                  0x40000001

//
// SimpleSVM specific constants.
//
#define CPUID_UNLOAD_SIMPLE_SVM     0x41414141
#define CPUID_PROBE_SIMPLE_SVM      0x42424242  // probe only — never triggers unload

// VMMCALL command codes (passed in guest RAX, with the R10/R11/R12 magic
// signature also set). Used by SvIsSimpleSvmHypervisorInstalled.
#define SV_VMMCALL_PROBE            0x5356504231ULL   // "SVPB1" — presence probe
#define SV_VMMCALL_PROBE_ACK        0x5356414345ULL   // ack written back to RAX
#define CPUID_HV_MAX                CPUID_HV_INTERFACE

/*!
    @brief      Breaks into a kernel debugger when it is present.

    @details    This macro is emits software breakpoint that only hits when a
                kernel debugger is present. This macro is useful because it does
                not change the current frame unlike the DbgBreakPoint function,
                and breakpoint by this macro can be overwritten with NOP without
                impacting other breakpoints.
 */
#define SV_DEBUG_BREAK() \
    if (KD_DEBUGGER_NOT_PRESENT) \
    { \
        NOTHING; \
    } \
    else \
    { \
        __debugbreak(); \
    } \
    reinterpret_cast<void*>(0)

 //
 // A power state callback handle.
 //
static PVOID g_PowerCallbackRegistration;

//
// CR3 of the System process, captured once at PASSIVE_LEVEL.
// Written to the processor immediately before VMRUN so that the host CR3
// saved in HSAVE always maps the full kernel address space — independent of
// whichever process context DriverEntry happens to execute in (e.g. kdmapper).
//
static ULONG_PTR g_SystemCr3;

// ---------------------------------------------------------------------------
// Private host CR3 — deep copy of kernel PML4 entries [256..511].
// Host-mode code runs on isolated page tables so guest modifications to
// kernel-space PTEs cannot corrupt the hypervisor's address space.
// ---------------------------------------------------------------------------
#define HOST_CR3_PTE_PRESENT     (1ULL << 0)
#define HOST_CR3_PTE_LARGE_PAGE  (1ULL << 7)
#define HOST_CR3_PFN_MASK        0x000FFFFFFFFFF000ULL
#define HOST_CR3_MAX_PT_PAGES    4096

static PVOID   g_HostPtPages[HOST_CR3_MAX_PT_PAGES];
static UINT32  g_HostPtCount = 0;
static UINT64  g_HostCr3Pa = 0;   // PA of our private PML4; 0 = not built

static PVOID SvHostCr3AllocPage(VOID)
{
    PVOID page = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'rC_H');
    if (!page) return NULL;
    RtlZeroMemory(page, PAGE_SIZE);
    if (g_HostPtCount < HOST_CR3_MAX_PT_PAGES)
        g_HostPtPages[g_HostPtCount++] = page;
    return page;
}
static PUINT64 SvHostCr3MapPa(UINT64 Pa)
{
    PHYSICAL_ADDRESS phys; phys.QuadPart = (LONGLONG)(Pa & ~(UINT64)0xFFF);
    PVOID va = MmGetVirtualForPhysical(phys);
    // MmGetVirtualForPhysical returns NULL (or a garbage non-zero value) for
    // physical addresses that have no kernel VA mapping (MMIO, firmware, gaps).
    // Validate the returned address is a canonical kernel VA before use.
    if (!va || (UINT64)va < 0xFFFF800000000000ULL || !MmIsAddressValid(va))
        return NULL;
    return (PUINT64)va;
}
/*!
    @brief  Build a private host CR3 as a shallow PML4 clone of System CR3.

    Allocates a single new PML4 page. Kernel-half entries (256..511) are
    copied verbatim from the active kernel PML4, so the sub-tables
    (PDPT/PD/PT) are SHARED with the live kernel CR3. User-half entries
    (0..255) are zeroed so host mode has no user-space view.

    Why shallow, not deep
    ---------------------
    The previous implementation deep-cloned PDPT/PD/PT pages using
    MmGetVirtualForPhysical at every level. That had two fatal problems
    on Windows and is the direct cause of the post-VMEXIT triple fault
    observed under nested SVM:

      1. The clone is a point-in-time snapshot of the kernel address
         space. Any allocation made AFTER SvBuildHostCr3 returns -
         including the per-CPU GDT page allocated by SvBuildHostGdt one
         line later, plus any later driver pool growth - lives in PT
         pages that the snapshot does not contain. When the host then
         takes any fault that requires walking the GDT (e.g. delivering
         an exception through the private IDT, which reads the CS
         descriptor from the private GDT), the CPU page-walks the
         private CR3, finds no mapping for the GDT VA, and #PF's. The
         #PF cascades to #DF, then triple-fault.

      2. MmGetVirtualForPhysical is documented "should not be used by
         drivers" - it can return NULL or a stale VA for page-table-page
         physical addresses (system PTE region, large-page-backed slots).
         The original code silently substituted the orig entry on
         failure (ourPml4[i] = origPml4[i]), which both defeated
         isolation and concealed the bug because partial clones still
         pointed at real PT pages via the fallback entries.

    Sharing sub-tables with the live kernel is the only way to keep host
    PT views consistent with the kernel's mutations of those tables (new
    allocations, page-in, etc.). Real-world AMD-SVM hypervisors (hvpp,
    ksm, hyper-v, kvm-amd) all do shallow PML4 clones for the same
    reason.

    Privacy properties preserved
    ----------------------------
    - Own PML4 page: the guest cannot replace our top-level table via
      its CR3 (CR3 writes are intercepted; we don't honor them on host).
    - User-half zeroed: guest user-space VAs are unreachable from host.
    - Self-ref entry rebased: Windows' recursive mapping at PML4[0x1ED]
      (or wherever it lives) is re-pointed at our own PML4 so the
      recursive window does not reach back into the kernel PML4.

    Privacy properties lost vs deep clone
    -------------------------------------
    - Guest tampering with sub-tables (PDPT/PD/PT pages) IS visible to
      host. In practice this is necessary - those tables ARE the live
      kernel, and the host must see the same view to operate. The deep
      clone never actually delivered this guarantee either: it
      RtlCopyMemory'd entire PT pages, so leaf entries were always
      shared anyway.
 */
static BOOLEAN SvBuildHostCr3(VOID)
{
    if (g_HostCr3Pa != 0) return TRUE;

    UINT64  sysCr3 = (UINT64)g_SystemCr3;
    UINT64  pml4Pa = sysCr3 & HOST_CR3_PFN_MASK;
    PUINT64 origPml4 = SvHostCr3MapPa(pml4Pa);
    if (!origPml4) return FALSE;

    PUINT64 ourPml4 = (PUINT64)SvHostCr3AllocPage();
    if (!ourPml4) return FALSE;

    // Zero the user-half (no user-space VAs visible from host mode).
    for (UINT32 i = 0; i < 256; i++) ourPml4[i] = 0;

    // Shallow-copy the kernel-half. Sub-tables (PDPT/PD/PT) are shared
    // with the kernel CR3, so any kernel allocation made after this
    // point - including the per-CPU GDT built one line below in
    // SvVirtualizeProcessor - is automatically visible to the host.
    for (UINT32 i = 256; i < 512; i++) ourPml4[i] = origPml4[i];

    g_HostCr3Pa = MmGetPhysicalAddress(ourPml4).QuadPart;

    // Re-point any self-referencing PML4 entry (Windows' recursive
    // mapping slot) at our own PML4 PA, so the recursive window in our
    // address space stays inside our PML4 instead of reaching back into
    // the kernel PML4.
    for (UINT32 i = 256; i < 512; i++)
    {
        if ((ourPml4[i] & HOST_CR3_PTE_PRESENT) &&
            (ourPml4[i] & HOST_CR3_PFN_MASK) == pml4Pa)
        {
            ourPml4[i] = (ourPml4[i] & ~HOST_CR3_PFN_MASK) | g_HostCr3Pa;
            break;
        }
    }

    return TRUE;
}

static VOID SvDestroyHostCr3(VOID)
{
    for (UINT32 i = 0; i < g_HostPtCount; i++)
        if (g_HostPtPages[i]) ExFreePoolWithTag(g_HostPtPages[i], 'rC_H');
    g_HostPtCount = 0;
    g_HostCr3Pa = 0;
}

// ---------------------------------------------------------------------------
// Host-side IDT / TSS for catching double-faults before they escalate.
// The IST1 stack for vector 8 (#DF) breaks the recursive stack chain.
//
// NOTE: This block must appear BEFORE SvBuildHostGdt, which references
// TSS_64 / g_HostTss / g_HostDfStack when building the private per-CPU TSS
// descriptor.
// ---------------------------------------------------------------------------
#pragma pack(push, 1)
typedef struct _IDT_ENTRY_64
{
    UINT16 OffsetLow;       // [0:15]
    UINT16 Selector;        // [16:31]
    UINT8  Ist;             // [32:39]
    UINT8  Attributes;      // [40:47]
    UINT16 OffsetMiddle;    // [48:63]
    UINT32 OffsetHigh;      // [64:95]
    UINT32 Reserved;        // [96:127]
} IDT_ENTRY_64, * PIDT_ENTRY_64;
static_assert(sizeof(IDT_ENTRY_64) == 16, "IDT_ENTRY_64 Size Mismatch");

typedef struct _TSS_64
{
    UINT32 Reserved0;
    UINT64 Rsp0;
    UINT64 Rsp1;
    UINT64 Rsp2;
    UINT64 Reserved1;
    UINT64 Ist1;
    UINT64 Ist2;
    UINT64 Ist3;
    UINT64 Ist4;
    UINT64 Ist5;
    UINT64 Ist6;
    UINT64 Ist7;
    UINT64 Reserved2;
    UINT16 Reserved3;
    UINT16 IoMapBaseAddress;
} TSS_64, * PTSS_64;
static_assert(sizeof(TSS_64) == 104, "TSS_64 Size Mismatch");
#pragma pack(pop)

static DECLSPEC_ALIGN(16) IDT_ENTRY_64 g_HostIdt[256];
static DECLSPEC_ALIGN(16) TSS_64       g_HostTss[256];  // per-CPU (max 256 CPUs)
static DECLSPEC_ALIGN(16) UINT8        g_HostDfStack[256][0x4000];  // per-CPU IST1 stacks
static BOOLEAN                         g_HostIdtInitialized = FALSE;

// ---------------------------------------------------------------------------
// Private host GDT — per-CPU copy of the current GDT loaded before VMRUN.
// VMRUN captures GDTR into the HSAVE area, so loading our private GDT before
// VMRUN means host-mode always runs with an isolated descriptor table.
// Stored outside VIRTUAL_PROCESSOR_DATA to avoid breaking its fixed size
// and the physical-allocation alignment invariant.
// ---------------------------------------------------------------------------
#define HOST_GDT_MAX_CPUS 256
static PVOID   g_HostGdt[HOST_GDT_MAX_CPUS];             // VA of per-CPU GDT copy
static UINT64  g_OrigGdtBase[HOST_GDT_MAX_CPUS];         // original GDT base
static UINT16  g_OrigGdtLimit[HOST_GDT_MAX_CPUS];        // original GDT limit
static UINT16  g_OrigTrSelector[HOST_GDT_MAX_CPUS];      // original TR selector
static DESCRIPTOR_TABLE_REGISTER g_OrigIdtr[HOST_GDT_MAX_CPUS]; // original IDTR (saved before __lidt)

/*!
    @brief  Build a private GDT copy for this CPU. Call once per vCPU before VMRUN.
 */
static BOOLEAN SvBuildHostGdt(_In_ ULONG CpuIndex)
{
    if (CpuIndex >= HOST_GDT_MAX_CPUS)
        return FALSE;

    // Already built for this CPU.
    if (g_HostGdt[CpuIndex] != NULL)
        return TRUE;

    DESCRIPTOR_TABLE_REGISTER gdtr;
    _sgdt(&gdtr);

    PVOID copy = ExAllocatePool2(POOL_FLAG_NON_PAGED, PAGE_SIZE, 'tGdH');
    if (!copy)
        return FALSE;

    RtlZeroMemory(copy, PAGE_SIZE);
    RtlCopyMemory(copy, (PVOID)gdtr.Base, (SIZE_T)gdtr.Limit + 1);

    // The system TSS descriptor has its busy bit set (type = 0xB).
    // LTR requires type = 0x9 (available TSS); executing LTR on a busy
    // descriptor raises #GP(0) with NTSTATUS 0xc0000096 (privileged instruction).
    // Clear the busy bit (bit 41 in the 16-byte system descriptor, i.e. bit 9
    // of the second byte of the Access byte, which sits at byte offset 5 of
    // the first 8-byte half of the descriptor).
    UINT16 tr = SvReadTr();
    if (tr && (tr & ~7U) + 7 <= gdtr.Limit)
    {
        PUINT8 trDesc = (PUINT8)copy + (tr & ~7U);
        trDesc[5] &= ~(UINT8)0x02;   // clear the busy bit (bit 1 of access byte)

        //
        // CRITICAL: repoint this descriptor at OUR OWN private TSS
        // (g_HostTss[CpuIndex]), not the system's real TSS.
        //
        // The byte-copy above duplicated the GDT, but the TSS descriptor it
        // copied still encodes the BASE ADDRESS of the real, live Windows TSS
        // (TR pointed at it when we read it). Loading TR from this "private"
        // GDT with that descriptor unmodified means LTR still resolves to the
        // SAME system TSS object in memory — there is no private TSS in play.
        //
        // A previous version of this code "solved" the need for a private
        // IST1 stack by writing directly into that live system TSS's Ist1
        // field. That is a permanent, unrestored modification of real kernel
        // data that Windows (and PatchGuard) consider critical — caught as
        // CRITICAL_STRUCTURE_CORRUPTION (0x109) with a "generic data region"
        // failure type. It also affects EVERY exception on that CPU that uses
        // IST1, not just ours, for the remaining lifetime of the boot.
        //
        // Fix: rewrite the base-address fields of this descriptor (in OUR
        // copy only — the real GDT and real TSS are untouched) to point at
        // g_HostTss[CpuIndex] instead. LTR then loads a TR that resolves to
        // our own private TSS. We set up Ist1 on that private TSS below.
        //
        // 16-byte system descriptor base-address field layout (Intel/AMD):
        //   byte copy[0..1]   = SegmentLimit[0:15]      (unused here)
        //   byte copy[2..3]   = BaseAddress[0:15]
        //   byte copy[4]      = BaseAddress[16:23]
        //   byte copy[5]      = Access / Type byte (already patched above)
        //   byte copy[6]      = Limit[16:19] | Flags
        //   byte copy[7]      = BaseAddress[24:31]
        //   qword copy[8..15] = BaseAddress[32:63] (high 32 bits, low 32 of
        //                       that qword) + reserved
        //
        RtlZeroMemory(&g_HostTss[CpuIndex], sizeof(g_HostTss[CpuIndex]));
        g_HostTss[CpuIndex].Ist1 =
            (UINT64)&g_HostDfStack[CpuIndex][sizeof(g_HostDfStack[CpuIndex]) - 0x10];

        UINT64 tssBase = (UINT64)&g_HostTss[CpuIndex];
        trDesc[2] = (UINT8)(tssBase & 0xFF);
        trDesc[3] = (UINT8)((tssBase >> 8) & 0xFF);
        trDesc[4] = (UINT8)((tssBase >> 16) & 0xFF);
        trDesc[7] = (UINT8)((tssBase >> 24) & 0xFF);
        *(UINT32*)(trDesc + 8) = (UINT32)(tssBase >> 32);
        *(UINT32*)(trDesc + 12) = 0;   // reserved, must be zero
        // trDesc[12..15] (upper half of the high qword) stay zero (reserved).

        // Limit must cover our TSS_64 (104 bytes) — set to sizeof-1, low
        // 16 bits in copy[0..1], top nibble of limit in low nibble of copy[6].
        UINT32 tssLimit = (UINT32)sizeof(TSS_64) - 1;
        trDesc[0] = (UINT8)(tssLimit & 0xFF);
        trDesc[1] = (UINT8)((tssLimit >> 8) & 0xFF);
        trDesc[6] = (UINT8)((trDesc[6] & 0xF0) | ((tssLimit >> 16) & 0x0F));
    }

    g_HostGdt[CpuIndex] = copy;
    g_OrigGdtBase[CpuIndex] = gdtr.Base;
    g_OrigGdtLimit[CpuIndex] = gdtr.Limit;
    g_OrigTrSelector[CpuIndex] = tr;

    return TRUE;
}

static VOID SvDestroyHostGdt(_In_ ULONG CpuIndex)
{
    if (CpuIndex < HOST_GDT_MAX_CPUS && g_HostGdt[CpuIndex])
    {
        ExFreePoolWithTag(g_HostGdt[CpuIndex], 'tGdH');
        g_HostGdt[CpuIndex] = NULL;
    }
}


// Each slot covers one 512GB PML4 entry that was not pre-built.
// Wired into Pml4Entries on-demand from SvHandleNpf (no allocation at VMEXIT time).
#define NPT_OVERFLOW_SLOTS 8
static PPML4E_TREE  g_NptOverflowTrees[NPT_OVERFLOW_SLOTS];  // VAs of pre-alloc trees
static ULONG64      g_NptOverflowPAs[NPT_OVERFLOW_SLOTS];    // their physical addresses
static ULONG        g_NptOverflowCount = 0;                   // how many are allocated
// Maps pml4Idx → overflow tree VA; -1 means not yet wired.
// Index 0..NPT_PML4_COUNT-1 are covered by the built-in trees.
// Index NPT_PML4_COUNT..511 are served from g_NptOverflowTrees on first fault.
static PPML4E_TREE  g_NptPml4IdxToTree[512];  // [pml4Idx] → tree VA or NULL

/*!
    @brief      Sends a message to the kernel debugger.

    @param[in]  Format - The format string to print.
 */
#pragma prefast(push)
#pragma prefast(disable : 26826, "C-style variable arguments needed for DbgPrint.")
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
static
VOID
SvDebugPrint(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
)
{
    va_list argList;

    va_start(argList, Format);
    vDbgPrintExWithPrefix("[SimpleSvm] ",
        DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        Format,
        argList);
    va_end(argList);
}
#pragma prefast(pop)

//
// Forward declarations for host exception stubs in x64.asm
//
EXTERN_C VOID SvHostDoubleFaultStub(VOID);
EXTERN_C VOID SvHostPageFaultStub(VOID);
EXTERN_C VOID SvHostGeneralProtectionStub(VOID);
EXTERN_C VOID SvHostDefaultStub(VOID);

// Per-CPU recursion guard: prevents DbgPrint inside a host fault handler from
// re-entering the same handler when INT 0x2D fires and is caught by the default
// stub, causing an infinite loop before the IDT default is in place.
static volatile BOOLEAN g_InHostFaultPrint[256];

/*!
    @brief      Load the original kernel IDT so DbgPrint / KeBugCheck work.

    @details    DbgPrint internally raises INT 0x2D (KdDebugServiceTrap) to
                hand the print buffer to the kernel debugger. While the
                private host IDT is loaded, vector 0x2D resolves to
                SvHostDefaultStub - which bugchecks with arg1 = 0x4FF and
                obscures whatever the original DbgPrint was trying to
                report. __svm_stgi() does NOT fix this: it only sets GIF,
                which gates external interrupts; software interrupts
                (INT n) always go through whichever IDT is currently in
                IDTR.

                Restoring the original kernel IDT before DbgPrint /
                KeBugCheck routes INT 0x2D back to KdDebugServiceTrap,
                lets the bugcheck path print its parameters, and lets the
                kernel write a crash dump. This is a one-way swap - every
                caller bugchecks immediately afterwards, so we never need
                to put the private IDT back.

                The function is also safe to call from the host fault
                stubs (#DF/#PF/#GP/default): in all cases the host has
                already been entered after a VMEXIT, GS base points at
                the kernel KPCR (either the host's was loaded via VMLOAD,
                or it's still the guest's - which is the kernel anyway),
                so KeGetCurrentProcessorIndex resolves correctly.
 */
static FORCEINLINE VOID SvSwapToKernelIdtForBugcheck(VOID)
{
    ULONG cpu = KeGetCurrentProcessorIndex();
    if (cpu < HOST_GDT_MAX_CPUS && g_OrigIdtr[cpu].Limit != 0)
    {
        __lidt(&g_OrigIdtr[cpu]);
    }
}

/*!
    @brief  Busy-spin long enough for KDNET to flush queued DbgPrint output.

    @details  KDNET ships DbgPrint buffers over the NIC asynchronously: a
              call to DbgPrint queues the packet to the NIC's TX ring; the
              NIC's DMA engine pushes it out a few hundred microseconds
              later. KeBugCheck doesn't wait for this - it tears down the
              NIC driver state as part of the bugcheck callback chain, so
              any DbgPrint output queued in the last ~10ms before
              KeBugCheck is silently discarded along with the NIC.

              Spinning here for ~250ms with PAUSE keeps the CPU off the
              memory bus while the NIC's DMA finishes. ~250ms is far more
              than KDNET needs in practice (typical NIC TX latency is
              <1ms over GbE) but cheap insurance against scheduling
              jitter.

              Call this AFTER the final DbgPrint and BEFORE KeBugCheck in
              every host-side bugcheck path.
 */
static FORCEINLINE VOID SvFlushKdnetBeforeBugcheck(VOID)
{
    // ~250ms at 1 GHz pause-rate. _mm_pause is roughly 100 cycles on
    // modern AMD parts, so this is ~30M iterations of throttled spin.
    for (volatile UINT64 i = 0; i < 2500000ULL; i++)
    {
        _mm_pause();
    }
}

/*!
    @brief  Diagnostic DbgPrint that works from any host-mode VMEXIT path,
            including silent ones (CPUID, MSR, NPF, etc.), without
            permanently altering the host IDT.

    @details  Steps:
                1. Save the current IDTR (typically the private host IDT).
                2. Load the kernel IDT so DbgPrint's INT 0x2D reaches
                   KdDebugServiceTrap instead of SvHostDefaultStub.
                3. Set GIF + IF if the caller hasn't already, so DbgPrint
                   doesn't deadlock on its internal spinlock + interrupt
                   delivery path.
                4. DbgPrint the message.
                5. SvFlushKdnetBeforeBugcheck-equivalent spin (~50ms) to
                   give KDNET a chance to flush before we either continue
                   into another VMEXIT or return through the asm stub.
                6. Restore previous interrupt + IDT state.

              Designed to be safe to call from anywhere in
              SvHandleVmExit (including before __svm_vmload moved into
              the asm stub - the kernel-IDT load doesn't depend on GS).
 */
static VOID SvDiagPrintFromVmexit(_In_z_ _Printf_format_string_ PCSTR Fmt, ...)
{
    //
    // VMEXIT entry context invariants (per AMD APM + Tanda's original
    // SvHandleVmExit comment at line 2017):
    //   - GIF = 0 (VMEXIT cleared it; only STGI sets it back)
    //   - IF could be anything but the kernel-mode convention is that
    //     EFLAGS.IF is also off in host VMEXIT context
    //   - CR8 holds whatever the GUEST set it to (CR8 is NOT in the AMD
    //     HSAVE area, so VMEXIT doesn't restore the host's pre-VMRUN CR8)
    //
    // The previous version of this helper called __svm_stgi() + _enable()
    // before doing anything else. That ungated external interrupt
    // delivery while the host was still running on the private IDT, at
    // whatever IRQL the guest left in CR8 (often PASSIVE_LEVEL = 0).
    // Any device interrupt that fired during the next ~50ms would walk
    // the private IDT, land on SvHostDefaultStub, and bugcheck. CPU0
    // got lucky 20 times; CPU1 lost the race on its 7th VMEXIT and the
    // box reset. See user log: trace stops at CPU1 n=6 with no fault
    // handler output, immediately followed by "Shutdown occurred at".
    //
    // Two correctness changes here:
    //
    //   1. Do NOT enable interrupts. DbgPrint queues the print packet
    //      to the KDNET NIC's TX ring via direct register I/O; the NIC
    //      DMA engine pushes the packet out asynchronously without
    //      needing the CPU to service interrupts. The TX-completion
    //      interrupt sits pending until the guest resumes, at which
    //      point its IDT services it normally.
    //
    //   2. Raise IRQL to HIGH_LEVEL via CR8 anyway, so any kernel API
    //      DbgPrint touches sees a sane IRQL and Driver Verifier
    //      doesn't fire spurious assertions on debug builds. We restore
    //      CR8 before returning so the caller's IRQL is unchanged.
    //
    DESCRIPTOR_TABLE_REGISTER savedIdtr;
    __sidt(&savedIdtr);

    // Swap to kernel IDT FIRST so DbgPrint's internal INT 0x2D reaches
    // KdDebugServiceTrap. The swap is a single LIDT - no fault window.
    SvSwapToKernelIdtForBugcheck();

    // Raise IRQL to HIGH_LEVEL for the print. Pure CR8 write; no Ke API
    // call so this is safe even if the caller is already at HIGH_LEVEL.
    UINT64 savedCr8 = __readcr8();
    __writecr8(15);  // HIGH_LEVEL

    va_list args;
    va_start(args, Fmt);
    vDbgPrintEx(0, 0, Fmt, args);
    va_end(args);

    // Give the NIC DMA time to push the packet out the wire before the
    // next handler runs (or before our caller bugchecks, in the
    // SvFlushKdnetBeforeBugcheck use case). ~50ms is far more than
    // typical KDNET TX latency over GbE but cheap insurance against
    // jitter when many CPUs are printing concurrently during multi-CPU
    // virtualization.
    //
    // DO NOT spin here. With GIF=0 and EFLAGS.IF=0 in host VMEXIT
    // context, every microsecond spent here is a microsecond this CPU
    // cannot answer an IPI, broadcast TLB flush, or KeIpiGenericCall
    // rendezvous from a peer. Callers on the bugcheck path that need
    // KDNET to drain already call SvFlushKdnetBeforeBugcheck()
    // explicitly — that's the right place for the spin because the
    // system is on its way down anyway.

    __writecr8(savedCr8);
    __lidt(&savedIdtr);
}

// Per-CPU VMEXIT trace counters. Limits the diagnostic output to the
// first N exits per CPU so the print path doesn't drown KDNET in steady
// state. Bumped by SvHandleVmExit's entry trace below.
#define SV_VMEXIT_TRACE_LIMIT  20
static volatile UINT32 g_VmexitTraceCount[HOST_GDT_MAX_CPUS];
// Set non-zero from a debugger to unconditionally enable VMEXIT tracing
// (useful for late-stage debugging after the first 20 exits).
static volatile UINT32 g_VmexitTraceForce = 0;

// ---------------------------------------------------------------------------
// COM1 raw serial output. Bypasses KDNET and the kernel debug subsystem
// entirely. UART transmission is hardware-driven once a byte is in the
// THR register, so output survives any host-side software freeze.
//
// Initialisation programs 115200-8N1 with FIFO enabled. Configure VMware
// to route COM1 to a named pipe (Windows host) or socket (Linux host):
//
//   .vmx fragment:
//     serial0.present = "TRUE"
//     serial0.fileType = "pipe"
//     serial0.fileName = "\\.\pipe\com_1"
//     serial0.tryNoRxLoss = "FALSE"
//
// Then on the host, attach with PuTTY / socat to the pipe to capture
// the trace stream.
// ---------------------------------------------------------------------------
#define SV_COM1_BASE  0x3F8u
#define SV_COM1_THR   (SV_COM1_BASE + 0)   // transmit holding (write) / RX buffer (read)
#define SV_COM1_IER   (SV_COM1_BASE + 1)
#define SV_COM1_FCR   (SV_COM1_BASE + 2)
#define SV_COM1_LCR   (SV_COM1_BASE + 3)
#define SV_COM1_MCR   (SV_COM1_BASE + 4)
#define SV_COM1_LSR   (SV_COM1_BASE + 5)
#define SV_COM1_DLL   (SV_COM1_BASE + 0)
#define SV_COM1_DLM   (SV_COM1_BASE + 1)

static volatile LONG g_SerialInitialized = 0;

static VOID SvSerialInit(VOID)
{
    if (InterlockedCompareExchange(&g_SerialInitialized, 1, 0) != 0)
        return;

    __outbyte(SV_COM1_IER, 0x00);  // disable interrupts
    __outbyte(SV_COM1_LCR, 0x80);  // DLAB on
    __outbyte(SV_COM1_DLL, 0x01);  // 115200 baud (divisor low)
    __outbyte(SV_COM1_DLM, 0x00);  // divisor high
    __outbyte(SV_COM1_LCR, 0x03);  // 8 data, no parity, 1 stop, DLAB off
    __outbyte(SV_COM1_FCR, 0xC7);  // enable FIFO, clear, 14-byte threshold
    __outbyte(SV_COM1_MCR, 0x0B);  // DTR + RTS + OUT2
}

static FORCEINLINE VOID SvSerialChar(_In_ char c)
{
    // Blind write — no THR-empty check. If VMware's emulated UART
    // never reports THR-empty (e.g. pipe reader not yet attached),
    // the previous LSR-polled version drops every byte after a
    // bounded spin. Blind writes are accepted by VMware's UART
    // regardless of pipe-reader state; bytes are simply queued.
    __outbyte(SV_COM1_THR, (UINT8)c);
}

static VOID SvSerialString(_In_z_ const char* s)
{
    while (*s)
    {
        if (*s == '\n') SvSerialChar('\r');
        SvSerialChar(*s++);
    }
}

static VOID SvSerialHex(_In_ UINT64 v, _In_ UINT32 width)
{
    static const char digits[] = "0123456789ABCDEF";
    char buf[17];
    if (width == 0 || width > 16) width = 16;
    buf[width] = 0;
    for (INT32 i = (INT32)width - 1; i >= 0; i--)
    {
        buf[i] = digits[v & 0xF];
        v >>= 4;
    }
    SvSerialString(buf);
}

//
// One-line serial emit per VMEXIT. Format is fixed (no varargs) so we
// never invoke any sprintf-class code from VMEXIT context. The total
// per-exit cost is ~80 bytes × 87 µs = ~7 ms at 115200 baud, which is
// still too expensive for steady-state but acceptable as a triage
// channel until the first-VMRUN failure is understood. Toggle off by
// setting g_SerialPerExit = 0 from a debugger once steady state is OK.
//
static volatile LONG g_SerialPerExit = 0;

static FORCEINLINE VOID SvSerialEmitExit(
    _In_ ULONG Cpu,
    _In_ UINT64 ExitCode,
    _In_ UINT64 Rip,
    _In_ UINT64 ExitInfo1)
{
    if (!g_SerialPerExit) return;
    SvSerialString("[SV] cpu=");
    SvSerialHex(Cpu, 2);
    SvSerialString(" code=");
    SvSerialHex(ExitCode, 4);
    SvSerialString(" rip=");
    SvSerialHex(Rip, 16);
    SvSerialString(" info1=");
    SvSerialHex(ExitInfo1, 16);
    SvSerialString("\n");
}

// ---------------------------------------------------------------------------
// Lock-free per-CPU VMEXIT ring buffer.
//
// VMEXIT context invariants:
//   - GIF = 0 (no NMI / SMI / INTR delivery to this CPU until STGI)
//   - EFLAGS.IF = 0 typically
//   - Only APIs documented as safe at IRQL >= IPI_LEVEL are legal
//
// DbgPrint / vDbgPrintEx are NOT in that set: they acquire kernel-internal
// locks, and the KDNET transport behind them may itself depend on IPIs to
// peer CPUs. Calling them from VMEXIT context with GIF=0 will deadlock any
// peer that is currently spinning on the same lock or waiting for this CPU
// to acknowledge a KeIpiGenericCall / KiFlushTargetTb rendezvous.
//
// The hot path here stores a fixed-size binary record into a per-CPU slot
// (single writer, no locks, no API calls, no spin). A drain function called
// from a periodic DPC formats and prints the records via DbgPrint at
// DISPATCH_LEVEL with GIF=1, which IS legal.
//
// Writer touches:  g_VmexitRing[cpu][.], g_VmexitRingHead[cpu]
// Drainer touches: g_VmexitRingHead[cpu] (read), g_VmexitRingTail[cpu]
// No shared mutable state => no atomics needed beyond the head publish.
// ---------------------------------------------------------------------------
#define SV_VMEXIT_RING_SIZE  256u   // power of 2

typedef struct _SV_VMEXIT_RECORD
{
    UINT64 ExitCode;
    UINT64 ExitInfo1;
    UINT64 ExitInfo2;
    UINT64 Rip;
    UINT64 Rax;
    UINT64 Rflags;
    UINT64 Cr3;
    UINT64 Tsc;
} SV_VMEXIT_RECORD, * PSV_VMEXIT_RECORD;

static SV_VMEXIT_RECORD g_VmexitRing[HOST_GDT_MAX_CPUS][SV_VMEXIT_RING_SIZE];
static volatile UINT32  g_VmexitRingHead[HOST_GDT_MAX_CPUS];
static UINT32           g_VmexitRingTail[HOST_GDT_MAX_CPUS];

// ---------------------------------------------------------------------------
// Forensic last-exit marker. Searchable in a memory dump by the magic
// 'LSTEXIT\0' (0x0054495845545344 little-endian). The most recent VMEXIT
// state of every CPU is here, in addition to the ring buffer.
// ---------------------------------------------------------------------------
#define SV_LAST_EXIT_MAGIC  0x0054495845545344ULL  // "DSTEXITS\0" reversed = LSTEXIT

typedef struct _SV_LAST_EXIT
{
    UINT64           Magic;
    UINT64           Cpu;
    UINT64           ExitCount;
    UINT64           HostRip;     // RIP of host code that handled the exit
    SV_VMEXIT_RECORD Record;
} SV_LAST_EXIT;

__declspec(align(64)) static SV_LAST_EXIT g_LastExit[HOST_GDT_MAX_CPUS];

static FORCEINLINE VOID SvLastExitWrite(
    _In_ ULONG Cpu,
    _In_ const SV_VMEXIT_RECORD* Rec)
{
    if (Cpu >= HOST_GDT_MAX_CPUS) return;
    SV_LAST_EXIT* e = &g_LastExit[Cpu];
    e->Magic = SV_LAST_EXIT_MAGIC;
    e->Cpu = Cpu;
    e->ExitCount++;
    e->HostRip = (UINT64)_ReturnAddress();
    e->Record = *Rec;
}

//
// Record one VMEXIT. Safe to call from VMEXIT context with GIF=0.
// No locks, no kernel APIs, no spin — just stores.
//
static FORCEINLINE VOID SvRecordVmexit(_In_ PVIRTUAL_PROCESSOR_DATA VpData)
{
    ULONG cpu = KeGetCurrentProcessorIndex();
    if (cpu >= HOST_GDT_MAX_CPUS)
        return;

    UINT32 head = g_VmexitRingHead[cpu];
    PSV_VMEXIT_RECORD rec =
        &g_VmexitRing[cpu][head & (SV_VMEXIT_RING_SIZE - 1)];

    rec->ExitCode = VpData->GuestVmcb.ControlArea.ExitCode;
    rec->ExitInfo1 = VpData->GuestVmcb.ControlArea.ExitInfo1;
    rec->ExitInfo2 = VpData->GuestVmcb.ControlArea.ExitInfo2;
    rec->Rip = VpData->GuestVmcb.StateSaveArea.Rip;
    rec->Rax = VpData->GuestVmcb.StateSaveArea.Rax;
    rec->Rflags = VpData->GuestVmcb.StateSaveArea.Rflags;
    rec->Cr3 = VpData->GuestVmcb.StateSaveArea.Cr3;
    rec->Tsc = __rdtsc();

    // Publish the head AFTER the record is fully written. _mm_sfence is
    // a single SFENCE instruction — no locks, safe at any IRQL/GIF.
    _mm_sfence();
    g_VmexitRingHead[cpu] = head + 1;

    // Forensic markers — survive any subsequent kernel freeze.
    SvLastExitWrite(cpu, rec);
    SvSerialEmitExit(cpu, rec->ExitCode, rec->Rip, rec->ExitInfo1);
}

//
// Drain the ring on the calling thread.
// IRQL <= DISPATCH_LEVEL. NEVER call this from a VMEXIT handler.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID SvDrainVmexitTrace(VOID)
{
    for (ULONG cpu = 0; cpu < HOST_GDT_MAX_CPUS; cpu++)
    {
        UINT32 head = g_VmexitRingHead[cpu];
        UINT32 tail = g_VmexitRingTail[cpu];
        if (head == tail)
            continue;

        // If the writer ran ahead by more than one ring, drop the
        // oldest dropped-on-wrap records the same way an ETL ring does.
        UINT32 lag = head - tail;
        if (lag > SV_VMEXIT_RING_SIZE)
        {
            DbgPrint("[SimpleSvm] VMEXIT ring on CPU%lu overflowed by %lu records\n",
                cpu, lag - SV_VMEXIT_RING_SIZE);
            tail = head - SV_VMEXIT_RING_SIZE;
        }

        for (UINT32 i = tail; i != head; i++)
        {
            PSV_VMEXIT_RECORD rec =
                &g_VmexitRing[cpu][i & (SV_VMEXIT_RING_SIZE - 1)];
            DbgPrint("[SimpleSvm] VMEXIT cpu=%lu n=%lu ExitCode=0x%llX "
                "ExitInfo1=0x%llX ExitInfo2=0x%llX RIP=%016llX "
                "RAX=%016llX RFLAGS=%016llX CR3=%016llX TSC=%016llX\n",
                cpu, i,
                rec->ExitCode, rec->ExitInfo1, rec->ExitInfo2,
                rec->Rip, rec->Rax, rec->Rflags, rec->Cr3, rec->Tsc);
        }
        g_VmexitRingTail[cpu] = head;
    }
}

//
// Periodic drain DPC. Initialized via SvStartVmexitTraceDrainer at driver
// load; cancelled via SvStopVmexitTraceDrainer at unload.
//
static KTIMER g_VmexitDrainTimer;
static KDPC   g_VmexitDrainDpc;
static volatile LONG g_VmexitDrainerActive = 0;

_IRQL_requires_(DISPATCH_LEVEL)
static VOID NTAPI SvVmexitDrainDpc(
    _In_ PKDPC Dpc,
    _In_opt_ PVOID DeferredContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);
    SvDrainVmexitTrace();
}

static VOID SvStartVmexitTraceDrainer(VOID)
{
    if (InterlockedCompareExchange(&g_VmexitDrainerActive, 1, 0) != 0)
        return;

    KeInitializeDpc(&g_VmexitDrainDpc, SvVmexitDrainDpc, NULL);
    KeInitializeTimer(&g_VmexitDrainTimer);

    // Pin the drain DPC to the highest-numbered CPU. The default rule
    // queues the DPC to the CPU that called KeSetTimer (CPU 0), which is
    // exactly the CPU most likely to be wedged inside our VMRUN loop.
    // Pinning to CPU (count-1) gives the drain a chance to fire on a
    // healthy peer.
    ULONG nCpu = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    if (nCpu > 1) KeSetTargetProcessorDpc(&g_VmexitDrainDpc, (CCHAR)(nCpu - 1));

    LARGE_INTEGER due;
    due.QuadPart = -10LL * 1000LL * 1000LL;        // 1 second relative
    KeSetTimerEx(&g_VmexitDrainTimer, due, 100,    // every 100 ms — see ring sooner
        &g_VmexitDrainDpc);
}

static VOID SvStopVmexitTraceDrainer(VOID)
{
    if (InterlockedCompareExchange(&g_VmexitDrainerActive, 0, 1) != 1)
        return;
    KeCancelTimer(&g_VmexitDrainTimer);
    KeFlushQueuedDpcs();
    SvDrainVmexitTrace();   // final flush
}

/*!
    @brief      Host #DF handler — runs on IST1 stack.

    @details    Called from SvHostDoubleFaultStub. Captures the fault context
                and bugchecks with diagnostic information for post-mortem analysis.

    @param[in]  StackPointer - Pointer to saved GPRs on the IST1 stack.
 */
DECLSPEC_NORETURN
EXTERN_C
VOID
SvHostDoubleFault(
    _In_ PVOID StackPointer
)
{
    PGUEST_REGISTERS regs = (PGUEST_REGISTERS)StackPointer;
    UINT64* frame = (UINT64*)((UINT64)StackPointer + sizeof(GUEST_REGISTERS));
    UINT64 errorCode = frame[0];
    UINT64 rip = frame[1];
    UINT64 cs = frame[2];
    UINT64 rflags = frame[3];
    UINT64 rsp = frame[4];
    UINT64 ss = frame[5];

    // Route the upcoming DbgPrint's INT 0x2D back to the kernel handler.
    SvSwapToKernelIdtForBugcheck();

    DbgPrint("[SimpleSvm] HOST #DF on CPU%lu (IST1 stack)\n"
        "  RIP=%016llX CS=%04llX RFLAGS=%016llX\n"
        "  RSP=%016llX SS=%04llX ErrorCode=%016llX\n"
        "  RAX=%016llX RCX=%016llX RDX=%016llX RBX=%016llX\n"
        "  RBP=%016llX RSI=%016llX RDI=%016llX\n"
        "  R8 =%016llX R9 =%016llX R10=%016llX R11=%016llX\n"
        "  R12=%016llX R13=%016llX R14=%016llX R15=%016llX\n",
        KeGetCurrentProcessorIndex(),
        rip, cs, rflags, rsp, ss, errorCode,
        regs->Rax, regs->Rcx, regs->Rdx, regs->Rbx,
        regs->Rbp, regs->Rsi, regs->Rdi,
        regs->R8, regs->R9, regs->R10, regs->R11,
        regs->R12, regs->R13, regs->R14, regs->R15);

#pragma prefast(suppress : __WARNING_USE_OTHER_FUNCTION, "Diagnostic crash.")
    SvFlushKdnetBeforeBugcheck();
    KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0x4DF, rip, rsp, errorCode);
}

/*!
    @brief      Host #PF handler for diagnostics.

    @param[in]  StackPointer - Pointer to saved GPRs on stack.
 */
EXTERN_C
VOID
SvHostPageFault(
    _In_ PVOID StackPointer
)
{
    PGUEST_REGISTERS regs = (PGUEST_REGISTERS)StackPointer;
    UINT64* frame = (UINT64*)((UINT64)StackPointer + sizeof(GUEST_REGISTERS));
    UINT64 errorCode = frame[0];
    UINT64 rip = frame[1];
    UINT64 cr2 = __readcr2();

    // Re-enable GIF and interrupts before calling DbgPrint — DbgPrint acquires
    // an internal spinlock and will deadlock if called with GIF=0 (VMEXIT context).
    SvSwapToKernelIdtForBugcheck();  // ORDER FIX: swap to kernel IDT BEFORE enabling interrupts
    __svm_stgi();
    _enable();

    ULONG cpu = KeGetCurrentProcessorIndex();
    if (!InterlockedExchange8((volatile CHAR*)&g_InHostFaultPrint[cpu], TRUE)) {
        DbgPrint("[SimpleSvm] HOST #PF on CPU%lu: RIP=%016llX CR2=%016llX EC=%016llX "
            "RAX=%016llX RCX=%016llX\n",
            cpu, rip, cr2, errorCode,
            regs->Rax, regs->Rcx);
        InterlockedExchange8((volatile CHAR*)&g_InHostFaultPrint[cpu], FALSE);
    }

#pragma prefast(suppress : __WARNING_USE_OTHER_FUNCTION, "Diagnostic crash.")
    SvFlushKdnetBeforeBugcheck();
    KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0x4EF, rip, cr2, errorCode);
}

/*!
    @brief      Host #GP handler for diagnostics.

    @param[in]  StackPointer - Pointer to saved GPRs on stack.
 */
EXTERN_C
VOID
SvHostGeneralProtection(
    _In_ PVOID StackPointer
)
{
    PGUEST_REGISTERS regs = (PGUEST_REGISTERS)StackPointer;
    UINT64* frame = (UINT64*)((UINT64)StackPointer + sizeof(GUEST_REGISTERS));
    UINT64 errorCode = frame[0];
    UINT64 rip = frame[1];

    SvSwapToKernelIdtForBugcheck();  // ORDER FIX: swap to kernel IDT BEFORE enabling interrupts
    __svm_stgi();
    _enable();

    ULONG cpu = KeGetCurrentProcessorIndex();
    if (!InterlockedExchange8((volatile CHAR*)&g_InHostFaultPrint[cpu], TRUE)) {
        DbgPrint("[SimpleSvm] HOST #GP on CPU%lu: RIP=%016llX EC=%016llX "
            "RAX=%016llX RCX=%016llX\n",
            cpu, rip, errorCode,
            regs->Rax, regs->Rcx);
        InterlockedExchange8((volatile CHAR*)&g_InHostFaultPrint[cpu], FALSE);
    }

#pragma prefast(suppress : __WARNING_USE_OTHER_FUNCTION, "Diagnostic crash.")
    SvFlushKdnetBeforeBugcheck();
    KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0x4E9, rip, errorCode, 0);
}

/*!
    @brief      Default host IDT handler — catches any vector without a
                specific handler (e.g. INT 0x2D, NMIs, spurious vectors).

    @details    Deliberately does NOT call DbgPrint. DbgPrint raises INT 0x2D
                internally; if that INT fires while we are already in the default
                handler, we'd recurse and triple-fault. Diagnostic info is
                embedded in KeBugCheckEx parameters instead.

    @param[in]  StackPointer - Pointer to saved GPRs on the handler stack.
 */
DECLSPEC_NORETURN
EXTERN_C
VOID
SvHostDefault(
    _In_ PVOID StackPointer
)
{
    UINT64* frame = (UINT64*)((UINT64)StackPointer + sizeof(GUEST_REGISTERS));
    UINT64 errorCode = frame[0];  // synthetic 0 for no-error-code vectors
    UINT64 rip = frame[1];

    SvSwapToKernelIdtForBugcheck();  // ORDER FIX: swap to kernel IDT BEFORE enabling interrupts
    __svm_stgi();
    // Route KeBugCheckEx's internal INT 0x2D (and any subsequent crash-
    // dump printing) back to KdDebugServiceTrap instead of looping
    // through us again. _enable() and DbgPrint are still avoided here
    // because we may have arrived from an early host-side fault where
    // re-entering this path is exactly what got us into this stub.
    SvFlushKdnetBeforeBugcheck();
    KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0x4FF, rip, errorCode, 0);
}

/*!
    @brief      Sets an IDT entry for a given vector.

    @param[in]  Idt - Pointer to the IDT array.
    @param[in]  Vector - Exception vector number.
    @param[in]  Handler - Address of the handler stub.
    @param[in]  Ist - IST index (1-7) or 0 for legacy stack switching.
    @param[in]  Selector - Code segment selector.
 */
static
VOID
SvSetIdtEntry(
    _Inout_ PIDT_ENTRY_64 Idt,
    _In_ UINT8 Vector,
    _In_ PVOID Handler,
    _In_ UINT8 Ist,
    _In_ UINT16 Selector
)
{
    UINT64 addr = (UINT64)Handler;
    Idt[Vector].OffsetLow = (UINT16)(addr & 0xFFFF);
    Idt[Vector].OffsetMiddle = (UINT16)((addr >> 16) & 0xFFFF);
    Idt[Vector].OffsetHigh = (UINT32)((addr >> 32) & 0xFFFFFFFF);
    Idt[Vector].Selector = Selector;
    Idt[Vector].Ist = Ist & 0x7;
    Idt[Vector].Attributes = 0x8E;  // P=1, DPL=0, Type=0xE (64-bit interrupt gate)
    Idt[Vector].Reserved = 0;
}

/*!
    @brief      Dumps AMD Machine Check Architecture (MCA) banks on boot.

    @details    Triple faults log entries in MCA banks that persist across
                warm resets. Call this early to capture prior-boot crash context.
 */
static
VOID
SvDumpMcaBanks(
    VOID
)
{
    UINT64 mcgCap = __readmsr(0x179);
    ULONG  numBanks = (ULONG)(mcgCap & 0xff);
    UINT64 mcgStat = __readmsr(0x17A);

    DbgPrint("[SimpleSvm] MCG_CAP=%016llX (banks=%lu) MCG_STATUS=%016llX (RIPV=%llu EIPV=%llu MCIP=%llu)\n",
        mcgCap, numBanks, mcgStat,
        (mcgStat >> 0) & 1, (mcgStat >> 1) & 1, (mcgStat >> 2) & 1);

    for (ULONG i = 0; i < numBanks; i++)
    {
        UINT64 status = __readmsr(0x401 + i * 4);
        if (!(status & (1ULL << 63)))
        {
            continue;  // VAL bit not set
        }
        UINT64 addr = 0, misc = 0;
        if (status & (1ULL << 58))  // ADDRV
        {
            addr = __readmsr(0x402 + i * 4);
        }
        if (status & (1ULL << 59))  // MISCV
        {
            misc = __readmsr(0x403 + i * 4);
        }
        DbgPrint("[SimpleSvm] MCA Bank %lu: STATUS=%016llX ADDR=%016llX MISC=%016llX\n",
            i, status, addr, misc);
        // Clear the bank for the next boot
        __writemsr(0x401 + i * 4, 0);
    }
}

/*!
    @brief      Allocates page aligned, zero filled physical memory.

    @details    This function allocates page aligned nonpaged pool. The
                allocated memory is zero filled and must be freed with
                SvFreePageAlingedPhysicalMemory. On Windows 8 and later versions
                of Windows, the allocated memory is non executable.

    @param[in]  NumberOfBytes - A size of memory to allocate in byte. This must
                be equal or greater than PAGE_SIZE.

    @result     A pointer to the allocated memory filled with zero; or NULL when
                there is insufficient memory to allocate requested size.
 */
__drv_allocatesMem(Mem)
_Post_writable_byte_size_(NumberOfBytes)
_Post_maybenull_
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
_Must_inspect_result_
static
PVOID
SvAllocatePageAlingedPhysicalMemory(
    _In_ SIZE_T NumberOfBytes
)
{
    PVOID memory;

    //
    // The size must be equal or greater than PAGE_SIZE in order to allocate
    // page aligned memory.
    //
    NT_ASSERT(NumberOfBytes >= PAGE_SIZE);

    memory = ExAllocatePool2(POOL_FLAG_NON_PAGED, NumberOfBytes, 'MVSS');
    if (memory != nullptr)
    {
        NT_ASSERT(PAGE_ALIGN(memory) == memory);
        RtlZeroMemory(memory, NumberOfBytes);
    }
    return memory;
}

/*!
    @brief      Frees memory allocated by SvAllocatePageAlingedPhysicalMemory.

    @param[in]  BaseAddress - The address returned by
                SvAllocatePageAlingedPhysicalMemory.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
static
VOID
SvFreePageAlingedPhysicalMemory(
    _Pre_notnull_ __drv_freesMem(Mem) PVOID BaseAddress
)
{
    ExFreePoolWithTag(BaseAddress, 'MVSS');
}

/*!
    @brief      Allocates page aligned, zero filled contiguous physical memory.

    @details    This function allocates page aligned nonpaged pool where backed
                by contiguous physical pages. The allocated memory is zero
                filled and must be freed with SvFreeContiguousMemory. The
                allocated memory is executable.

    @param[in]  NumberOfBytes - A size of memory to allocate in byte.

    @result     A pointer to the allocated memory filled with zero; or NULL when
                there is insufficient memory to allocate requested size.
 */
_Post_writable_byte_size_(NumberOfBytes)
_Post_maybenull_
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
_Must_inspect_result_
static
PVOID
SvAllocateContiguousMemory(
    _In_ SIZE_T NumberOfBytes
)
{
    PVOID memory;
    PHYSICAL_ADDRESS boundary, lowest, highest;

    boundary.QuadPart = lowest.QuadPart = 0;
    highest.QuadPart = -1;

    memory = MmAllocateContiguousNodeMemory(NumberOfBytes,
        lowest,
        highest,
        boundary,
        PAGE_READWRITE,
        MM_ANY_NODE_OK);
    if (memory != nullptr)
    {
        RtlZeroMemory(memory, NumberOfBytes);
    }
    return memory;
}

/*!
    @brief      Frees memory allocated by SvAllocateContiguousMemory.

    @param[in]  BaseAddress - The address returned by SvAllocateContiguousMemory.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_same_
static
VOID
SvFreeContiguousMemory(
    _In_ PVOID BaseAddress
)
{
    MmFreeContiguousMemory(BaseAddress);
}

/*!
    @brief          Injects #GP with 0 of error code.

    @param[in,out]  VpData - Per processor data.
 */
_IRQL_requires_same_
static
VOID
SvInjectGeneralProtectionException(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
)
{
    EVENTINJ event;

    //
    // Inject #GP(vector = 13, type = 3 = exception) with a valid error code.
    // An error code are always zero. See "#GP-General-Protection Exception
    // (Vector 13)" for details about the error code.
    //
    event.AsUInt64 = 0;
    event.Fields.Vector = 13;
    event.Fields.Type = 3;
    event.Fields.ErrorCodeValid = 1;
    event.Fields.Valid = 1;
    VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

/*!
    @brief  Inject #UD (Invalid Opcode, vector 6) into the guest.

    @details Used for guest attempts to execute SVM instructions (VMRUN,
             VMLOAD, VMSAVE, STGI, CLGI, SKINIT, INVLPGA).  We do not expose
             nested SVM to the guest, so from the guest's point of view
             EFER.SVME is effectively unavailable and these opcodes are
             invalid — #UD is the architecturally-correct response.  #UD has
             no error code.
*/
static VOID
SvInjectUndefinedOpcodeException(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData
)
{
    EVENTINJ event;

    event.AsUInt64 = 0;
    event.Fields.Vector = 6;      // #UD
    event.Fields.Type = 3;        // exception
    event.Fields.ErrorCodeValid = 0;
    event.Fields.Valid = 1;
    VpData->GuestVmcb.ControlArea.EventInj = event.AsUInt64;
}

/*!
    @brief  Advance guest RIP past an intercepted instruction of known length.

    Stock SimpleSvm sets Rip = NRip after every instruction intercept, relying
    on the AMD NRIP_SAVE feature (CPUID Fn8000_000A_EDX bit 3). VMware's
    nested SVM monitor is unreliable about this: even when it reports
    NRIPS=1, NRip is often left equal to the faulting Rip, or zero. Setting
    Rip = NRip then puts the guest back on the same instruction, producing
    a silent infinite VMEXIT loop on VCPU 0 while VCPU 1..N park in
    KiIdleLoop waiting for it - exactly the hang observed.

    Fix: always advance by the explicit instruction length we know from the
    intercept code (CPUID = 2 bytes, RDMSR/WRMSR/RDTSC = 2 bytes,
    RDTSCP/XSETBV = 3 bytes). NRip is consulted only as a sanity cross-check
    and accepted only when it sits in the expected range (curRip+1 .. +15).
    This works regardless of whether the underlying CPU/monitor supports
    NRIP_SAVE.
 */
static FORCEINLINE VOID SvAdvanceGuestRip(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_    ULONG                   InstructionLength)
{
    const UINT64 curRip = VpData->GuestVmcb.StateSaveArea.Rip;
    const UINT64 nRip = VpData->GuestVmcb.ControlArea.NRip;

    // Trust NRip only if it lies in the legal range for a single x86
    // instruction (1..15 bytes past current RIP). Anything else (0,
    // equal to curRip, or absurdly far) means the monitor didn't
    // populate it reliably - fall back to the known length.
    if (nRip > curRip && (nRip - curRip) <= 15)
    {
        VpData->GuestVmcb.StateSaveArea.Rip = nRip;
    }
    else
    {
        VpData->GuestVmcb.StateSaveArea.Rip = curRip + InstructionLength;
    }
}

/*!
    @brief          Handles #VMEXIT due to execution of the CPUID instructions.

    @details        This function returns unmodified results of the CPUID
                    instruction, except for few cases to indicate presence of
                    the hypervisor, and to process an unload request.

                    CPUID leaf 0x40000000 and 0x40000001 return modified values
                    to conform to the hypervisor interface to some extent. See
                    "Requirements for implementing the Microsoft Hypervisor interface"
                    https://msdn.microsoft.com/en-us/library/windows/hardware/Dn613994(v=vs.85).aspx
                    for details of the interface.

    @param[in,out]  VpData - Per processor data.
    @param[in,out]  GuestContext - Guest's GPRs.
 */
_IRQL_requires_same_
static
VOID
SvHandleCpuid(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    int registers[4];
    int leaf, subLeaf;
    SEGMENT_ATTRIBUTE attribute;

    leaf = static_cast<int>(GuestContext->VpRegs->Rax);
    subLeaf = static_cast<int>(GuestContext->VpRegs->Rcx);
    UINT32 uleaf = static_cast<UINT32>(leaf);

    // Serve everything from the pre-boot snapshot.  No live __cpuidex calls
    // here — after VMRUN we are the hypervisor, so any live call would return
    // ECX[31]=1 and potentially different data than the system had at boot.
    //
    // Sub-leaf handling: the snapshot stores sub-leaf 0 only. For leaves that
    // enumerate topology or XSAVE sub-leaves (0x04, 0x0B, 0x0D, 0x1F) with a
    // non-zero sub-leaf, we return g_InvalidCpuidLeaf — callers that care
    // about those iterate from sub-leaf 0 until they see a zero type field,
    // which this satisfies conservatively.
    const int* cached;

    if (uleaf <= g_MaxStdCpuidLeaf && subLeaf == 0)
    {
        cached = g_StdCpuidCache[uleaf];
    }
    else if (uleaf >= 0x40000000u && uleaf <= 0x40000010u)
    {
        // Hypervisor-range always served from snapshot regardless of sub-leaf;
        // none of these leaves have meaningful sub-leaves.
        cached = g_HvCpuidCache[uleaf - 0x40000000u];
    }
    else if (uleaf >= 0x80000000u && uleaf <= g_MaxExtCpuidLeaf)
    {
        UINT32 idx = uleaf - 0x80000000u;
        cached = (subLeaf == 0 && idx <= 31u) ? g_ExtCpuidCache[idx] : g_InvalidCpuidLeaf;
    }
    else
    {
        cached = g_InvalidCpuidLeaf;
    }

    registers[0] = cached[0];
    registers[1] = cached[1];
    registers[2] = cached[2];
    registers[3] = cached[3];

    // Unload / probe leaf — handled on top of the snapshot result.
    if (leaf == CPUID_UNLOAD_SIMPLE_SVM)
    {
        if (subLeaf == CPUID_PROBE_SIMPLE_SVM)
        {
            registers[0] = 'SVMS';
        }
        else if (subLeaf == CPUID_UNLOAD_SIMPLE_SVM)
        {
            registers[0] = 'SVMS';
            attribute.AsUInt16 = VpData->GuestVmcb.StateSaveArea.SsAttrib;
            if (attribute.Fields.Dpl == DPL_SYSTEM)
            {
                ULONG cpu = KeGetCurrentProcessorIndex();
                g_CpuidEntryTsc[cpu] = __rdtsc();
                g_RdtscTrapArmed[cpu] = TRUE;
                VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_RDTSC;
                VpData->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_RDTSCP;
                VpData->GuestVmcb.ControlArea.VmcbClean = 0;
                GuestContext->ExitVm = TRUE;
            }
        }
    }

    GuestContext->VpRegs->Rax = registers[0];
    GuestContext->VpRegs->Rbx = registers[1];
    GuestContext->VpRegs->Rcx = registers[2];
    GuestContext->VpRegs->Rdx = registers[3];

    SvAdvanceGuestRip(VpData, 2);
}
static VOID SvHandleRdtsc(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext,
    _In_ BOOLEAN IsRdtscp,
    _In_ UINT64 ExitTsc)
{
    ULONG cpu = KeGetCurrentProcessorIndex();
    UINT64 tsc;

    if (g_RdtscTrapArmed[cpu])
    {
        //
        // TSC compensation: return a value that makes the preceding CPUID
        // look as though it ran at bare-metal speed.
        //
        // compensated = cpuid_entry_tsc + bare_metal_cost
        //
        //   cpuid_entry_tsc  = TSC captured the moment the CPUID VMEXIT fired
        //                      (before any hypervisor work ran).
        //   bare_metal_cost  = measured native CPUID latency in cycles.
        //
        // This is always less than the real current TSC (ExitTsc) because
        // bare_metal_cost < actual VMEXIT overhead, so future native RDTSCs
        // remain monotonic and larger than the compensated value.
        //
        tsc = g_CpuidEntryTsc[cpu] + g_BareMetalCpuidCost;
        g_RdtscTrapArmed[cpu] = FALSE;

        // Disarm intercepts — next RDTSC runs natively.
        VpData->GuestVmcb.ControlArea.InterceptMisc1 &= ~SVM_INTERCEPT_MISC1_RDTSC;
        VpData->GuestVmcb.ControlArea.InterceptMisc2 &= ~SVM_INTERCEPT_MISC2_RDTSCP;
        VpData->GuestVmcb.ControlArea.VmcbClean = 0;
    }
    else
    {
        // Not armed: return the exit-entry TSC directly (no hypervisor overhead
        // visible to the guest — matches what bare metal would return).
        tsc = ExitTsc;
    }

    GuestContext->VpRegs->Rax = (UINT32)(tsc & 0xFFFFFFFF);
    GuestContext->VpRegs->Rdx = (UINT32)(tsc >> 32);

    if (IsRdtscp)
    {
        // RDTSCP also returns IA32_TSC_AUX in ECX.
        GuestContext->VpRegs->Rcx = __readmsr(0xC0000103);   // TSC_AUX
    }

    // RDTSC = 0F 31 (2 bytes), RDTSCP = 0F 01 F9 (3 bytes). See block
    // comment on SvAdvanceGuestRip for why we don't trust NRip alone.
    SvAdvanceGuestRip(VpData, IsRdtscp ? 3u : 2u);
}
/*!
    @brief          Handles #VMEXIT due to execution of the WRMSR and RDMSR
                    instructions.

    @details        This protects EFER.SVME from being cleared by the guest by
                    injecting #GP when it is about to be cleared. For other MSR
                    access, it passes-through.

    @param[in,out]  VpData - Per processor data.
    @param[in,out]  GuestContext - Guest's GPRs.
 */
_IRQL_requires_same_
static
VOID
SvHandleMsrAccess(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    ULARGE_INTEGER value;
    UINT32 msr;
    BOOLEAN writeAccess;

    msr = GuestContext->VpRegs->Rcx & MAXUINT32;
    writeAccess = (VpData->GuestVmcb.ControlArea.ExitInfo1 != 0);

    //
    // If IA32_MSR_EFER is accessed for write, we must protect the EFER_SVME bit
    // from being cleared.
    //
    if (msr == IA32_MSR_EFER)
    {
        if (writeAccess == FALSE)
        {
            //
            // EFER read: return the real EFER with EFER_SVME masked off so the
            // guest can't detect the hypervisor by probing this bit.
            //
            value.QuadPart = __readmsr(IA32_MSR_EFER) & ~(UINT64)EFER_SVME;
            GuestContext->VpRegs->Rax = value.LowPart;
            GuestContext->VpRegs->Rdx = value.HighPart;
        }
        else
        {
            //
            // EFER write: protect SVME from being cleared.
            //
            value.LowPart = GuestContext->VpRegs->Rax & MAXUINT32;
            value.HighPart = GuestContext->VpRegs->Rdx & MAXUINT32;
            if ((value.QuadPart & EFER_SVME) == 0)
            {
                SvInjectGeneralProtectionException(VpData);
                return;
            }
            VpData->GuestVmcb.StateSaveArea.Efer = value.QuadPart;
        }
    }
    else
    {
        //
        // Hypervisor synthetic MSRs (0x40000000-0x4FFFFFFF).
        //
        // On bare metal these MSRs do not exist and must #GP.
        //
        // Under Hyper-V (g_RunningUnderHyperV == TRUE) our driver is L1 and
        // the guest is L2.  When a VMEXIT_MSR reaches us for this range (some
        // platforms generate it; others produce a hardware #GP instead, which
        // is caught by SvHandleGuestGp), we forward the access from L1 host
        // context.  Hyper-V L0 owns these MSRs for L1 and handles them safely.
        // No STGI needed: HV synthetic MSR interception is above SVM's GIF.
        //
        if (msr >= 0x40000000U && msr <= 0x4FFFFFFFU)
        {
            // HV synthetic MSR range (SynIC, synthetic timers, etc.).
            //
            // NESTED (g_RunningUnderHyperV == TRUE): our driver is L1 inside
            // a real L0 hypervisor (Hyper-V/VMware) that owns these MSRs for
            // us. Forward the access from L1 host context — L0 handles it
            // safely, and this preserves enlightened behaviour the guest
            // expects when running in a VM. This is safe here because a real
            // L0 backs the MSR (no host #GP).
            //
            // BARE METAL (g_RunningUnderHyperV == FALSE): these MSRs are not
            // backed by anything. We must NOT forward (host __readmsr/__writemsr
            // would #GP -> bugcheck/storm) and must NOT inject #GP (Windows
            // enlightenment retries in a tight loop -> VMEXIT storm on
            // 0x400000B0/0x400000B1). Instead SWALLOW: ignore writes, return 0
            // for reads, advance RIP. The guest believes the SynIC is set up,
            // stops retrying, and falls back to the real local APIC.
            //
            if (g_RunningUnderHyperV)
            {
                ULARGE_INTEGER v;
                if (writeAccess != FALSE)
                {
                    v.LowPart = (UINT32)(GuestContext->VpRegs->Rax & MAXUINT32);
                    v.HighPart = (UINT32)(GuestContext->VpRegs->Rdx & MAXUINT32);
                    __writemsr(msr, v.QuadPart);
                }
                else
                {
                    v.QuadPart = __readmsr(msr);
                    GuestContext->VpRegs->Rax = v.LowPart;
                    GuestContext->VpRegs->Rdx = v.HighPart;
                }
            }
            else
            {
                // Bare metal: swallow.
                if (writeAccess == FALSE)
                {
                    GuestContext->VpRegs->Rax = 0;
                    GuestContext->VpRegs->Rdx = 0;
                }
                // (writes: discard)
            }
            SvAdvanceGuestRip(VpData, 2);
            return;
        }

        //
        // Only pass through MSRs in valid architectural ranges:
        //   0x00000000 - 0x00001FFF  (low range)
        //   0xC0000000 - 0xC0001FFF  (AMD/K8 extended range)
        //   0xC0010000 - 0xC0011FFF  (AMD-specific range, e.g. SYSCFG, HWCR)
        // Anything outside these windows is undefined — inject #GP so the
        // guest sees bare-metal behavior instead of a host-side fault.
        //
        BOOLEAN inRange =
            (msr <= 0x00001FFFU) ||
            (msr >= 0xC0000000U && msr <= 0xC0001FFFU) ||
            (msr >= 0xC0010000U && msr <= 0xC0011FFFU);

        if (!inRange)
        {
            SvInjectGeneralProtectionException(VpData);
            return;
        }

        if (writeAccess != FALSE)
        {
            value.LowPart = GuestContext->VpRegs->Rax & MAXUINT32;
            value.HighPart = GuestContext->VpRegs->Rdx & MAXUINT32;
            __writemsr(msr, value.QuadPart);
        }
        else
        {
            value.QuadPart = __readmsr(msr);
            GuestContext->VpRegs->Rax = value.LowPart;
            GuestContext->VpRegs->Rdx = value.HighPart;
        }
    }

    //
    // Then, advance RIP to "complete" the instruction. RDMSR (0F 32) and
    // WRMSR (0F 30) are both 2 bytes. See SvAdvanceGuestRip header.
    //
    SvAdvanceGuestRip(VpData, 2);
}

/*!
    @brief          Handles #VMEXIT due to execution of the XSETBV instruction.

    @details        Validates the XCR0 value per Intel/AMD SDM before executing
                    the instruction. Injects #GP for invalid values so a guest
                    cannot crash the system by passing arbitrary XCR0 masks.
                    The valid mask is captured from CPUID.0Dh.0 at driver load.

    @param[in,out]  VpData - Per processor data.
    @param[in,out]  GuestContext - Guest's GPRs.
 */
_IRQL_requires_same_
static
VOID
SvHandleXsetbv(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    UINT32 xcr_index = GuestContext->VpRegs->Rcx & MAXUINT32;
    UINT64 value = ((UINT64)(GuestContext->VpRegs->Rdx & MAXUINT32) << 32) |
        (GuestContext->VpRegs->Rax & MAXUINT32);

    // Only XCR0 (index 0) is architecturally defined.
    if (xcr_index != 0)
    {
        SvInjectGeneralProtectionException(VpData);
        return;
    }

    // Bit 0 (x87) must always be set — SDM requirement.
    if (!(value & 1ULL))
    {
        SvInjectGeneralProtectionException(VpData);
        return;
    }

    // Value must not set any bits the hardware doesn't support.
    if (value & ~g_ValidXcr0Mask)
    {
        SvInjectGeneralProtectionException(VpData);
        return;
    }

    // AVX (bit 2) requires SSE (bit 1) — SDM Table 13-1.
    if ((value & (1ULL << 2)) && !(value & (1ULL << 1)))
    {
        SvInjectGeneralProtectionException(VpData);
        return;
    }

    // CR4.OSXSAVE (bit 18) must be set before XSETBV is legal on this cpu.
    // If the host OS hasn't enabled it, executing _xsetbv will #GP inside
    // the VMEXIT handler (GIF=0) → triple fault.  Inject #GP to the guest
    // and skip the host execution — the guest will handle it in its own
    // CR4.OSXSAVE enable path.
    if (!(__readcr4() & (1ULL << 18)))
    {
        SvInjectGeneralProtectionException(VpData);
        return;
    }

    // Execute XSETBV on behalf of the guest.  Wrap in SEH: if the hardware
    // rejects the value for any reason not caught above (e.g. BIOS-locked
    // bits) the exception becomes a guest #GP rather than a host triple fault.
    __try
    {
        _xsetbv(0, value);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        SvInjectGeneralProtectionException(VpData);
        return;
    }
    // XSETBV = 0F 01 D1 (3 bytes). See SvAdvanceGuestRip header.
    SvAdvanceGuestRip(VpData, 3);
}

/*!
    @brief          Handles #VMEXIT due to execution of the VMRUN instruction.

    @details        This function always injects #GP to the guest.

    @param[in,out]  VpData - Per processor data.
    @param[in,out]  GuestContext - Guest's GPRs.
 */
_IRQL_requires_same_
static
VOID
SvHandleVmrun(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    UNREFERENCED_PARAMETER(GuestContext);

    SvInjectGeneralProtectionException(VpData);
}

/*!
    @brief  Returns a pointer into GuestRegisters for the GPR index encoded in
            an AMD SVM ExitInfo1 field (bits [11:8] for CR/DR exits).
 */
static
UINT64*
SvGprFromIndex(
    _In_ PGUEST_REGISTERS GuestRegisters,
    _In_ UINT32 GprIndex
)
{
    switch (GprIndex & 0xF)
    {
    case  0: return &GuestRegisters->Rax;
    case  1: return &GuestRegisters->Rcx;
    case  2: return &GuestRegisters->Rdx;
    case  3: return &GuestRegisters->Rbx;
    case  4: return &GuestRegisters->Rsp;
    case  5: return &GuestRegisters->Rbp;
    case  6: return &GuestRegisters->Rsi;
    case  7: return &GuestRegisters->Rdi;
    case  8: return &GuestRegisters->R8;
    case  9: return &GuestRegisters->R9;
    case 10: return &GuestRegisters->R10;
    case 11: return &GuestRegisters->R11;
    case 12: return &GuestRegisters->R12;
    case 13: return &GuestRegisters->R13;
    case 14: return &GuestRegisters->R14;
    case 15: return &GuestRegisters->R15;
    default: return &GuestRegisters->Rax;
    }
}

/*!
    @brief  Handles #VMEXIT due to a MOV-to-CR or MOV-from-CR instruction.

    @details
        ExitInfo1 encoding (AMD APM Vol.2 §15.12):
          bits  [3:0]  = CR number
          bit   [4]    = 0 (write to CR), 1 (read from CR)
          bits [11:8]  = GPR index

        We intercept CR3/CR4 writes and CR8 writes.
        - CR3 write: pass through directly (no VPID-style flush needed under NPT).
        - CR4 write: clear CR4.VMXE (not applicable on AMD but mirrors Intel parity;
          on AMD we only need to ensure SVME is preserved — SVME lives in EFER, not
          CR4, so we pass CR4 writes through unchanged).
        - CR8 write: write directly to CR8 (TPR).
 */
 /*!
     @brief  Handle VMEXIT_CR0_SEL_WRITE (selective CR0 write).

     @details Fires only when the guest changes CR0 bits other than TS/MP (so
              not on FPU-context-switch TS toggles). With DecodeAssists the GPR
              index is in ExitInfo1[3:0]. We read the guest's intended value
              from that GPR (captured correctly at VMEXIT) and write it into
              StateSaveArea.Cr0, so VMRUN loads a clean, consistent CR0 on
              resume. This avoids the guest executing a native MOV CR0 that
              could fault in guest mode, and keeps register state intact.
 */
_IRQL_requires_same_
static
VOID
SvHandleCr0SelWrite(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    UINT64 exitInfo1 = VpData->GuestVmcb.ControlArea.ExitInfo1;
    UINT32 gprIdx = (UINT32)(exitInfo1 & 0xF);
    UINT64* gpr = SvGprFromIndex(GuestContext->VpRegs, gprIdx);

    // Apply the guest's intended CR0 to the VMCB. VMRUN loads StateSaveArea.Cr0
    // into hardware on resume — this is the single authoritative write.
    VpData->GuestVmcb.StateSaveArea.Cr0 = *gpr;

    // MOV CR0, reg is 3 bytes (0F 22 /r). SvAdvanceGuestRip uses NRip when
    // sane, else curRip + 3.
    SvAdvanceGuestRip(VpData, 3);
}


_IRQL_requires_same_
static
VOID
SvHandleMovCr(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    //
    // AMD SVM ExitInfo1 / ExitCode format for MOV-CR (APM Vol 2 §15.12.1):
    //
    //   ExitCode  : 0x00..0x0F = MOV-from-CRn (read);  the CR# is the low nibble.
    //               0x10..0x1F = MOV-to-CRn   (write); the CR# is (ExitCode & 0xF).
    //   ExitInfo1 : bit 63     = 1 if the offending instruction was "MOV CRn,reg"
    //                            (vs CLTS / LMSW / SMSW);
    //               bits 3:0   = GPR INDEX of the source/destination register.
    //
    // The previous code used Intel VMX EXIT_QUALIFICATION layout (CR# in
    // ExitInfo1[3:0], GPR index in ExitInfo1[11:8]). That is wrong for SVM:
    // a guest "MOV CR8, RCX" (ExitInfo1 = 0x8000000000000001) was being
    // interpreted as "MOV CR1, RAX" and falling through to
    // SvInjectGeneralProtectionException; a guest "MOV CR8, RAX" with RAX=1
    // (ExitInfo1 = 0x8000000000000000) was interpreted as "MOV CR0, RAX"
    // and reached __writecr0(1) - which clears CR0.PG with EFER.LMA=1 on
    // the host and triple-faults the box, matching the observed kdnet-loss
    // signature after two CR8-write VMEXITs.
    //
    UINT64  exitInfo1 = VpData->GuestVmcb.ControlArea.ExitInfo1;
    UINT64  exitCode = VpData->GuestVmcb.ControlArea.ExitCode;
    UINT32  crNum = (UINT32)(exitCode & 0xF);          // implicit in ExitCode
    UINT32  isRead = (exitCode <= VMEXIT_CR15_READ);    // 0x00..0x0F vs 0x10..0x1F
    UINT32  gprIdx = (UINT32)(exitInfo1 & 0xF);          // GPR index, bits [3:0]
    UINT64* gpr = SvGprFromIndex(GuestContext->VpRegs, gprIdx);

    // If the MOV-CR bit (ExitInfo1[63]) is clear, this exit was caused by
    // CLTS / LMSW / SMSW - none of which we currently emulate. Inject #UD
    // back to the guest so it gets a meaningful fault rather than silently
    // wrong behaviour. (LMSW + CR0 emulation can be added later if needed;
    // Windows kernel doesn't use these on x64.)
    if ((exitInfo1 & (1ULL << 63)) == 0)
    {
        EVENTINJ ev;
        ev.AsUInt64 = 0;
        ev.Fields.Vector = 6;    // #UD
        ev.Fields.Type = 3;    // exception
        ev.Fields.Valid = 1;
        VpData->GuestVmcb.ControlArea.EventInj = ev.AsUInt64;
        return;
    }

    if (isRead)
    {
        // MOV from CR — return hardware register directly.
        // CR0 and CR4 reads are not intercepted (InterceptCrRead has no bits
        // set for them) so these cases are only reachable if something
        // explicitly enables them in future.  Return hardware in all cases
        // so there is no stale-shadow risk.
        switch (crNum)
        {
        case 0: *gpr = __readcr0(); break;
        case 2: *gpr = __readcr2(); break;
        case 3: *gpr = __readcr3(); break;
        case 4: *gpr = __readcr4(); break;
        case 8: *gpr = __readcr8(); break;
        default:
            SvInjectGeneralProtectionException(VpData);
            return;
        }
    }
    else
    {
        // MOV to CR.
        //
        // For CR0/CR4: VMRUN restores the full guest register state from
        // VMCB.StateSaveArea before resuming the guest.  That means whatever
        // we write to StateSaveArea.Cr4 here IS what the guest hardware
        // register will contain after the next VMRUN.  The previous code
        // stored a "shadow" (the guest's raw value) and separately called
        // __writecr4(forced) — but VMRUN immediately overwrote that hardware
        // write with the shadow, so the forced bits were silently discarded on
        // every resume.  Correct approach: OR the required bits into the VMCB
        // field directly, then let VMRUN do the single authoritative write to
        // hardware.  No __writecr4() call needed or wanted.
        //
        // CR0 write intercept is intentionally NOT enabled (InterceptCrWrite
        // has bit 0 clear).  MOV CR0 fires on every FPU lazy-save context
        // switch (TS bit manipulation) — intercepting it creates enough
        // VMEXIT overhead to starve the DPC timer list and triggers
        // TIMER_OR_DPC_INVALID (0xC7) concurrent-expiration bugchecks.
        // The bits we care about (PE/NE/WP/PG) are never cleared by Windows.
        switch (crNum)
        {
        case 2:
            __writecr2(*gpr);   // CR2 is not in the VMCB save area
            break;
        case 8:
            // CR8 (TPR) is not in VMCB.StateSaveArea; write directly.
            __writecr8(*gpr & 0xF);
            break;
        default:
            SvInjectGeneralProtectionException(VpData);
            return;
        }
    }

    // Advance past the MOV-CR instruction. Length is encoded by the
    // assembler (typically 3 bytes: 0F 22 /r or 0F 20 /r) but we let
    // SvAdvanceGuestRip's NRip path cover the common case and fall back
    // to 3 if NRip is unreliable (which it occasionally is under nested
    // SVM, see SvAdvanceGuestRip header).
    SvAdvanceGuestRip(VpData, 3);
}

/*!
    @brief  Handles #VMEXIT due to a MOV-to-DR or MOV-from-DR instruction.

    @details
        ExitInfo1 encoding (AMD APM Vol.2 §15.12):
          bits  [2:0]  = DR number
          bit   [4]    = 0 (write to DR), 1 (read from DR)
          bits [11:8]  = GPR index

        DR4/DR5 alias DR6/DR7 when CR4.DE=0; inject #UD when CR4.DE=1.
        All accesses are passed through to hardware.
 */
_IRQL_requires_same_
static
VOID
SvHandleMovDr(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    //
    // AMD SVM ExitInfo1 / ExitCode format for MOV-DR (APM Vol 2 §15.13):
    //
    //   ExitCode  : 0x20..0x2F = MOV-from-DRn (read);  DR# is (ExitCode & 0xF).
    //               0x30..0x3F = MOV-to-DRn   (write); DR# is (ExitCode & 0xF).
    //   ExitInfo1 : bits 3:0   = GPR INDEX of the source/destination register.
    //
    // Same Intel/AMD-confusion bug as SvHandleMovCr - the previous code took
    // DR# from ExitInfo1[2:0] and GPR index from ExitInfo1[11:8] (Intel
    // EXIT_QUALIFICATION layout). That would silently misroute every guest
    // MOV-DR. Not currently fatal because DR1..7 are passed through to the
    // host's DRn, so a misrouted "MOV DR3, RAX" would just write RAX to the
    // wrong DR; under a kernel debugger setting actual hardware breakpoints
    // it becomes "wrong breakpoint fires" which would mislead diagnostics.
    //
    UINT64  exitInfo1 = VpData->GuestVmcb.ControlArea.ExitInfo1;
    UINT64  exitCode = VpData->GuestVmcb.ControlArea.ExitCode;
    UINT32  drNum = (UINT32)(exitCode & 0xF);          // implicit in ExitCode
    UINT32  isRead = (exitCode >= VMEXIT_DR0_READ &&
        exitCode <= VMEXIT_DR15_READ);    // 0x20..0x2F vs 0x30..0x3F
    UINT32  gprIdx = (UINT32)(exitInfo1 & 0xF);          // GPR index, bits [3:0]
    UINT64* gpr = SvGprFromIndex(GuestContext->VpRegs, gprIdx);

    // DR4/DR5: alias or #UD depending on CR4.DE (bit 3).
    if (drNum == 4 || drNum == 5)
    {
        if (VpData->GuestVmcb.StateSaveArea.Cr4 & (1ULL << 3))
        {
            // CR4.DE=1: DR4/DR5 are not aliased — inject #UD.
            EVENTINJ ev;
            ev.AsUInt64 = 0;
            ev.Fields.Vector = 6;    // #UD
            ev.Fields.Type = 3;    // exception
            ev.Fields.Valid = 1;
            VpData->GuestVmcb.ControlArea.EventInj = ev.AsUInt64;
            return;
        }
        drNum = (drNum == 4) ? 6 : 7;
    }

    if (isRead)
    {
        switch (drNum)
        {
        case 0: *gpr = __readdr(0); break;
        case 1: *gpr = __readdr(1); break;
        case 2: *gpr = __readdr(2); break;
        case 3: *gpr = __readdr(3); break;
        case 6: *gpr = __readdr(6); break;
        case 7: *gpr = VpData->GuestVmcb.StateSaveArea.Dr7; break;
        default: *gpr = 0; break;
        }
    }
    else
    {
        switch (drNum)
        {
        case 0: __writedr(0, *gpr); break;
        case 1: __writedr(1, *gpr); break;
        case 2: __writedr(2, *gpr); break;
        case 3: __writedr(3, *gpr); break;
        case 6: __writedr(6, *gpr); break;
        case 7:
            // DR7 is saved/restored by VMRUN/VMEXIT; update VMCB directly.
            VpData->GuestVmcb.StateSaveArea.Dr7 = *gpr;
            break;
        default: break;
        }
    }

    // Advance past the MOV-DR instruction (3 bytes: 0F 21 /r or 0F 23 /r,
    // typically; SvAdvanceGuestRip prefers NRip when valid).
    SvAdvanceGuestRip(VpData, 3);
}

/*!
    @brief  Handles #VMEXIT due to VMMCALL instruction.

    @details
        Mirrors Intel VMCALL gating: ring-3 callers receive #UD.
        Unknown call numbers also receive #UD.  Currently no custom
        call numbers are defined; this is a placeholder gate.
 */
_IRQL_requires_same_
static
VOID
SvHandleVmmcall(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    // Determine CPL from VMCB CS attribute (bits [1:0] of DPL = bits [6:5] of
    // the attribute byte, i.e. (Attrib >> 5) & 3 — AMD APM attribute format).
    UINT32 cpl = (VpData->GuestVmcb.StateSaveArea.CsAttrib >> 5) & 3;

    if (cpl != 0)
    {
        // Ring-3 (or ring-1/2) VMMCALL — inject #UD and do not advance RIP.
        EVENTINJ ev;
        ev.AsUInt64 = 0;
        ev.Fields.Vector = 6;
        ev.Fields.Type = 3;
        ev.Fields.Valid = 1;
        VpData->GuestVmcb.ControlArea.EventInj = ev.AsUInt64;
        VpData->GuestVmcb.ControlArea.NRip = VpData->GuestVmcb.StateSaveArea.Rip;
        return;
    }

    // Gate on magic signature in R10/R11/R12 (mirrors Intel Ophion convention).
    UINT64 r10 = GuestContext->VpRegs->R10;
    UINT64 r11 = GuestContext->VpRegs->R11;
    UINT64 r12 = GuestContext->VpRegs->R12;

    if (r10 != 0x48564653ULL ||
        r11 != 0x564d43414c4cULL ||
        r12 != 0x4e4f485950455256ULL)
    {
        // Unknown / unsigned VMMCALL — inject #UD.
        EVENTINJ ev;
        ev.AsUInt64 = 0;
        ev.Fields.Vector = 6;
        ev.Fields.Type = 3;
        ev.Fields.Valid = 1;
        VpData->GuestVmcb.ControlArea.EventInj = ev.AsUInt64;
        VpData->GuestVmcb.ControlArea.NRip = VpData->GuestVmcb.StateSaveArea.Rip;
        return;
    }

    // Known call number dispatch. Call number is in guest RAX.
    UINT64 callNo = GuestContext->VpRegs->Rax;

    if (callNo == SV_VMMCALL_PROBE)
    {
        // Hypervisor presence probe: ack into guest RAX.
        GuestContext->VpRegs->Rax = SV_VMMCALL_PROBE_ACK;
    }

    // Advance past VMMCALL (0F 01 D9, 3 bytes). SvAdvanceGuestRip uses NRip
    // when it is sanely populated (NRIPS), otherwise curRip + 3.
    SvAdvanceGuestRip(VpData, 3);
}


/*!
    @brief  Handle guest #GP (#VMEXIT_EXCEPTION_GP) under nested virtualisation.

    @details
    When running as L1 inside Hyper-V L0, the L2 guest executes WRMSR/RDMSR
    to a Hyper-V synthetic MSR (0x40000000-0x4FFFFFFF).  Because those MSRs
    live outside the three architectural MSRPM windows, the AMD hardware either
    does not generate a VMEXIT_MSR at all (platform-dependent) or generates a
    hardware #GP directly inside the L2 guest -- which then escalates through
    Windows' crash handler into the 0x3D double-fault bugcheck.

    The fix: intercept #GP in the VMCB (InterceptException bit 13), decode the
    faulting opcode at guest RIP, and if it is WRMSR (0F 30) or RDMSR (0F 32)
    to an HV synthetic MSR while running under Hyper-V, execute the MSR access
    from L1 host context.  Hyper-V L0 intercepts those accesses for L1 normally
    and handles them without fault.  GIF-off is fine here: Hyper-V MSR
    interception operates above AMD SVM's GIF layer.

    All other #GPs are re-injected to the guest unchanged.
*/
static VOID
SvHandleGuestGp(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_CONTEXT GuestContext
)
{
    //
    // If this #GP is a WRMSR/RDMSR to an HV synthetic MSR (0x40000000+),
    // SWALLOW it (ignore writes, zero reads, advance RIP) exactly as the
    // VMEXIT_MSR path does. On some platforms these accesses surface as a
    // hardware #GP here instead of VMEXIT_MSR. We must NOT re-inject #GP for
    // them: Windows' enlightenment code retries in a tight loop, producing a
    // VMEXIT storm on 0x400000B0/0x400000B1 (SynIC SINT registers). We also
    // must NOT forward to host context (unbacked MSR -> host #GP -> bugcheck).
    // Swallowing breaks the loop and the guest falls back to the real APIC.
    //
    //
    // Re-inject the #GP to the guest with the original error code. ExitInfo1
    // holds the #GP error code per AMD APM Vol.2 Sec 15.12.
    //
    // IMPORTANT: we do NOT peek the faulting opcode bytes at the guest RIP
    // here. The guest RIP can be a USERMODE address (ring-3 apps #GP for
    // ordinary reasons); dereferencing it in host context — where we run on
    // the host CR3 that does not map that usermode VA — faults, hits
    // SvHostPageFault, and bugchecks (observed: CR2 = the guest usermode RIP).
    // HV synthetic-MSR accesses are handled entirely in the VMEXIT_MSR path
    // (SvHandleMsrAccess), so the #GP path needs no MSR decoding.
    //
    UNREFERENCED_PARAMETER(GuestContext);

    EVENTINJ ev;
    ev.AsUInt64 = 0;
    ev.Fields.Vector = 13;     // #GP
    ev.Fields.Type = 3;     // Exception
    ev.Fields.ErrorCodeValid = 1;
    ev.Fields.ErrorCode = (UINT32)VpData->GuestVmcb.ControlArea.ExitInfo1;
    ev.Fields.Valid = 1;
    VpData->GuestVmcb.ControlArea.EventInj = ev.AsUInt64;
}

// Forward declarations for NPT shadow handlers (defined after SvBuildNestedPageTables)
static VOID SvHandleNpf(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData);
static VOID SvHandleDb(_Inout_ PVIRTUAL_PROCESSOR_DATA VpData);

/*!
    @brief          C-level entry point of the host code called from SvLaunchVm.

    @details        This function loads save host state first, and then, handles
                    #VMEXIT which may or may not change guest's state via VpData
                    or GuestRegisters.

                    Interrupts are disabled when this function is called due to
                    the cleared GIF. Not all host state are loaded yet, so do it
                    with the VMLOAD instruction.

                    If the #VMEXIT handler detects a request to unload the
                    hypervisor, this function loads guest state, disables SVM
                    and returns to execution flow where the #VMEXIT triggered.

    @param[in,out]  VpData - Per processor data.
    @param[in,out]  GuestRegisters - Guest's GPRs.

    @result         TRUE when virtualization is terminated; otherwise FALSE.
 */
_IRQL_requires_same_
EXTERN_C
BOOLEAN
NTAPI
SvHandleVmExit(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _Inout_ PGUEST_REGISTERS GuestRegisters
)
{
    // Capture the TSC as the very first action, before any other work.
    // This timestamp is used by SvHandleRdtsc for TSC compensation:
    // the compensated path returns cpuid_entry_tsc + bare_metal_cost,
    // and the uncompensated path returns this exit-entry TSC directly,
    // so neither path leaks VMEXIT overhead to the guest.
    const UINT64 exitTsc = __rdtsc();

    // Stage-2 breakpoint: fires on the very first VMEXIT across all CPUs.
    // Commands when WinDbg pauses:
    //   ?? VpData->GuestVmcb.ControlArea.ExitCode      (0xFFFFFFFF... = invalid VMCB)
    //   ?? VpData->GuestVmcb.ControlArea.ExitInfo1
    //   ?? VpData->GuestVmcb.ControlArea.ExitInfo2
    //   ?? VpData->GuestVmcb.StateSaveArea.Rip
    //   ln @@(VpData->GuestVmcb.StateSaveArea.Rip)     (symbolize guest RIP)
    // Remove once first-VMEXIT exit code is understood.


    GUEST_CONTEXT guestContext;
    KIRQL oldIrql;

    guestContext.VpRegs = GuestRegisters;
    guestContext.ExitVm = FALSE;

    //
    // ----- DIAGNOSTIC ENTRY TRACE -----
    // Print the first SV_VMEXIT_TRACE_LIMIT VMEXITs per CPU so we can prove
    // host-side code is running. If you see "VMEXIT entered" in the KDNET
    // log on the next run, the asm stub + VMLOAD + private host context
    // are all working and the crash is downstream of this point. If you
    // do NOT see it, the crash is in the asm stub or VMRUN itself and we
    // go after that next. The trace uses SvDiagPrintFromVmexit which
    // temporarily swaps to the kernel IDT so INT 0x2D from DbgPrint
    // reaches KdDebugServiceTrap instead of SvHostDefaultStub, spins
    // briefly to let KDNET DMA the packet out, then restores the private
    // IDT. Steady-state behavior is unchanged after the first 20 exits.
    //
    // Record the exit into a lock-free per-CPU ring buffer. DO NOT call
    // DbgPrint / vDbgPrintEx here — they are not IPI_LEVEL-safe and
    // calling them from VMEXIT context with GIF=0 will deadlock any peer
    // CPU that is waiting on the same Kd / KDNET internal lock or on a
    // KeIpiGenericCall rendezvous to this CPU. The records are formatted
    // and printed asynchronously by the periodic drain DPC; see
    // SvRecordVmexit and SvDrainVmexitTrace for the contract.
    //
    SvRecordVmexit(VpData);

    //
    // Host FS / GS / TR / LDTR bases and the syscall MSRs are restored from
    // VpData->HostVmcb by an explicit VMLOAD in the asm stub immediately
    // after VMSAVE, BEFORE this function is entered. That ordering is load-
    // bearing: any GS-relative access here (compiler stack-cookie XOR,
    // __chkstk, KPCR self-check) would otherwise walk the guest's stale
    // GS_BASE, which after a guest SWAPGS may point at a user-mode TEB -
    // unreachable from host CR3 and #PF. See the comment block in x64.asm
    // around the post-VMRUN VMLOAD for the full hazard discussion.
    //
    NT_ASSERT(VpData->HostStackLayout.Reserved1 == MAXUINT64);
    // IDT vectoring re-injection. AMD APM Vol.2 §15.7.2: if the CPU was in the
// middle of delivering an IDT event (exception, interrupt, NMI, software
// interrupt) when this VMEXIT fired, that event is captured in ExitIntInfo
// and is otherwise lost. Re-inject by copying to EventInj so it's delivered
// on the next VMRUN.
//
// Handlers that need to inject their own event (e.g. SvHandleVmrun → #GP)
// will simply overwrite EventInj — which is the correct behavior, because
// their new exception replaces the in-flight event that was caused by the
// bad instruction.
//
    UINT64 exitIntInfo = VpData->GuestVmcb.ControlArea.ExitIntInfo;
    if (exitIntInfo & (1ULL << 31))   // Valid bit
    {
        //
        // Re-inject the in-flight IDT event — BUT NOT for NMIs.
        //
        // Type field is bits [10:8].  Type 2 = NMI.  An NMI that was in the
        // middle of being delivered when this VMEXIT fired must NOT be blindly
        // copied to EventInj here: the VMEXIT_NMI handler below re-injects the
        // NMI explicitly with the correct latch handling, and the dedicated
        // VMEXIT_NMI path is the only place that should manage NMI delivery.
        // Copying an NMI here (especially on a non-NMI exit) delivers a
        // spurious NMI to the guest at an arbitrary RIP — the guest's NMI
        // path then runs with interrupts disabled and faults on a NULL/invalid
        // reference (seen as 0xD1 DRIVER_IRQL_NOT_LESS_OR_EQUAL at IRQL 0xFF,
        // address 0, "interrupts were disabled", Stack.Pointer NMI).
        //
        UINT32 inflightType = (UINT32)((exitIntInfo >> 8) & 0x7);
        if (inflightType != 2 /* not NMI */)
        {
            InterlockedIncrement(&g_IdtVectoringReinjects);
            VpData->GuestVmcb.ControlArea.EventInj = exitIntInfo;
        }
    }

    //
    // Raise the IRQL to the DISPATCH_LEVEL level. This has no actual effect since
    // interrupts are disabled at #VMEXI but warrants bug check when some of
    // kernel API that are not usable on this context is called with Driver
    // Verifier. This protects developers from accidentally writing such #VMEXIT
    // handling code. This should actually raise IRQL to HIGH_LEVEL to represent
    // this running context better, but our Logger code is not designed to run at
    // that level unfortunately. Finally, note that this API is a thin wrapper
    // of mov-to-CR8 on x64 and safe to call on this context.
    //
    oldIrql = KeGetCurrentIrql();
    if (oldIrql < DISPATCH_LEVEL)
    {
        KeRaiseIrqlToDpcLevel();
    }

    //
    // Guest's RAX is overwritten by the host's value on #VMEXIT and saved in
    // the VMCB instead. Reflect the guest RAX to the context.
    //
    GuestRegisters->Rax = VpData->GuestVmcb.StateSaveArea.Rax;

    //
    // Update the _KTRAP_FRAME structure values in hypervisor stack, so that
    // Windbg can reconstruct call stack of the guest during debug session.
    // This is optional but very useful thing to do for debugging.
    //
    VpData->HostStackLayout.TrapFrame.Rsp = VpData->GuestVmcb.StateSaveArea.Rsp;
    VpData->HostStackLayout.TrapFrame.Rip = VpData->GuestVmcb.ControlArea.NRip;

    //
    // Handle #VMEXIT according with its reason.
    //
    switch (VpData->GuestVmcb.ControlArea.ExitCode)
    {
    case VMEXIT_CPUID:
        SvHandleCpuid(VpData, &guestContext);
        // No TSC arming here — arming RDTSC/RDTSCP after every CPUID adds a
        // VMEXIT per CPUID and caused 0xC7 TIMER_OR_DPC_INVALID. TSC comp is
        // armed only on the unload leaf inside SvHandleCpuid.
        break;
    case VMEXIT_MSR:
        SvHandleMsrAccess(VpData, &guestContext);
        break;
    case VMEXIT_XSETBV:
        SvHandleXsetbv(VpData, &guestContext);
        break;
    case VMEXIT_RDTSC:
        SvHandleRdtsc(VpData, &guestContext, FALSE, exitTsc);
        break;
    case VMEXIT_RDTSCP:
        SvHandleRdtsc(VpData, &guestContext, TRUE, exitTsc);
        break;
    case VMEXIT_INIT:
        // INIT signal received while in guest mode.  The AMD manual says the
        // hypervisor should re-inject it so the processor processes it after
        // the next VMRUN.  In practice (especially under VMware nested virt)
        // this is a no-op: just let the guest proceed.
        break;
    case VMEXIT_NMI:
    {
        // NMI causes VMEXIT with NMI-in-service latch set. Per AMD APM §15.22.4,
        // new NMIs are blocked until we re-inject via EventInj or execute IRET.
        // Re-inject the NMI so it's delivered to guest and the latch is cleared.

        EVENTINJ ev;
        ev.AsUInt64 = 0;
        ev.Fields.Vector = 2;   // NMI
        ev.Fields.Type = 2;   // NMI type
        ev.Fields.Valid = 1;
        VpData->GuestVmcb.ControlArea.EventInj = ev.AsUInt64;
        break;
    }
#if !SHADOW_PAGING_DISABLED
    case VMEXIT_NPF:
        SvHandleNpf(VpData);
        break;
    case VMEXIT_EXCEPTION_DB:
        SvHandleDb(VpData);
        break;
#endif
    case VMEXIT_EXCEPTION_GP:
        // Guest #GP — may be caused by WRMSR/RDMSR to a Hyper-V synthetic MSR
        // (0x40000000-0x4FFFFFFF) when running as L1 inside Hyper-V L0.
        // SvHandleGuestGp forwards the access from host context under Hyper-V;
        // all other #GPs are re-injected to the guest unchanged.
        SvHandleGuestGp(VpData, &guestContext);
        break;
    case VMEXIT_EXCEPTION_DF:
        // Guest #DF (double fault) — intercepted before it can cascade to triple fault.
        // STGI only ungates external interrupts (sets GIF); software
        // interrupts like INT 0x2D from DbgPrint still go through the
        // currently-loaded IDT. Restore the kernel IDT before DbgPrint so
        // the print + bugcheck path actually works.
        SvSwapToKernelIdtForBugcheck();  // ORDER FIX: swap to kernel IDT BEFORE enabling interrupts
        __svm_stgi();
        _enable();
        DbgPrint("[SimpleSvm] GUEST #DF on CPU%lu: RIP=%016llX RSP=%016llX CR3=%016llX "
            "ExitInfo1=%016llX ExitInfo2=%016llX\n",
            KeGetCurrentProcessorIndex(),
            VpData->GuestVmcb.StateSaveArea.Rip,
            VpData->GuestVmcb.StateSaveArea.Rsp,
            VpData->GuestVmcb.StateSaveArea.Cr3,
            VpData->GuestVmcb.ControlArea.ExitInfo1,
            VpData->GuestVmcb.ControlArea.ExitInfo2);
        SV_DEBUG_BREAK();
#pragma prefast(suppress : __WARNING_USE_OTHER_FUNCTION, "Diagnostic crash.")
        SvFlushKdnetBeforeBugcheck();
        KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0xDF,
            VpData->GuestVmcb.StateSaveArea.Rip,
            VpData->GuestVmcb.ControlArea.ExitInfo1,
            VpData->GuestVmcb.ControlArea.ExitInfo2);
        break;
    case VMEXIT_SHUTDOWN:
        // Guest reached triple fault — SVM unconditionally traps shutdown.
        // Same IDT-swap requirement as VMEXIT_EXCEPTION_DF above.
        SvSwapToKernelIdtForBugcheck();  // ORDER FIX: swap to kernel IDT BEFORE enabling interrupts
        __svm_stgi();
        _enable();
        DbgPrint("[SimpleSvm] GUEST SHUTDOWN (triple fault) on CPU%lu: "
            "RIP=%016llX RSP=%016llX CR3=%016llX EFER=%016llX\n",
            KeGetCurrentProcessorIndex(),
            VpData->GuestVmcb.StateSaveArea.Rip,
            VpData->GuestVmcb.StateSaveArea.Rsp,
            VpData->GuestVmcb.StateSaveArea.Cr3,
            VpData->GuestVmcb.StateSaveArea.Efer);
        SV_DEBUG_BREAK();
#pragma prefast(suppress : __WARNING_USE_OTHER_FUNCTION, "Diagnostic crash.")
        SvFlushKdnetBeforeBugcheck();
        KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0xCAFE,
            VpData->GuestVmcb.StateSaveArea.Rip,
            VpData->GuestVmcb.StateSaveArea.Rsp,
            VpData->GuestVmcb.StateSaveArea.Cr3);
        break;
    case VMEXIT_INTR:
        // External hardware interrupt caused a VMEXIT (only if V_INTR_MASKING
        // is set and RFLAGS.IF=0 in guest).  The interrupt has already been
        // acknowledged by the processor; just let the guest continue.
        break;
    case VMEXIT_VINTR:
        // Virtual interrupt delivery — clear the V_IRQ bit and advance.
        VpData->GuestVmcb.ControlArea.VIntr &= ~(1ULL << 8);
        break;
    case VMEXIT_VMMCALL:
        SvHandleVmmcall(VpData, &guestContext);
        break;
        // Guest attempted an SVM instruction.  We do not provide nested SVM,
        // so inject #UD (do NOT advance RIP — the exception replaces the
        // instruction).  Without these cases the guest's VMRUN/VMLOAD/etc.
        // falls through to default and bugchecks the host (seen as ExitCode
        // 0x80 VMEXIT_VMRUN in MANUALLY_INITIATED_CRASH Arg2).
    case VMEXIT_VMRUN:
    case VMEXIT_VMLOAD:
    case VMEXIT_VMSAVE:
    case VMEXIT_STGI:
    case VMEXIT_CLGI:
    case VMEXIT_SKINIT:
    case VMEXIT_INVLPGA:
        SvInjectUndefinedOpcodeException(VpData);
        break;
    case VMEXIT_CR0_SEL_WRITE:
        SvHandleCr0SelWrite(VpData, &guestContext);
        break;
        // MOV-to-CR8 (write we intercept). CR3 and CR4 removed.
    case VMEXIT_CR8_WRITE:
        // MOV-from-CR8 (read).
    case VMEXIT_CR8_READ:
        SvHandleMovCr(VpData, &guestContext);
        break;
        // DR read/write exits — all 8 debug registers.
    case VMEXIT_DR0_READ:  case VMEXIT_DR1_READ:  case VMEXIT_DR2_READ:
    case VMEXIT_DR3_READ:  case VMEXIT_DR6_READ:  case VMEXIT_DR7_READ:
    case VMEXIT_DR0_WRITE: case VMEXIT_DR1_WRITE: case VMEXIT_DR2_WRITE:
    case VMEXIT_DR3_WRITE: case VMEXIT_DR6_WRITE: case VMEXIT_DR7_WRITE:
        SvHandleMovDr(VpData, &guestContext);
        break;
    default:
        // Stage-3 breakpoint: an unhandled VMEXIT exit code.
        // Commands when WinDbg pauses:
        //   ?? VpData->GuestVmcb.ControlArea.ExitCode
        //   ?? VpData->GuestVmcb.ControlArea.ExitInfo1
        //   ?? VpData->GuestVmcb.ControlArea.ExitInfo2
        //   ?? VpData->GuestVmcb.StateSaveArea.Rip
        //
        // Only break if a kernel debugger is attached. Without one the INT 3
        // would fault on the (about-to-be-restored) kernel IDT path; skip it
        // and fall straight through to the diagnostic bugcheck below.
        if (KdDebuggerNotPresent == FALSE)
        {
            __debugbreak();
        }

        // STGI only ungates external interrupts; software interrupts
        // (INT 0x2D from DbgPrint, and KeBugCheck's own debug print)
        // still walk the currently-loaded IDT. Swap to the kernel IDT
        // first - otherwise INT 0x2D lands on SvHostDefaultStub, the
        // print never appears, and the bugcheck shows up as 0xE2/0x4FF
        // instead of the real exit code.
        SvSwapToKernelIdtForBugcheck();  // ORDER FIX: swap to kernel IDT BEFORE enabling interrupts
        __svm_stgi();
        _enable();
        DbgPrint("[SimpleSvm] UNHANDLED VMEXIT on CPU%lu: ExitCode=0x%llX "
            "ExitInfo1=0x%llX ExitInfo2=0x%llX RIP=%016llX\n",
            KeGetCurrentProcessorIndex(),
            VpData->GuestVmcb.ControlArea.ExitCode,
            VpData->GuestVmcb.ControlArea.ExitInfo1,
            VpData->GuestVmcb.ControlArea.ExitInfo2,
            VpData->GuestVmcb.StateSaveArea.Rip);
        SV_DEBUG_BREAK();
#pragma prefast(suppress : __WARNING_USE_OTHER_FUNCTION, "Unrecoverable path.")
        // Use KeBugCheckEx with sub-code 0xE0 (ours) so the exit code
        // appears in the BSOD parameter list. This is critical when
        // DbgPrint output is lost (e.g. KD disconnected before the
        // print landed) - the bugcheck parameters survive into the
        // crash dump and Arg2 = ExitCode tells us which intercept the
        // switch didn't handle.
        SvFlushKdnetBeforeBugcheck();
        KeBugCheckEx(MANUALLY_INITIATED_CRASH, 0xE0,
            VpData->GuestVmcb.ControlArea.ExitCode,
            VpData->GuestVmcb.ControlArea.ExitInfo1,
            VpData->GuestVmcb.StateSaveArea.Rip);
    }

    //
    // Again, no effect to change IRQL but restoring it here since a #VMEXIT
    // handler where the developers most likely call the kernel API inadvertently
    // is already executed.
    //
    if (oldIrql < DISPATCH_LEVEL)
    {
        KeLowerIrql(oldIrql);
    }

    //
    // Terminate the SimpleSvm hypervisor if requested.
    //
    if (guestContext.ExitVm != FALSE)
    {
        NT_ASSERT(VpData->GuestVmcb.ControlArea.ExitCode == VMEXIT_CPUID);

        //
        // Set return values of CPUID instruction as follows:
        //  RBX     = An address to return
        //  RCX     = A stack pointer to restore
        //  EDX:EAX = An address of per processor data to be freed by the caller
        //
        guestContext.VpRegs->Rax = reinterpret_cast<UINT64>(VpData) & MAXUINT32;
        guestContext.VpRegs->Rbx = VpData->GuestVmcb.ControlArea.NRip;
        guestContext.VpRegs->Rcx = VpData->GuestVmcb.StateSaveArea.Rsp;
        guestContext.VpRegs->Rdx = reinterpret_cast<UINT64>(VpData) >> 32;

        //
        // Load guest state (currently host state is loaded).
        //
        __svm_vmload(MmGetPhysicalAddress(&VpData->GuestVmcb).QuadPart);

        //
        // Set the global interrupt flag (GIF) but still disable interrupts by
        // clearing IF. GIF must be set to return to the normal execution, but
        // interruptions are not desirable until SVM is disabled as it would
        // execute random kernel-code in the host context.
        //
        _disable();
        __svm_stgi();

        //
        // Disable SVM, and restore the guest RFLAGS. This may enable interrupts.
        // Some of arithmetic flags are destroyed by the subsequent code.
        //
        __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) & ~EFER_SVME);

        // Restore original GDT, TR, and IDTR now that host-mode is exiting.
        {
            ULONG exitCpu = KeGetCurrentProcessorIndex();
            if (exitCpu < HOST_GDT_MAX_CPUS)
            {
                if (g_HostGdt[exitCpu])
                {
                    DESCRIPTOR_TABLE_REGISTER origGdtr;
                    origGdtr.Limit = g_OrigGdtLimit[exitCpu];
                    origGdtr.Base = g_OrigGdtBase[exitCpu];
                    SvLoadGdt(&origGdtr);
                    SvLoadTr(g_OrigTrSelector[exitCpu]);
                }
                // Always restore the original IDTR — this is the critical fix:
                // our private IDT is still loaded (VMRUN captured it into HSAVE
                // and the processor restores it on VMEXIT), so any DbgPrint
                // after this point would fire INT 0x2D into our private IDT
                // and triple-fault without this restore.
                if (g_OrigIdtr[exitCpu].Limit != 0)
                    __lidt(&g_OrigIdtr[exitCpu]);
            }
        }

        // Restore System CR3 so the guest page tables are active again.
        __writecr3(g_SystemCr3);

        __writeeflags(VpData->GuestVmcb.StateSaveArea.Rflags);
        goto Exit;
    }

    //
    // Reflect potentially updated guest's RAX to VMCB. Again, unlike other GPRs,
    // RAX is loaded from VMCB on VMRUN.
    //
    VpData->GuestVmcb.StateSaveArea.Rax = guestContext.VpRegs->Rax;

Exit:
    NT_ASSERT(VpData->HostStackLayout.Reserved1 == MAXUINT64);
    return guestContext.ExitVm;
}

/*!
    @brief      Returns attributes of a segment specified by the segment selector.

    @details    This function locates a segment descriptor from the segment
                selector and the GDT base, extracts attributes of the segment,
                and returns it. The returned value is the same as what the "dg"
                command of Windbg shows as "Flags". Here is an example output
                with 0x18 of the selector:
                ----
                0: kd> dg 18
                P Si Gr Pr Lo
                Sel        Base              Limit          Type    l ze an es ng Flags
                ---- ----------------- ----------------- ---------- - -- -- -- -- --------
                0018 00000000`00000000 00000000`00000000 Data RW Ac 0 Bg By P  Nl 00000493
                ----

    @param[in]  SegmentSelector - A segment selector to get attributes of a
                corresponding descriptor.
    @param[in]  GdtBase - A base address of GDT.

    @result     Attributes of the segment.
 */
_IRQL_requires_same_
_Check_return_
static
UINT16
SvGetSegmentAccessRight(
    _In_ UINT16 SegmentSelector,
    _In_ ULONG_PTR GdtBase
)
{
    PSEGMENT_DESCRIPTOR descriptor;
    SEGMENT_ATTRIBUTE attribute;

    //
    // Get a segment descriptor corresponds to the specified segment selector.
    //
    descriptor = reinterpret_cast<PSEGMENT_DESCRIPTOR>(
        GdtBase + (SegmentSelector & ~RPL_MASK));

    //
    // Extract all attribute fields in the segment descriptor to a structure
    // that describes only attributes (as opposed to the segment descriptor
    // consists of multiple other fields).
    //
    attribute.Fields.Type = descriptor->Fields.Type;
    attribute.Fields.System = descriptor->Fields.System;
    attribute.Fields.Dpl = descriptor->Fields.Dpl;
    attribute.Fields.Present = descriptor->Fields.Present;
    attribute.Fields.Avl = descriptor->Fields.Avl;
    attribute.Fields.LongMode = descriptor->Fields.LongMode;
    attribute.Fields.DefaultBit = descriptor->Fields.DefaultBit;
    attribute.Fields.Granularity = descriptor->Fields.Granularity;
    attribute.Fields.Reserved1 = 0;

    return attribute.AsUInt16;
}

/*!
    @brief      Tests whether the SimpleSvm hypervisor is installed.

    @details    This function checks a result of CPUID leaf 40000000h, which
                should return a vendor name of the hypervisor if any of those
                who implement the Microsoft Hypervisor interface is installed.
                If the SimpleSvm hypervisor is installed, this should return
                "SimpleSvm", and if no hypervisor is installed, it the result of
                CPUID is undefined. For more details of the interface, see
                "Requirements for implementing the Microsoft Hypervisor interface"
                https://msdn.microsoft.com/en-us/library/windows/hardware/Dn613994(v=vs.85).aspx

    @result     TRUE when the SimpleSvm is installed; otherwise, FALSE.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Check_return_
static
BOOLEAN
SvIsSimpleSvmHypervisorInstalled(
    VOID
)
{
    //
    // Detect our presence with a signed VMMCALL probe.
    //
    // VMMCALL is the correct primitive: when our hypervisor is present it
    // traps to SvHandleVmmcall (which acks); when it is not present the
    // instruction raises #UD, which the SEH frame below catches. Unlike CPUID,
    // it does not depend on us hiding/serving a magic CPUID leaf — CPUID would
    // return live hardware values on a not-yet-virtualized CPU and is exactly
    // the coupling we are avoiding.
    //
    // Both passes:
    //   - First pass (not yet virtualized): VMMCALL -> #UD -> __except -> FALSE
    //   - Replay pass (virtualized): VMMCALL traps -> ack in RAX -> TRUE
    //
    __try
    {
        UINT64 ack = SvProbeVmmcall(SV_VMMCALL_PROBE);
        return (ack == SV_VMMCALL_PROBE_ACK) ? TRUE : FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

/*!
    @brief      Virtualizes the current processor.

    @details    This function enables SVM, initialize VMCB with the current
                processor state, and enters the guest mode on the current
                processor.

    @param[in,out]  VpData - The address of per processor data.
    @param[in]      SharedVpData - The address of share data.
    @param[in]      ContextRecord - The address of CONETEXT to use as an initial
                    context of the processor after it is virtualized.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
static
VOID
SvPrepareForVirtualization(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData,
    _In_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData,
    _In_ const CONTEXT* ContextRecord
)
{
    DESCRIPTOR_TABLE_REGISTER gdtr, idtr;
    PHYSICAL_ADDRESS guestVmcbPa, hostVmcbPa, hostStateAreaPa, pml4BasePa, msrpmPa;

    //
    // Capture the current GDTR and IDTR to use as initial values of the guest
    // mode.
    //
    _sgdt(&gdtr);
    __sidt(&idtr);

    guestVmcbPa = MmGetPhysicalAddress(&VpData->GuestVmcb);
    hostVmcbPa = MmGetPhysicalAddress(&VpData->HostVmcb);
    hostStateAreaPa = MmGetPhysicalAddress(&VpData->HostStateArea);
    pml4BasePa = MmGetPhysicalAddress(&SharedVpData->Pml4Entries);
    msrpmPa = MmGetPhysicalAddress(SharedVpData->MsrPermissionsMap);

    //
    // Configure to trigger #VMEXIT with CPUID and VMRUN instructions. CPUID is
    // intercepted to present existence of the SimpleSvm hypervisor and provide
    // an interface to ask it to unload itself.
    //
    // VMRUN is intercepted because it is required by the processor to enter the
    // guest mode; otherwise, #VMEXIT occurs due to VMEXIT_INVALID when a
    // processor attempts to enter the guest mode. See "Canonicalization and
    // Consistency Checks" on "VMRUN Instruction".
    //
    // CPUID intercept intentionally omitted.  The hardware VMEXIT+VMRUN
    // round-trip is ~300-1500 cycles regardless of handler speed.  Under
    // CPUID-heavy workloads (Edge/Chrome JIT, driver init bursts) this
    // accumulates into DPC latency that causes concurrent timer expiration
    // (0xC7) with 5+ nested interrupt dispatches.  Guest sees native CPUID
    // (VMware's "VMwareVMware") which is transparent and correct.
    // Probe/unload moves to VMMCALL (already intercepted via InterceptMisc2).
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_CPUID;
    VpData->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMRUN;

#if !SV_MINIMAL_VMCB
    // Intercept VMMCALL so ring-3 callers receive #UD and we can gate the
    // known call-number interface (matches Intel VMCALL gating in Ophion).
    VpData->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_VMMCALL;

    // XSETBV interception is now safe: the host IDT has a full 256-vector
    // default handler (SvHostDefaultStub) so no vector can deliver to a
    // zero gate.  SvHandleXsetbv validates the value and guards _xsetbv
    // with CR4.OSXSAVE + SEH before executing it on the host.
    VpData->GuestVmcb.ControlArea.InterceptMisc2 |= SVM_INTERCEPT_MISC2_XSETBV;

#if !SHADOW_PAGING_DISABLED
    // Only intercept #DB if shadow pages were actually wired up.
    // Under nested virt SvRegisterAllShadowPages is skipped, leaving
    // g_ShadowPageCount == 0 — intercepting #DB then turns every guest
    // single-step into an infinite re-inject loop → host-stack overflow
    // → #DF → triple fault.
    if (g_ShadowPageCount > 0)
    {
        VpData->GuestVmcb.ControlArea.InterceptException |= (1UL << 1);
    }
#endif

    //
    // Intercept guest #DF (exception 8) to diagnose double-fault chains before
    // they cascade to triple fault. This is guest-side diagnostics only.
    //
    VpData->GuestVmcb.ControlArea.InterceptException |= (1UL << 8);

    //
    // Selective CR0 write intercept (CR0_SEL_WRITE = InterceptMisc1 bit 5).
    //
    // AMD SVM has no bit-granular CR0 mask like Intel VMX. It offers two
    // choices: intercept ALL CR0 writes (InterceptCrWrite bit 0), or intercept
    // only writes that change bits OTHER than CR0.TS and CR0.MP
    // (CR0_SEL_WRITE). We use the latter.
    //
    // This matters because MOV CR0 fires constantly from FPU lazy-save context
    // switches that toggle CR0.TS — intercepting those (blanket bit 0) caused
    // 0xC7 TIMER_OR_DPC_INVALID from VMEXIT overhead. CR0_SEL_WRITE skips the
    // TS/MP-only writes entirely (no overhead) but still traps meaningful CR0
    // changes such as a driver clearing CR0.WP to patch read-only memory. We
    // then apply the value to the VMCB so VMRUN loads a clean, consistent CR0,
    // instead of letting the guest write a value that faults in guest mode.
    //
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= (1UL << 5);

    //
    // We do NOT intercept guest #GP (exception 13).
    //
    // The #GP intercept previously existed only for a nested-Hyper-V scenario:
    // when running as L1 inside Hyper-V L0, an L2 guest's WRMSR/RDMSR to the
    // synthetic MSR range (0x40000000-0x4FFFFFFF) faults #GP because L0 does
    // not expose those MSRs nested. But that range is already handled in the
    // VMEXIT_MSR path (SvHandleMsrAccess swallows it), so the #GP intercept is
    // redundant even there.
    //
    // On bare metal it is actively HARMFUL: it traps EVERY legitimate guest
    // #GP and bounces it through SvHandleGuestGp to re-inject. That extra
    // intercept/re-inject round trip corrupts legitimate kernel instruction
    // sequences. Observed failure: a driver executing
    //     mov rax, r12 ; btr rax, 10h ; mov cr0, rax    (clear CR0.WP)
    // resumed with RAX = 0 after the round trip and wrote 0 to CR0, an invalid
    // long-mode state that #GPs and bugchecks 0x109 CRITICAL_STRUCTURE_CORRUPTION.
    // Letting guest #GPs be delivered by hardware directly (no intercept) keeps
    // the guest's own register/RIP state perfectly intact.
    //
    // VpData->GuestVmcb.ControlArea.InterceptException |= (1UL << 13);

    //
    // Also, configure to trigger #VMEXIT on MSR access as configured by the
    // MSRPM. In our case, write to IA32_MSR_EFER is intercepted.
    //
    VpData->GuestVmcb.ControlArea.InterceptMisc1 |= SVM_INTERCEPT_MISC1_MSR_PROT;
    VpData->GuestVmcb.ControlArea.MsrpmBasePa = msrpmPa.QuadPart;

    // CR write/read intercepts.
    // InterceptCrWrite: bit N = intercept writes to CRn.
    // InterceptCrRead:  bit N = intercept reads  from CRn.
    //
    // CR0 write intercept is intentionally absent — MOV CR0 fires on every
    // FPU lazy-save context switch and causes 0xC7 TIMER_OR_DPC_INVALID from
    // DPC latency accumulation.  PE/NE/WP/PG are never cleared by Windows.
    // No CR write intercepts at all.
    //
    // CR8 (TPR = x64 IRQL) intercept removed. Handling guest MOV-CR8 in host
    // context via __writecr8 diverges the guest's hardware TPR from Windows'
    // software IRQL tracking in the KPRCB. SwapContext's ATTEMPTED_SWITCH_FROM
    // _DPC (0xB8) guard reads the effective IRQL/DPC state; when it sees the
    // inconsistency it bugchecks even on a legitimate PASSIVE_LEVEL thread
    // switch (e.g. NtUserMessageCall -> KeWaitForSingleObject). The guest must
    // own its TPR directly in hardware — there is nothing for us to mask or
    // shadow in CR8.
    //
    // CR0 intercept: omitted (MOV CR0 on every FPU switch -> 0xC7 overhead).
    // CR3 intercept: omitted (NPT handles guest CR3 in hardware).
    // CR4 intercept: omitted (no forced-bit enforcement needed for a Windows
    //                guest; the bits we'd force are ones Windows already sets).
    // CR8 intercept: omitted (see above).
    // No CR read intercepts either.
#if 0
    VpData->GuestVmcb.ControlArea.InterceptCrWrite |=
        (1u << 8);    // CR8 — TPR pass-through (DISABLED)
#endif
#endif // !SV_MINIMAL_VMCB

    //
    // Specify guest's address space ID (ASID). TLB is maintained by the ID for
    // guests. Use the same value for all processors since all of them run a
    // single guest in our case. Use 1 as the most likely supported ASID by the
    // processor. The actual the supported number of ASID can be obtained with
    // CPUID. See "CPUID Fn8000_000A_EBX SVM Revision and Feature
    // Identification". Zero of ASID is reserved and illegal.
    //
    VpData->GuestVmcb.ControlArea.GuestAsid = 1;

    //
    // Enable Nested Page Tables. By enabling this, the processor performs the
    // nested page walk, that involves with an additional page walk to translate
    // a guest physical address to a system physical address. An address of
    // nested page tables is specified by the NCr3 field of VMCB.
    //
    // We have already build the nested page tables with SvBuildNestedPageTables.
    //
    // Note that our hypervisor does not trigger any additional #VMEXIT due to
    // the use of Nested Page Tables since all physical addresses from 0-512 GB
    // are configured to be accessible from the guest.
    //
    VpData->GuestVmcb.ControlArea.NpEnable |= SVM_NP_ENABLE_NP_ENABLE;
    VpData->GuestVmcb.ControlArea.NCr3 = pml4BasePa.QuadPart;

    //
    // Set up the initial guest state based on the current system state.
    // values are loaded into the processor as guest state when the VMRUN
    // instruction is executed.
    //
    VpData->GuestVmcb.StateSaveArea.GdtrBase = gdtr.Base;
    VpData->GuestVmcb.StateSaveArea.GdtrLimit = gdtr.Limit;
    VpData->GuestVmcb.StateSaveArea.IdtrBase = idtr.Base;
    VpData->GuestVmcb.StateSaveArea.IdtrLimit = idtr.Limit;

    VpData->GuestVmcb.StateSaveArea.CsLimit = GetSegmentLimit(ContextRecord->SegCs);
    VpData->GuestVmcb.StateSaveArea.DsLimit = GetSegmentLimit(ContextRecord->SegDs);
    VpData->GuestVmcb.StateSaveArea.EsLimit = GetSegmentLimit(ContextRecord->SegEs);
    VpData->GuestVmcb.StateSaveArea.SsLimit = GetSegmentLimit(ContextRecord->SegSs);
    VpData->GuestVmcb.StateSaveArea.CsSelector = ContextRecord->SegCs;
    VpData->GuestVmcb.StateSaveArea.DsSelector = ContextRecord->SegDs;
    VpData->GuestVmcb.StateSaveArea.EsSelector = ContextRecord->SegEs;
    VpData->GuestVmcb.StateSaveArea.SsSelector = ContextRecord->SegSs;
    VpData->GuestVmcb.StateSaveArea.CsAttrib = SvGetSegmentAccessRight(ContextRecord->SegCs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.DsAttrib = SvGetSegmentAccessRight(ContextRecord->SegDs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.EsAttrib = SvGetSegmentAccessRight(ContextRecord->SegEs, gdtr.Base);
    VpData->GuestVmcb.StateSaveArea.SsAttrib = SvGetSegmentAccessRight(ContextRecord->SegSs, gdtr.Base);

    //
    // Guest EFER: force EFER_SVME set. AMD VMRUN performs a consistency check
    // requiring guest EFER.SVME == 1; if it is clear, VMRUN raises #GP on the
    // VMRUN instruction itself (faulting RIP = SvLaunchVm vmrun), which lands
    // in the host #GP/default handler and bugchecks. __readmsr can return EFER
    // without SVME on a capture/replay second pass, so OR the bit in
    // unconditionally. The guest cannot observe this — SvHandleMsrAccess masks
    // EFER_SVME out of any guest EFER read.
    //
    VpData->GuestVmcb.StateSaveArea.Efer = __readmsr(IA32_MSR_EFER) | EFER_SVME;
    VpData->GuestVmcb.StateSaveArea.Cr0 = __readcr0();
    VpData->GuestVmcb.StateSaveArea.Cr2 = __readcr2();
    VpData->GuestVmcb.StateSaveArea.Cr3 = __readcr3();
    VpData->GuestVmcb.StateSaveArea.Cr4 = __readcr4();
    VpData->GuestVmcb.StateSaveArea.Rflags = ContextRecord->EFlags;
    VpData->GuestVmcb.StateSaveArea.Rsp = ContextRecord->Rsp;
    VpData->GuestVmcb.StateSaveArea.Rip = ContextRecord->Rip;
    VpData->GuestVmcb.StateSaveArea.GPat = __readmsr(IA32_MSR_PAT);

    //
    // Save some of the current state on VMCB. Some of those states are:
    // - FS, GS, TR, LDTR (including all hidden state)
    // - KernelGsBase
    // - STAR, LSTAR, CSTAR, SFMASK
    // - SYSENTER_CS, SYSENTER_ESP, SYSENTER_EIP
    // See "VMSAVE and VMLOAD Instructions" for mode details.
    //
    // Those are restored to the processor right before #VMEXIT with the VMLOAD
    // instruction so that the guest can start its execution with saved state,
    // and also, re-saved to the VMCS with right after #VMEXIT with the VMSAVE
    // instruction so that the host (hypervisor) do not destroy guest's state.
    //
    __svm_vmsave(guestVmcbPa.QuadPart);

    //
    // Store data to stack so that the host (hypervisor) can use those values.
    //
    VpData->HostStackLayout.Reserved1 = MAXUINT64;
    VpData->HostStackLayout.SharedVpData = SharedVpData;
    VpData->HostStackLayout.Self = VpData;
    VpData->HostStackLayout.HostVmcbPa = hostVmcbPa.QuadPart;
    VpData->HostStackLayout.GuestVmcbPa = guestVmcbPa.QuadPart;

    //
    // Set an address of the host state area to VM_HSAVE_PA MSR. The processor
    // saves some of the current state on VMRUN and loads them on #VMEXIT. See
    // "VM_HSAVE_PA MSR (C001_0117h)".
    //
    __writemsr(SVM_MSR_VM_HSAVE_PA, hostStateAreaPa.QuadPart);

    //
    // Also, save some of the current state to VMCB for the host. This is loaded
    // after #VMEXIT to reproduce the current state for the host (hypervisor).
    //
    __svm_vmsave(hostVmcbPa.QuadPart);
}

/*!
    @brief      Virtualize the current processor.

    @details    This function enables SVM, initialize VMCB with the current
                processor state, and enters the guest mode on the current
                processor.

    @param[in]  Context - A pointer of share data.

    @result     STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Check_return_
static
NTSTATUS
SvVirtualizeProcessor(
    _In_opt_ PVOID Context
)
{
    NTSTATUS status;
    PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData;
    PVIRTUAL_PROCESSOR_DATA vpData;
    PCONTEXT contextRecord;
    SHADOW_STEP_STATE* shadowStepState;

    vpData = nullptr;
    shadowStepState = nullptr;

    NT_ASSERT(ARGUMENT_PRESENT(Context));
    _Analysis_assume_(ARGUMENT_PRESENT(Context));

    contextRecord = static_cast<PCONTEXT>(ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*contextRecord),
        'MVSS'));
    if (contextRecord == nullptr)
    {
        SvDebugPrint("Insufficient memory.\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Allocate per processor data.
    //
#pragma prefast(suppress : __WARNING_MEMORY_LEAK, "Ownership is taken on success.")
    vpData = static_cast<PVIRTUAL_PROCESSOR_DATA>(
        SvAllocatePageAlingedPhysicalMemory(sizeof(VIRTUAL_PROCESSOR_DATA)));
    if (vpData == nullptr)
    {
        SvDebugPrint("Insufficient memory.\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    shadowStepState = static_cast<SHADOW_STEP_STATE*>(ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*shadowStepState),
        'tSVS'));
    if (shadowStepState == nullptr)
    {
        SvDebugPrint("Insufficient memory for shadow-step state.\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    RtlZeroMemory(shadowStepState, sizeof(*shadowStepState));
    vpData->HostStackLayout.ShadowStepState = shadowStepState;

    //
    // Capture the current RIP, RSP, RFLAGS, and segment selectors. This
    // captured state is used as an initial state of the guest mode; therefore
    // when virtualization starts by the later call of SvLaunchVm, a processor
    // resume its execution at this location and state.
    //
    RtlCaptureContext(contextRecord);

    //
    // First time of this execution, the SimpleSvm hypervisor is not installed
    // yet. Therefore, the branch is taken, and virtualization is attempted.
    //
    // At the second execution of here, after SvLaunchVm virtualized the
    // processor, SvIsSimpleSvmHypervisorInstalled returns TRUE, and this
    // function exits with STATUS_SUCCESS.
    //
    SvDebugPrint("[VirtCPU%lu] Checking if already virtualized (EFER=%016llX CR0=%016llX CR4=%016llX)...\n",
        KeGetCurrentProcessorIndex(),
        __readmsr(IA32_MSR_EFER), __readcr0(), __readcr4());

    if (SvIsSimpleSvmHypervisorInstalled() == FALSE)
    {
        SvDebugPrint("Attempting to virtualize the processor.\n");
        sharedVpData = static_cast<PSHARED_VIRTUAL_PROCESSOR_DATA>(Context);

        //
        // Enable SVM by setting EFER.SVME. It has already been verified that this
        // bit was writable with SvIsSvmSupported.
        //
        SvDebugPrint("[VirtCPU%lu] Enabling SVME (EFER before=%016llX)...\n",
            KeGetCurrentProcessorIndex(), __readmsr(IA32_MSR_EFER));
        __writemsr(IA32_MSR_EFER, __readmsr(IA32_MSR_EFER) | EFER_SVME);
        SvDebugPrint("[VirtCPU%lu] SVME enabled (EFER after=%016llX)\n",
            KeGetCurrentProcessorIndex(), __readmsr(IA32_MSR_EFER));

        //
        // Set up VMCB, the structure describes the guest state and what events
        // within the guest should be intercepted, ie, triggers #VMEXIT.
        //
        SvDebugPrint("[VirtCPU%lu] Preparing VMCB (vpData=%p guestVmcbPA=%016llX)...\n",
            KeGetCurrentProcessorIndex(), vpData,
            MmGetPhysicalAddress(&vpData->GuestVmcb).QuadPart);
        SvPrepareForVirtualization(vpData, sharedVpData, contextRecord);
        SvDebugPrint("[VirtCPU%lu] VMCB ready: NCr3=%016llX intercepts1=%08X intercepts2=%08X "
            "interceptExcept=%08X RIP=%016llX RSP=%016llX\n",
            KeGetCurrentProcessorIndex(),
            vpData->GuestVmcb.ControlArea.NCr3,
            vpData->GuestVmcb.ControlArea.InterceptMisc1,
            vpData->GuestVmcb.ControlArea.InterceptMisc2,
            vpData->GuestVmcb.ControlArea.InterceptException,
            vpData->GuestVmcb.StateSaveArea.Rip,
            vpData->GuestVmcb.StateSaveArea.Rsp);

        //
        // Switch to the host RSP to run as the host (hypervisor), and then
        // enters loop that executes code as a guest until #VMEXIT happens and
        // handles #VMEXIT as the host.
        //
        // This function should never return to here.
        //
        SvDebugPrint("[VirtCPU%lu] Launching VM (GuestVmcbPa=%016llX HostVmcbPa=%016llX)...\n",
            KeGetCurrentProcessorIndex(),
            vpData->HostStackLayout.GuestVmcbPa,
            vpData->HostStackLayout.HostVmcbPa);

        DESCRIPTOR_TABLE_REGISTER hostIdtr;
        UINT16 csSelector;
        ULONG cpu = KeGetCurrentProcessorIndex();

        csSelector = contextRecord->SegCs;

        // ----------------------------------------------------------------
        // Phase 1: everything that requires interrupts ENABLED (allocates
        // memory, calls kernel APIs, may internally call DbgPrint).
        // ----------------------------------------------------------------

        // Initialize the shared host IDT once — pure memory writes, safe here.
        if (!g_HostIdtInitialized)
        {
            RtlZeroMemory(g_HostIdt, sizeof(g_HostIdt));
            for (UINT32 v = 0; v < 256; v++)
                SvSetIdtEntry(g_HostIdt, (UINT8)v, SvHostDefaultStub, 0, csSelector);
            SvSetIdtEntry(g_HostIdt, 8, SvHostDoubleFaultStub, 1, csSelector);
            SvSetIdtEntry(g_HostIdt, 13, SvHostGeneralProtectionStub, 0, csSelector);
            SvSetIdtEntry(g_HostIdt, 14, SvHostPageFaultStub, 0, csSelector);

            // Route #DB (vector 1) and #BP (vector 3 / __debugbreak) through
            // the kernel's own IDT handlers so WinDbg can catch breakpoints
            // placed inside VMEXIT code. Without this, int 1 and int 3 hit
            // SvHostDefaultStub and bugcheck instead of breaking into the
            // debugger.
            DESCRIPTOR_TABLE_REGISTER kernelIdtr;
            __sidt(&kernelIdtr);
            if (kernelIdtr.Limit >= (3 * sizeof(IDT_ENTRY_64) + sizeof(IDT_ENTRY_64) - 1))
            {
                IDT_ENTRY_64* kernelIdt = (IDT_ENTRY_64*)kernelIdtr.Base;
                g_HostIdt[1] = kernelIdt[1];   // #DB
                g_HostIdt[2] = kernelIdt[2];   // NMI — forward to kernel handler,
                //   not SvHostDefaultStub. Without
                //   this, any NMI arriving while
                //   the VMEXIT handler is running
                //   hits the default stub → bugcheck.
                g_HostIdt[3] = kernelIdt[3];   // #BP (__debugbreak / int 3)
            }

            g_HostIdtInitialized = TRUE;
        }

        // Build private host CR3 (calls ExAllocatePool2 + MmGetPhysicalAddress).
        if (g_HostCr3Pa == 0)
            SvBuildHostCr3();

        // Build per-CPU private GDT copy (calls ExAllocatePool2).
        SvBuildHostGdt(cpu);

        // Stage-1 breakpoint: inspect VMCB before the first VMRUN.
        // Must fire HERE — before _disable() and before the private IDT/CR3
        // are loaded. After __lidt / __writecr3 the kernel debugger has no
        // vector table and cannot receive INT 3, so the breakpoint would
        // triple-fault without a kernel debugger attached.
        //
        // Only break if a kernel debugger is actually attached. On a
        // debugger-less boot KdDebuggerNotPresent is TRUE and we skip the
        // INT 3 entirely (an unhandled INT 3 with no debugger bugchecks).
        if (KdDebuggerNotPresent == FALSE)
        {
            __debugbreak();
        }

        // ----------------------------------------------------------------
        // Phase 2: interrupts DISABLED — no allocations, no DbgPrint,
        // no kernel API that requires interrupts.  Only register loads
        // and the VMRUN itself from here to SvLaunchVm.
        // ----------------------------------------------------------------
        _disable();

        // NOTE: We no longer patch the live system TSS here. Our private GDT's
        // TSS descriptor (built in SvBuildHostGdt) now points at our own
        // g_HostTss[cpu], which already has Ist1 set up for us. The real
        // Windows TSS is never modified — see SvBuildHostGdt for why directly
        // patching it caused CRITICAL_STRUCTURE_CORRUPTION (0x109).

        // Save the original IDTR — must be restored on teardown because VMRUN
        // captures IDTR into HSAVE and every VMEXIT restores our private IDT.
        if (cpu < HOST_GDT_MAX_CPUS)
            __sidt(&g_OrigIdtr[cpu]);

        // Load private GDT (already built above).
        if (cpu < HOST_GDT_MAX_CPUS && g_HostGdt[cpu])
        {
            DESCRIPTOR_TABLE_REGISTER privGdtr;
            privGdtr.Limit = g_OrigGdtLimit[cpu];
            privGdtr.Base = (UINT64)g_HostGdt[cpu];

            // Clear the TSS busy bit in the private GDT right before LTR.
            // The busy bit clear in SvBuildHostGdt runs only once, but LTR
            // itself marks the descriptor busy (type 0x9 -> 0xB).  If this
            // path runs a second time on the same CPU (e.g. a failed VMRUN
            // returns and virtualization is re-attempted), the descriptor is
            // already busy and the next LTR raises #GP(0).  Clearing it here
            // makes LTR idempotent across repeated passes.
            UINT16 trSel = g_OrigTrSelector[cpu];
            if (trSel && ((trSel & ~7U) + 7U) <= privGdtr.Limit)
            {
                PUINT8 trDesc = (PUINT8)g_HostGdt[cpu] + (trSel & ~7U);
                trDesc[5] &= ~(UINT8)0x02;   // clear busy bit (bit 1 of access byte)
            }

            SvLoadGdt(&privGdtr);
            SvLoadTr(trSel);
        }

        // Load private IDT — from this point forward NO DbgPrint / kernel API.
        hostIdtr.Limit = sizeof(g_HostIdt) - 1;
        hostIdtr.Base = (UINT64)&g_HostIdt;
        __lidt(&hostIdtr);

        __writecr3(g_HostCr3Pa != 0 ? g_HostCr3Pa : (UINT64)g_SystemCr3);

        SvLaunchVm(&vpData->HostStackLayout.GuestVmcbPa);
        SV_DEBUG_BREAK();
#pragma prefast(suppress : __WARNING_USE_OTHER_FUNCTION, "Unrecoverble path.")
        SvFlushKdnetBeforeBugcheck();
        KeBugCheck(MANUALLY_INITIATED_CRASH);
    }

    SvDebugPrint("The processor has been virtualized. [CPU%lu]\n",
        KeGetCurrentProcessorIndex());
    status = STATUS_SUCCESS;

Exit:
    if (contextRecord != nullptr)
    {
        ExFreePoolWithTag(contextRecord, 'MVSS');
    }
    if ((!NT_SUCCESS(status)) && (vpData != nullptr))
    {
        //
        // Frees per processor data if allocated and this function is
        // unsuccessful.
        //
        if (shadowStepState != nullptr)
        {
            ExFreePoolWithTag(shadowStepState, 'tSVS');
            vpData->HostStackLayout.ShadowStepState = nullptr;
        }
        SvFreePageAlingedPhysicalMemory(vpData);
    }
    return status;
}

/*!
    @brief      Execute a callback on all processors one-by-one.

    @details    This function execute Callback with Context as a parameter for
                each processor on the current IRQL. If the callback returned
                non-STATUS_SUCCESS value or any error occurred, this function
                stops execution of the callback and returns the error code.

                When NumOfProcessorCompleted is not NULL, this function always
                set a number of processors that successfully executed the
                callback.

    @param[in]  Callback - A function to execute on all processors.
    @param[in]  Context - A parameter to pass to the callback.
    @param[out] NumOfProcessorCompleted - A pointer to receive a number of
                processors executed the callback successfully.

    @result     STATUS_SUCCESS when Callback executed and returned STATUS_SUCCESS
                on all processors; otherwise, an appropriate error code.
 */
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Check_return_
static
NTSTATUS
SvExecuteOnEachProcessor(
    _In_ NTSTATUS(*Callback)(PVOID),
    _In_opt_ PVOID Context,
    _Out_opt_ PULONG NumOfProcessorCompleted
)
{
    NTSTATUS status;
    ULONG i, numOfProcessors;
    PROCESSOR_NUMBER processorNumber;
    GROUP_AFFINITY affinity, oldAffinity;

    status = STATUS_SUCCESS;

    //
    // Get a number of processors on this system.
    //
    numOfProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);

    for (i = 0; i < numOfProcessors; i++)
    {
        //
        // Convert from an index to a processor number.
        //
        status = KeGetProcessorNumberFromIndex(i, &processorNumber);
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }

        //
        // Switch execution of this code to a processor #i.
        //
        affinity.Group = processorNumber.Group;
        affinity.Mask = 1ULL << processorNumber.Number;
        affinity.Reserved[0] = affinity.Reserved[1] = affinity.Reserved[2] = 0;
        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

        //
        // Execute the callback.
        //
        status = Callback(Context);

        //
        // Revert the previously executed processor.
        //
        KeRevertToUserGroupAffinityThread(&oldAffinity);

        //
        // Exit if the callback returned error.
        //
        if (!NT_SUCCESS(status))
        {
            goto Exit;
        }
    }

Exit:
    //
    // i must be the same as the number of processors on the system when this
    // function returns STATUS_SUCCESS;
    //
    NT_ASSERT(!NT_SUCCESS(status) || (i == numOfProcessors));

    //
    // Set a number of processors that successfully executed callback if the
    // out parameter is present.
    //
    if (ARGUMENT_PRESENT(NumOfProcessorCompleted))
    {
        *NumOfProcessorCompleted = i;
    }
    return status;
}

/*!
    @brief      De-virtualize the current processor if virtualized.

    @details    This function asks SimpleSVM hypervisor to deactivate itself
                through CPUID with a back-door function id and frees per
                processor data if it is returned. If the SimpleSvm is not
                installed, this function does nothing.

    @param[in]  Context - An out pointer to receive an address of shared data.

    @result     Always STATUS_SUCCESS.
 */
_IRQL_requires_max_(DISPATCH_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Check_return_
static
NTSTATUS
SvDevirtualizeProcessor(
    _In_opt_ PVOID Context
)
{
    int registers[4];   // EAX, EBX, ECX, and EDX
    UINT64 high, low;
    PVIRTUAL_PROCESSOR_DATA vpData;
    PSHARED_VIRTUAL_PROCESSOR_DATA* sharedVpDataPtr;

    if (!ARGUMENT_PRESENT(Context))
    {
        goto Exit;
    }

    //
    // Ask SimpleSVM hypervisor to deactivate itself. If the hypervisor is
    // installed, this ECX is set to 'SSVM', and EDX:EAX indicates an address
    // of per processor data to be freed.
    //
    __cpuidex(registers, CPUID_UNLOAD_SIMPLE_SVM, CPUID_UNLOAD_SIMPLE_SVM);
    if (registers[2] != 'SSVM')
    {
        goto Exit;
    }

    SvDebugPrint("The processor has been de-virtualized.\n");

    //
    // Get an address of per processor data indicated by EDX:EAX.
    //
    high = registers[3];
    low = registers[0] & MAXUINT32;
    vpData = reinterpret_cast<PVIRTUAL_PROCESSOR_DATA>(high << 32 | low);
    NT_ASSERT(vpData->HostStackLayout.Reserved1 == MAXUINT64);

    //
    // Save an address of shared data, then free per processor data.
    //
    sharedVpDataPtr = static_cast<PSHARED_VIRTUAL_PROCESSOR_DATA*>(Context);
    *sharedVpDataPtr = vpData->HostStackLayout.SharedVpData;
    if (vpData->HostStackLayout.ShadowStepState != nullptr)
    {
        ExFreePoolWithTag(vpData->HostStackLayout.ShadowStepState, 'tSVS');
        vpData->HostStackLayout.ShadowStepState = nullptr;
    }
    SvFreePageAlingedPhysicalMemory(vpData);

Exit:
    return STATUS_SUCCESS;
}

/*!
    @brief      De-virtualize all virtualized processors.

    @details    This function execute a callback to de-virtualize a processor on
                all processors, and frees shared data when the callback returned
                its pointer from a hypervisor.
 */
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
static
VOID
SvDevirtualizeAllProcessors(
    VOID
)
{
    PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData;

    sharedVpData = nullptr;

    //
    // De-virtualize all processors and free shared data when returned.
    //
    NT_VERIFY(NT_SUCCESS(SvExecuteOnEachProcessor(SvDevirtualizeProcessor,
        &sharedVpData,
        nullptr)));
    if (sharedVpData != nullptr)
    {
        SvFreeContiguousMemory(sharedVpData->MsrPermissionsMap);
        SvFreePageAlingedPhysicalMemory(sharedVpData);
    }

    // Free exec/decoy contiguous pages allocated by RegisterNptShadowPage.
    // Must happen after de-virtualization so NPT no longer references these PAs.
    for (ULONG i = 0; i < g_ShadowPageCount; i++)
    {
        PSHADOW_PAGE_ENTRY e = &g_ShadowPages[i];
        if (e->ExecVA) { SvFreeContiguousMemory(e->ExecVA);  e->ExecVA = nullptr; }
        if (e->DecoyVA) { SvFreeContiguousMemory(e->DecoyVA); e->DecoyVA = nullptr; }
        if (e->CaveMdl)
        {
            MmUnlockPages(e->CaveMdl);
            IoFreeMdl(e->CaveMdl);
            e->CaveMdl = nullptr;
        }
        e->Active = FALSE;
    }
    g_ShadowPageCount = 0;

    // Free pre-allocated overflow NPT trees.
    for (ULONG s = 0; s < NPT_OVERFLOW_SLOTS; s++)
    {
        if (g_NptOverflowTrees[s])
        {
            SvFreePageAlingedPhysicalMemory(g_NptOverflowTrees[s]);
            g_NptOverflowTrees[s] = nullptr;
        }
    }
    g_NptOverflowCount = 0;
    RtlZeroMemory(g_NptPml4IdxToTree, sizeof(g_NptPml4IdxToTree));
}

// ============================================================
//  NPT shadow paging — split + register
// ============================================================

// A 4KB NPT page table entry (used when we split a 2MB PDE).
typedef struct _PT_ENTRY_4KB
{
    union {
        UINT64 AsUInt64;
        struct {
            UINT64 Valid : 1;
            UINT64 Write : 1;
            UINT64 User : 1;
            UINT64 WriteThrough : 1;
            UINT64 CacheDisable : 1;
            UINT64 Accessed : 1;
            UINT64 Dirty : 1;
            UINT64 Pat : 1;
            UINT64 Global : 1;
            UINT64 Avl : 3;
            UINT64 PageFrameNumber : 40;
            UINT64 Reserved2 : 11;
            UINT64 NoExecute : 1;
        } Fields;
    };
} PT_ENTRY_4KB, * PPT_ENTRY_4KB;
static_assert(sizeof(PT_ENTRY_4KB) == 8, "PT_ENTRY_4KB size");

static FORCEINLINE VOID SvRequestGuestTlbFlush(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData)
{
    // 1 = flush all guest TLB entries (architectural baseline)
    // 3 = flush entries for this VMCB's ASID (requires FlushByAsid)
    VpData->GuestVmcb.ControlArea.TlbControl =
        g_SvmFlushByAsidSupported ? 3u : 1u;
    VpData->GuestVmcb.ControlArea.VmcbClean = 0;
}

// Split the 2MB NPT PDE that covers GuestPA into 512 4KB PTEs.
// Returns a pointer to the specific 4KB PTE for GuestPA, or NULL on failure.
static PPT_ENTRY_4KB SplitNptLargePage(
    _Inout_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData,
    _In_    ULONG64 GuestPA)
{
    ULONG64 pa2MB = GuestPA & ~((ULONG64)0x1FFFFF);   // 2MB-aligned GPA

    // Check if we already split this 2MB region
    for (ULONG i = 0; i < g_SplitPtCount; i++) {
        if (g_SplitPtGPA2MB[i] == pa2MB) {
            // Already split — just return the 4KB PTE pointer
            PPT_ENTRY_4KB pt = (PPT_ENTRY_4KB)g_SplitPtVAs[i];
            ULONG pteIdx = (ULONG)((GuestPA >> 12) & 0x1FF);
            return &pt[pteIdx];
        }
    }

    if (g_SplitPtCount >= MAX_SPLIT_PTS)
        return NULL;

    // Locate the 2MB PDE in the existing NPT structure.
    // NPT: Pml4Entries[pml4Idx] → Pml4eTrees[pml4Idx].PdptEntries[pdptIdx]
    //      → Pml4eTrees[pml4Idx].PdEntries[pdptIdx][pdIdx]
    ULONG pml4Idx = (ULONG)((GuestPA >> 39) & 0x1FF);
    ULONG pdptIdx = (ULONG)((GuestPA >> 30) & 0x1FF);
    ULONG pdIdx = (ULONG)((GuestPA >> 21) & 0x1FF);

    if (pml4Idx >= NPT_PML4_COUNT)
        return NULL;   // GPA is outside NPT coverage

    PPD_ENTRY_2MB pde = &SharedVpData->Pml4eTrees[pml4Idx].PdEntries[pdptIdx][pdIdx];
    if (!pde->Fields.Valid || !pde->Fields.LargePage)
        return NULL;

    // Allocate a new 512-entry 4KB PT
    PPT_ENTRY_4KB pt = (PPT_ENTRY_4KB)SvAllocatePageAlingedPhysicalMemory(PAGE_SIZE);
    if (!pt)
        return NULL;

    // Populate all 512 4KB PTEs as identity-mapped, RWX
    for (ULONG i = 0; i < 512; i++) {
        pt[i].AsUInt64 = 0;
        pt[i].Fields.Valid = 1;
        pt[i].Fields.Write = 1;
        pt[i].Fields.User = 1;
        pt[i].Fields.PageFrameNumber = ((pa2MB >> 12) + i);
    }

    // Retarget the 2MB PDE to the new 4KB PT.
    // IMPORTANT: PD_ENTRY_2MB.Fields.PageFrameNumber sits at bit 21 (the
    // 2MB large-page format).  A non-large PDE must store the PT PFN at
    // bits [12:51].  Reusing the same bitfield after clearing LargePage
    // would place the PFN 9 bits too high, setting reserved bits and
    // causing a reserved-bit #NPF on every data access to the region.
    // Write the demoted entry as a raw 64-bit value instead.
    PHYSICAL_ADDRESS ptPA = MmGetPhysicalAddress(pt);
    // Keep Valid(0)|Write(1)|User(2) from the old entry, clear everything
    // else (LargePage, PAT, dirty, accessed, reserved), and insert the PT
    // PFN at [12:51] in standard non-large PDE format.
    pde->AsUInt64 = (ptPA.QuadPart & 0x000FFFFFFFFFF000ULL) |
        (pde->AsUInt64 & 0x7ULL);   // preserve V/W/U

    // Track so we can find it again.
    // Cache the physical address at init time so the VMEXIT-context NPF handler
    // can resolve PT VA from the PDE's PA without calling MmGetVirtualForPhysical.
    g_SplitPtVAs[g_SplitPtCount] = pt;
    g_SplitPtPAs[g_SplitPtCount] = (ULONG64)ptPA.QuadPart;
    g_SplitPtGPA2MB[g_SplitPtCount] = pa2MB;
    g_SplitPtCount++;

    ULONG pteIdx = (ULONG)((GuestPA >> 12) & 0x1FF);
    return &pt[pteIdx];
}

// Called once after SvBuildNestedPageTables + CreateRwxHandlers.
// For every registered shadow page, split the covering 2MB PDE and
// point the 4KB PTE at the decoy page (NX=1 so reads see NOPs,
// execute faults trigger #NPF).
static VOID SvRegisterAllShadowPages(
    _Inout_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData)
{
    for (ULONG i = 0; i < g_ShadowPageCount; i++) {
        PSHADOW_PAGE_ENTRY e = &g_ShadowPages[i];
        if (!e->Active)
            continue;

        PPT_ENTRY_4KB pte = SplitNptLargePage(SharedVpData, e->GuestPA);
        if (!pte) {
            e->Active = FALSE;
            continue;
        }

        // Point PTE at decoy page, NX=1 — reads return NOPs, fetch triggers #NPF
        pte->Fields.PageFrameNumber = e->DecoyPA >> PAGE_SHIFT;
        pte->Fields.NoExecute = 1;
        pte->Fields.Write = 0;

        e->NptPte = &pte->AsUInt64;
        e->InExecState = FALSE;
    }
}

// Lookup shadow entry by guest physical address of the faulting page.
static PSHADOW_PAGE_ENTRY SvFindShadowEntry(ULONG64 faultGPA)
{
    ULONG64 pageGPA = faultGPA & ~(ULONG64)0xFFF;
    for (ULONG i = 0; i < g_ShadowPageCount; i++) {
        if (g_ShadowPages[i].Active && g_ShadowPages[i].GuestPA == pageGPA)
            return &g_ShadowPages[i];
    }
    return NULL;
}

// #NPF handler: instruction fetch on a shadow-guarded page.
// Swap NPT PTE to exec page (NX=0), arm single-step via RFLAGS.TF.
static VOID SvHandleNpf(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData)
{
#if SHADOW_PAGING_DISABLED
    UNREFERENCED_PARAMETER(VpData);
    // Shadow paging disabled — identity NPT has no NX pages; no NPFs expected.
    return;
#else
    ULONG64 exitInfo1 = VpData->GuestVmcb.ControlArea.ExitInfo1;
    ULONG64 faultGPA = VpData->GuestVmcb.ControlArea.ExitInfo2;

    // AMD APM Vol.2 §15.25.6: ExitInfo1 bit 4 (I/D) signals an instruction
    // fetch blocked by NX=1 in the NPT — the only NPF our shadow pages generate.
    const bool isInstructionFetch = (exitInfo1 & (1ULL << 4)) != 0;
    if (!isInstructionFetch)
    {
        // Data-access NPF. Two distinct causes:
        //
        // A) Truly missing PDE — GPA above or outside our pre-built identity
        //    range (MMIO regions: SMU, PCIe config, IOMMU). Add 2MB identity
        //    entry on demand so the guest doesn't loop forever.
        //
        // B) Split 2MB region with a Write=0 PTE — SvBuildNestedPageTables
        //    pre-fills all PDEs as Valid, so the PDE is always present after
        //    a SplitNptLargePage call. When a non-shadow page in that split
        //    region gets a data write NPF, the handler must restore Write=1
        //    on the collateral PTE so the guest can proceed. Shadow pages
        //    (SvFindShadowEntry != NULL) intentionally keep Write=0.
        ULONG64 pa2MB = faultGPA & ~(ULONG64)0x1FFFFF;
        ULONG pml4Idx = (ULONG)((pa2MB >> 39) & 0x1FF);
        ULONG pdptIdx = (ULONG)((pa2MB >> 30) & 0x1FF);
        ULONG pdIdx = (ULONG)((pa2MB >> 21) & 0x1FF);

        if (pml4Idx < NPT_PML4_COUNT)
        {
            PSHARED_VIRTUAL_PROCESSOR_DATA sv = VpData->HostStackLayout.SharedVpData;
            PPD_ENTRY_2MB pde = &sv->Pml4eTrees[pml4Idx].PdEntries[pdptIdx][pdIdx];

            if (!pde->Fields.Valid)
            {
                // Case A: missing PDE — add identity 2MB mapping on demand.
                ULONG64 pfn2MB = (pml4Idx * 512ULL * 512 + pdptIdx * 512 + pdIdx);
                pde->AsUInt64 = 0;
                pde->Fields.PageFrameNumber = pfn2MB;
                pde->Fields.Valid = 1;
                pde->Fields.Write = 1;
                pde->Fields.User = 1;
                pde->Fields.LargePage = 1;
                SvRequestGuestTlbFlush(VpData);
            }
            else if (!pde->Fields.LargePage)
            {
                // Case B: split 2MB region — locate the faulting 4KB PTE.
                // Resolve VA from our init-time cache (no OS API calls — safe at VMEXIT).
                ULONG64 ptPA = pde->AsUInt64 & 0x000FFFFFFFFFF000ULL;
                PPT_ENTRY_4KB pt = NULL;
                for (ULONG si = 0; si < g_SplitPtCount; si++) {
                    if (g_SplitPtPAs[si] == ptPA) {
                        pt = (PPT_ENTRY_4KB)g_SplitPtVAs[si];
                        break;
                    }
                }
                if (pt)
                {
                    ULONG pteIdx = (ULONG)((faultGPA >> 12) & 0x1FF);
                    if (!pt[pteIdx].Fields.Write)
                    {
                        // Only restore Write=1 for non-shadow collateral PTEs.
                        // Shadow PTEs intentionally have Write=0 — leave them.
                        PSHADOW_PAGE_ENTRY e = SvFindShadowEntry(faultGPA & ~(ULONG64)0xFFF);
                        if (!e)
                        {
                            // Collateral non-shadow PTE with Write=0 — restore write permission.
                            pt[pteIdx].Fields.Write = 1;
                            SvRequestGuestTlbFlush(VpData);
                        }
                        else
                        {
                            // Write to a shadow-protected page. Swap to exec so the write
                            // lands on the real backing physical page, then single-step to
                            // restore decoy. Same flow as instruction-fetch NPF.
                            SHADOW_STEP_STATE* s = VpData->HostStackLayout.ShadowStepState;

                            s->ActiveEntry = e;
                            s->GuestHadTf = (VpData->GuestVmcb.StateSaveArea.Rflags & 0x100) != 0;
                            s->GuestHadBs = (VpData->GuestVmcb.StateSaveArea.Dr6 & (1ULL << 14)) != 0;
                            s->GuestDr6Snapshot = VpData->GuestVmcb.StateSaveArea.Dr6;

                            // Point PTE at exec page, Write=1 so write completes, NX=0.
                            PPT_ENTRY_4KB shadowPte = (PPT_ENTRY_4KB)(ULONG_PTR)e->NptPte;
                            shadowPte->Fields.PageFrameNumber = e->ExecPA >> PAGE_SHIFT;
                            shadowPte->Fields.NoExecute = 0;
                            shadowPte->Fields.Write = 1;
                            e->InExecState = TRUE;

                            InterlockedIncrement(&g_ShadowNpfCount);
                            SvShadowTrace(SHADOW_TRACE_KIND_NPF, faultGPA, 0, 1);

                            VpData->GuestVmcb.StateSaveArea.Rflags |= 0x100;   // arm TF
                            SvRequestGuestTlbFlush(VpData);
                            // RIP NOT advanced — guest re-executes write against exec page.
                        }
                    }
                }
            }
            // LargePage + Valid with a data NPF should not normally occur;
            // if it does, something else (reserved bit, PAT mismatch) is wrong.
        }
        else
        {
            // GPA is above the pre-built NPT range. Use a pre-allocated overflow
            // tree — no memory allocation here (safe at VMEXIT with GIF=0).
            PPML4E_TREE tree = g_NptPml4IdxToTree[pml4Idx];  // NULL until first fault
            if (!tree && g_NptOverflowCount > 0)
            {
                // Claim the next free overflow tree.
                ULONG slot = InterlockedDecrement((LONG*)&g_NptOverflowCount);
                if ((LONG)slot >= 0)
                {
                    tree = g_NptOverflowTrees[slot];
                    ULONG64 treePdptPA = g_NptOverflowPAs[slot];  // PA of PdptEntries[0]

                    // Wire into the NPT PML4 table so the CPU walks it.
                    PSHARED_VIRTUAL_PROCESSOR_DATA sv2 = VpData->HostStackLayout.SharedVpData;
                    PPML4_ENTRY_2MB pml4e = &sv2->Pml4Entries[pml4Idx];
                    pml4e->Fields.PageFrameNumber = treePdptPA >> PAGE_SHIFT;
                    pml4e->Fields.Valid = 1;
                    pml4e->Fields.Write = 1;
                    pml4e->Fields.User = 1;

                    g_NptPml4IdxToTree[pml4Idx] = tree;
                }
            }

            if (tree)
            {
                // PDPT entries are pre-wired at init. Just add the 2MB identity
                // mapping for the faulting GPA — no OS API calls needed.
                PPD_ENTRY_2MB pde2 = &tree->PdEntries[pdptIdx][pdIdx];
                if (!pde2->Fields.Valid)
                {
                    ULONG64 pfn2MB = ((ULONG64)pml4Idx * 512 * 512) + ((ULONG64)pdptIdx * 512) + pdIdx;
                    pde2->AsUInt64 = 0;
                    pde2->Fields.PageFrameNumber = pfn2MB;
                    pde2->Fields.Valid = 1;
                    pde2->Fields.Write = 1;
                    pde2->Fields.User = 1;
                    pde2->Fields.LargePage = 1;
                }
                SvRequestGuestTlbFlush(VpData);
            }
            // If no overflow slots remain, the NPF re-fires. Nothing safe to do
            // without allocation — the guest will get stuck on this GPA.
        }
        return;
    }

    PSHADOW_PAGE_ENTRY e = SvFindShadowEntry(faultGPA);
    if (!e || !e->NptPte)
        return;

    SHADOW_STEP_STATE* s = VpData->HostStackLayout.ShadowStepState;

    // Snapshot guest state before we perturb anything so SvHandleDb can restore it.
    s->ActiveEntry = e;
    s->GuestHadTf = (VpData->GuestVmcb.StateSaveArea.Rflags & 0x100) != 0;
    s->GuestHadBs = (VpData->GuestVmcb.StateSaveArea.Dr6 & (1ULL << 14)) != 0;
    s->GuestDr6Snapshot = VpData->GuestVmcb.StateSaveArea.Dr6;

    // Swap to exec page: point PTE at ExecPA, clear NX.
    PPT_ENTRY_4KB pte = (PPT_ENTRY_4KB)(ULONG_PTR)e->NptPte;
    pte->Fields.PageFrameNumber = e->ExecPA >> PAGE_SHIFT;
    pte->Fields.NoExecute = 0;
    pte->Fields.Write = 0;
    e->InExecState = TRUE;

    InterlockedIncrement(&g_ShadowNpfCount);
    SvShadowTrace(SHADOW_TRACE_KIND_NPF, faultGPA, 0, 0);

    // Arm single-step
    VpData->GuestVmcb.StateSaveArea.Rflags |= 0x100;   // RFLAGS.TF

    // Flush guest TLB for this ASID so the updated PTE takes effect immediately.
    SvRequestGuestTlbFlush(VpData);

    // Do NOT advance RIP — the guest must re-execute the faulting instruction
    // now that the PTE points at the exec page.
#endif
}

// SvHandleVmexit preserves an interrupted guest event by copying ExitIntInfo
// into EventInj before dispatching the exit-specific handler.  On some AMD
// systems an intercepted #DB is reported there as well.  A shadow-step #DB is
// consumed by SvHandleDb, so leaving that pre-populated event intact delivers a
// second, guest-visible #DB at the resume RIP.
static FORCEINLINE VOID SvDiscardQueuedDb(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData)
{
    EVENTINJ queued;
    queued.AsUInt64 = VpData->GuestVmcb.ControlArea.EventInj;

    if (queued.Fields.Valid &&
        queued.Fields.Type == 3 &&
        queued.Fields.Vector == 1)
    {
        VpData->GuestVmcb.ControlArea.EventInj = 0;
    }
}

static FORCEINLINE BOOLEAN SvRipIsInsideShadowStub(
    _In_ const SHADOW_PAGE_ENTRY* Entry,
    _In_ UINT64 Rip)
{
    for (ULONG i = 0; i < Entry->StubCount; i++)
    {
        const UINT64 start = Entry->Stubs[i].StartVa;
        const UINT64 end = start + Entry->Stubs[i].Length;
        if (end >= start && Rip >= start && Rip < end)
            return TRUE;
    }
    return FALSE;
}

// #DB handler: single-step fired after one instruction executed on the exec page.
// Swap this CPU's active shadow entry back to decoy, restore guest TF/DR6 state,
// and forward any coincident hardware-BP or pre-existing guest TF to the guest IDT.
static VOID SvHandleDb(
    _Inout_ PVIRTUAL_PROCESSOR_DATA VpData)
{
    SHADOW_STEP_STATE* s = VpData->HostStackLayout.ShadowStepState;

    constexpr UINT64 kTrapFlag = 1ULL << 8;
    constexpr UINT64 kDr6Bd = 1ULL << 13;
    constexpr UINT64 kDr6Bs = 1ULL << 14;
    constexpr UINT64 kDr6Bt = 1ULL << 15;
    constexpr UINT64 kDr6BreakpointMask = 0xFULL;
    constexpr UINT64 kDr6GuestCauseMask =
        kDr6BreakpointMask | kDr6Bd | kDr6Bt;

    const UINT64 dr6 = VpData->GuestVmcb.StateSaveArea.Dr6;
    const bool   bs = (dr6 & kDr6Bs) != 0;  // single-step trap bit
    // Only treat hardware-BP bits as a coincident event when they are NEWLY set by
    // this #DB — i.e., not already present in DR6 when the NPF armed our step.
    // DR6 is sticky (processor ORs bits in, never auto-clears); without the mask
    // stale bits from any prior event make hw=true every time, injecting a spurious
    // STATUS_SINGLE_STEP #DB into non-debug kernel code (e.g. CLFS) → 0x3B bugcheck.
    const UINT64 directGuestCauses = dr6 & kDr6GuestCauseMask;
    const bool guestTfSet =
        (VpData->GuestVmcb.StateSaveArea.Rflags & kTrapFlag) != 0;
    const UINT64 newGuestCauses =
        directGuestCauses & ~s->GuestDr6Snapshot;
    const bool hw = (newGuestCauses & kDr6BreakpointMask) != 0;
    const bool guestDebugCause = newGuestCauses != 0;

    // Ours only if this CPU has an active entry AND a single-step trap fired.
    const bool ours = (s->ActiveEntry != nullptr) && bs;

    // Capture ActiveEntry before the abort path below nulls it — needed to
    // distinguish "our abort" from "no pending step" at the inject decision.
    const PSHADOW_PAGE_ENTRY savedActiveEntry = s->ActiveEntry;

    if (!ours)
    {
        // If WE armed TF for a shadow step on this CPU (s->ActiveEntry != nullptr)
        // but bs=false, a guest-owned debug event fired before the instruction
        // completed. Abort the pending step, restore the decoy mapping, and remove
        // only our TF contribution before returning the event to the guest.
        if (s->ActiveEntry != nullptr)
        {
            PSHADOW_PAGE_ENTRY abandonEntry = s->ActiveEntry;
            if (abandonEntry->NptPte)
            {
                PPT_ENTRY_4KB shadowPte = (PPT_ENTRY_4KB)(ULONG_PTR)abandonEntry->NptPte;
                shadowPte->Fields.PageFrameNumber = abandonEntry->DecoyPA >> PAGE_SHIFT;
                shadowPte->Fields.NoExecute = 1;
                shadowPte->Fields.Write = 0;
                abandonEntry->InExecState = FALSE;
                SvRequestGuestTlbFlush(VpData);
            }
            // Restore the TF value that belonged to the guest.  Clearing it
            // unconditionally breaks a guest debugger that was already stepping.
            if (s->GuestHadTf)
                VpData->GuestVmcb.StateSaveArea.Rflags |= kTrapFlag;
            else
                VpData->GuestVmcb.StateSaveArea.Rflags &= ~kTrapFlag;
            s->ActiveEntry = nullptr;
        }
        // Two distinct sub-cases:
        //
        // A) s->ActiveEntry != nullptr (abort path above already cleaned up):
        //    We armed TF, but a non-BS guest debug cause fired before the
        //    instruction completed. Re-inject only when DR6 contains a newly
        //    observed guest cause; this preserves debugger events without turning
        //    stale sticky DR6 bits into a spurious STATUS_SINGLE_STEP.
        //
        // B) s->ActiveEntry == nullptr (no pending shadow step on this CPU):
        //    We never armed TF.  The #DB is entirely organic — generated by
        //    the guest itself (kernel debugger single-step, DR0-DR3 watchpoint,
        //    or any other guest use of RFLAGS.TF / debug registers).  We MUST
        //    re-inject it unconditionally to preserve architectural guest behavior.
        const bool wasOurAbort = (savedActiveEntry != nullptr);
        // A second #DB can be generated from EventInj after our first handler
        // already cleared TF.  It has DR6.BS set, but no current TF and no
        // independent B0-B3/BD/BT cause.  Forwarding that replay raises
        // STATUS_SINGLE_STEP in arbitrary kernel code (the IOCTL dispatch entry
        // in the observed crash).  Preserve real TF, hardware-breakpoint,
        // task-switch, debug-register-access, and cause-less ICEBP events.
        const bool staleBsReplay =
            !wasOurAbort && bs && !guestTfSet && directGuestCauses == 0;

        // When aborting our step, forward only a newly-observed guest cause.
        // With no pending step, forward everything except the replay signature.
        const bool shouldInject =
            wasOurAbort ? guestDebugCause : !staleBsReplay;
        if (shouldInject)
        {
            InterlockedIncrement(&g_ShadowDbFwdCount);
            SvShadowTrace(SHADOW_TRACE_KIND_FWD, 0, dr6, 0);
            EVENTINJ ev;
            ev.AsUInt64 = 0;
            ev.Fields.Vector = 1;
            ev.Fields.Type = 3;
            ev.Fields.Valid = 1;
            VpData->GuestVmcb.ControlArea.EventInj = ev.AsUInt64;
        }
        else
        {
            // Cancel both possible copies of the consumed replay and remove its
            // sticky BS indication before returning to the guest.
            SvDiscardQueuedDb(VpData);
            VpData->GuestVmcb.StateSaveArea.Dr6 &= ~kDr6Bs;
        }
        return;
    }

    PSHADOW_PAGE_ENTRY e = s->ActiveEntry;

    // The generated cave forwarder contains two instructions:
    //   mov rax, target   (10 bytes)
    //   jmp rax            (2 bytes)
    // The first #DB lands at StubStart+10.  Keep the exec page and TF active
    // for that second instruction; restoring the decoy here exposes the cave's
    // original 0xCC padding instead of the jump and walks the debugger through
    // one breakpoint byte after another.  Complete the swap only after RIP has
    // left every registered stub range on this page.
    if (!guestDebugCause &&
        !s->GuestHadTf &&
        SvRipIsInsideShadowStub(e, VpData->GuestVmcb.StateSaveArea.Rip))
    {
        if (!s->GuestHadBs)
            VpData->GuestVmcb.StateSaveArea.Dr6 &= ~kDr6Bs;
        SvDiscardQueuedDb(VpData);
        SvShadowTrace(SHADOW_TRACE_KIND_CONT, e->GuestPA, dr6, 0);
        return;
    }

    // Our completed single-step sequence: swap this active entry back to decoy.
    PPT_ENTRY_4KB pte = (PPT_ENTRY_4KB)(ULONG_PTR)e->NptPte;
    pte->Fields.PageFrameNumber = e->DecoyPA >> PAGE_SHIFT;
    pte->Fields.NoExecute = 1;
    pte->Fields.Write = 0;
    e->InExecState = FALSE;
    SvRequestGuestTlbFlush(VpData);

    s->ActiveEntry = nullptr;

    InterlockedIncrement(&g_ShadowDbCount);
    SvShadowTrace(SHADOW_TRACE_KIND_DB, e->GuestPA, dr6,
        (UINT8)((hw ? 1 : 0) | (s->GuestHadTf ? 2 : 0)));

    // Undo only what we contributed
    if (!s->GuestHadTf)
        VpData->GuestVmcb.StateSaveArea.Rflags &= ~kTrapFlag;
    if (!s->GuestHadBs)
        VpData->GuestVmcb.StateSaveArea.Dr6 &= ~kDr6Bs;

    // The generic ExitIntInfo preservation runs before this handler.  If it
    // queued the intercepted shadow-step #DB, consume that copy as well.  A
    // genuine coincident guest event is re-created explicitly below.
    SvDiscardQueuedDb(VpData);

    // If a hardware BP coincided with our step, or the guest had its own TF
    // active, forward a #DB so the guest's debugger still sees its event.
    // DR6 already reflects the residual cause(s) after our cleanup above.
    if (hw || s->GuestHadTf)
    {
        InterlockedIncrement(&g_ShadowDbFwdCount);
        SvShadowTrace(SHADOW_TRACE_KIND_FWD, e->GuestPA, dr6,
            (UINT8)((hw ? 1 : 0) | (s->GuestHadTf ? 2 : 0)));
        EVENTINJ ev;
        ev.AsUInt64 = 0;
        ev.Fields.Vector = 1;
        ev.Fields.Type = 3;
        ev.Fields.Valid = 1;
        VpData->GuestVmcb.ControlArea.EventInj = ev.AsUInt64;
    }
    // RIP already points at next instruction — do not advance.
}

// ============================================================

/*!
    @brief          Build the MSR permissions map (MSRPM).

    @details        This function sets up MSRPM to intercept to IA32_MSR_EFER,
                    as suggested in "Extended Feature Enable Register (EFER)"
                    ----
                    Secure Virtual Machine Enable (SVME) Bit
                    Bit 12, read/write. Enables the SVM extensions. (...) The
                    effect of turning off EFER.SVME while a guest is running is
                    undefined; therefore, the VMM should always prevent guests
                    from writing EFER.
                    ----

                    Each MSR is controlled by two bits in the MSRPM. The LSB of
                    the two bits controls read access to the MSR and the MSB
                    controls write access. A value of 1 indicates that the
                    operation is intercepted. This function locates an offset for
                    IA32_MSR_EFER and sets the MSB bit. For details of logic, see
                    "MSR Intercepts".

    @param[in,out]  MsrPermissionsMap - The MSRPM to set up.
 */
_IRQL_requires_same_
static
VOID
SvBuildMsrPermissionsMap(
    _Inout_ PVOID MsrPermissionsMap
)
{
    constexpr UINT32 BITS_PER_MSR = 2;
    constexpr UINT32 SECOND_MSR_RANGE_BASE = 0xc0000000;
    constexpr UINT32 SECOND_MSRPM_OFFSET = 0x800 * CHAR_BIT;
    RTL_BITMAP bitmapHeader;
    ULONG offsetFrom2ndBase, offset;

    //
    // Setup and clear all bits, indicating no MSR access should be intercepted.
    //
    RtlInitializeBitMap(&bitmapHeader,
        static_cast<PULONG>(MsrPermissionsMap),
        SVM_MSR_PERMISSIONS_MAP_SIZE * CHAR_BIT
    );
    RtlClearAllBits(&bitmapHeader);

    //
    // Compute an offset from the second MSR permissions map offset (0x800) for
    // IA32_MSR_EFER in bits. Then, add an offset until the second MSR
    // permissions map.
    //
    offsetFrom2ndBase = (IA32_MSR_EFER - SECOND_MSR_RANGE_BASE) * BITS_PER_MSR;
    offset = SECOND_MSRPM_OFFSET + offsetFrom2ndBase;

    //
    // Set the MSB bit indicating write accesses to the MSR should be intercepted.
    //
    RtlSetBits(&bitmapHeader, offset, 1);
    RtlSetBits(&bitmapHeader, offset + 1, 1);
}

/*!
    @brief      Build pass-through style page tables used in nested paging.

    @details    This function build page tables used in Nested Page Tables. The
                page tables are used to translate from a guest physical address
                to a system physical address and pointed by the NCr3 field of
                VMCB, like the traditional page tables are pointed by CR3.

                The nested page tables built in this function are set to
                translate a guest physical address to the same system physical
                address. For example, guest physical address 0x1000 is
                translated into system physical address 0x1000.

                In order to save memory to build nested page tables, 2MB large
                pages are used (as opposed to the standard pages that describe
                translation only for 4K granularity. Also, only up to 1 TB of
                translation is built. 1GB huge pages are not used due to VMware
                not supporting this feature.

    @param[out] SharedVpData - Out buffer to build nested page tables.
 */
_IRQL_requires_same_
static
VOID
SvBuildNestedPageTables(
    _Out_ PSHARED_VIRTUAL_PROCESSOR_DATA SharedVpData
)
{
    ULONG64 pdptBasePa, pdBasePa, translationPa;

    //
    // Build NPT_PML4_COUNT PML4 entries. Each entry covers 512GB, so
    // NPT_PML4_COUNT entries cover NPT_PML4_COUNT * 512GB of physical space.
    // AMD MMIO regions (SMU, PCIe config, IOMMU) can sit above 1TB on
    // large-RAM systems, so we need more than 2 entries to avoid infinite
    // NPF loops on data accesses to unmapped MMIO GPAs.
    //
    for (ULONG64 pml4Index = 0; pml4Index < NPT_PML4_COUNT; pml4Index++) {
        PPML4_ENTRY_2MB pml4e = &SharedVpData->Pml4Entries[pml4Index];
        PPML4E_TREE pml4eTree = &SharedVpData->Pml4eTrees[pml4Index];

        //
        // Set the US (User) bit of all nested page table entries to be translated
        // without #VMEXIT, as all guest accesses are treated as user accesses at
        // the nested level. Also, the RW (Write) bit of nested page table entries
        // that corresponds to guest page tables must be 1 since all guest page
        // table accesses are threated as write access. See "Nested versus Guest
        // Page Faults, Fault Ordering" for more details.
        //
        // Those settings do not lower security since permission checks are done
        // twice independently: based on guest page tables, and nested page tables.
        // See "Nested versus Guest Page Faults, Fault Ordering" for more details.
        //
        pdptBasePa = MmGetPhysicalAddress(&pml4eTree->PdptEntries).QuadPart;
        pml4e->Fields.PageFrameNumber = pdptBasePa >> PAGE_SHIFT;
        pml4e->Fields.Valid = 1;
        pml4e->Fields.Write = 1;
        pml4e->Fields.User = 1;

        //
        // One PML4 entry controls 512 page directory pointer entires.
        //
        for (ULONG64 pdptIndex = 0; pdptIndex < 512; pdptIndex++)
        {
            //
            // PFN points to a base physical address of the page directory table.
            //
            pdBasePa = MmGetPhysicalAddress(&pml4eTree->PdEntries[pdptIndex][0]).QuadPart;
            pml4eTree->PdptEntries[pdptIndex].Fields.PageFrameNumber = pdBasePa >> PAGE_SHIFT;
            pml4eTree->PdptEntries[pdptIndex].Fields.Valid = 1;
            pml4eTree->PdptEntries[pdptIndex].Fields.Write = 1;
            pml4eTree->PdptEntries[pdptIndex].Fields.User = 1;

            //
            // One page directory entry controls 512 page directory entries.
            //
            // We do not explicitly configure PAT in the NPT entry. The consequences
            // of this are: 1) pages whose PAT (Page Attribute Table) type is the
            // Write-Combining (WC) memory type could be treated as the
            // Write-Combining Plus (WC+) while it should be WC when the MTRR type is
            // either Write Protect (WP), Writethrough (WT) or Writeback (WB), and
            // 2) pages whose PAT type is Uncacheable Minus (UC-) could be treated
            // as Cache Disabled (CD) while it should be WC, when MTRR type is WC.
            //
            // While those are not desirable, this is acceptable given that 1) only
            // introduces additional cache snooping and associated performance
            // penalty, which would not be significant since WC+ still lets
            // processors combine multiple writes into one and avoid large
            // performance penalty due to frequent writes to memory without caching.
            // 2) might be worse but I have not seen MTRR ranges configured as WC
            // on testing, hence the unintentional UC- will just results in the same
            // effective memory type as what would be with UC.
            //
            // See "Memory Types" (7.4), for details of memory types,
            // "PAT-Register PA-Field Indexing", "Combining Guest and Host PAT Types",
            // and "Combining PAT and MTRR Types" for how the effective memory type
            // is determined based on Guest PAT type, Host PAT type, and the MTRR
            // type.
            //
            // The correct approach may be to look up the guest PTE and copy the
            // caching related bits (PAT, PCD, and PWT) when constructing NTP
            // entries for non RAM regions, so the combined PAT will always be the
            // same as the guest PAT type. This may be done when any issue manifests
            // with the current implementation.
            //
            for (ULONG64 pdIndex = 0; pdIndex < 512; pdIndex++)
            {
                //
                // PFN points to a base physical address of system physical address
                // to be translated from a guest physical address. Set the PS
                // (LargePage) bit to indicate that this is a large page and no
                // subtable exists.
                //
                translationPa = (pml4Index * 512 * 512) + (pdptIndex * 512) + pdIndex;
                pml4eTree->PdEntries[pdptIndex][pdIndex].Fields.PageFrameNumber = translationPa;
                pml4eTree->PdEntries[pdptIndex][pdIndex].Fields.Valid = 1;
                pml4eTree->PdEntries[pdptIndex][pdIndex].Fields.Write = 1;
                pml4eTree->PdEntries[pdptIndex][pdIndex].Fields.User = 1;
                pml4eTree->PdEntries[pdptIndex][pdIndex].Fields.LargePage = 1;
            }
        }
    }

    // Wire built-in trees into the pml4Idx lookup table.
    RtlZeroMemory(g_NptPml4IdxToTree, sizeof(g_NptPml4IdxToTree));
    for (ULONG i = 0; i < NPT_PML4_COUNT; i++)
        g_NptPml4IdxToTree[i] = &SharedVpData->Pml4eTrees[i];

    // Pre-allocate overflow trees for GPAs that fall outside the built-in range.
    // Allocation happens here (PASSIVE_LEVEL) so the VMEXIT handler never needs
    // to allocate memory with interrupts disabled.
    g_NptOverflowCount = 0;
    for (ULONG s = 0; s < NPT_OVERFLOW_SLOTS; s++)
    {
        PPML4E_TREE tree = (PPML4E_TREE)SvAllocatePageAlingedPhysicalMemory(sizeof(PML4E_TREE));
        if (!tree)
            break;

        // Pre-wire all 512 PDPT entries so the CPU can walk PD tables without
        // the NPF handler calling any OS API. PD arrays start as all-zero (invalid
        // PDEs); the NPF handler fills 2MB identity entries on demand.
        for (ULONG pi = 0; pi < 512; pi++)
        {
            PHYSICAL_ADDRESS pdPhys = MmGetPhysicalAddress(&tree->PdEntries[pi][0]);
            tree->PdptEntries[pi].Fields.PageFrameNumber = pdPhys.QuadPart >> PAGE_SHIFT;
            tree->PdptEntries[pi].Fields.Valid = 1;
            tree->PdptEntries[pi].Fields.Write = 1;
            tree->PdptEntries[pi].Fields.User = 1;
        }

        // Store the PA of PdptEntries[0] so the NPF handler can wire Pml4Entries
        // without calling MmGetPhysicalAddress at VMEXIT time.
        PHYSICAL_ADDRESS pdptPhys = MmGetPhysicalAddress(&tree->PdptEntries[0]);

        g_NptOverflowTrees[s] = tree;
        g_NptOverflowPAs[s] = (ULONG64)pdptPhys.QuadPart;
        g_NptOverflowCount++;
    }
}

/*!
    @brief      Test whether the current processor support the SVM feature.

    @details    This function tests whether the current processor has enough
                features to run SimpleSvm, especially about SVM features.

    @result     TRUE if the processor supports the SVM feature; otherwise, FALSE.
 */
_IRQL_requires_same_
_Check_return_
static
BOOLEAN
SvIsSvmSupported(
    VOID
)
{
    BOOLEAN svmSupported;
    int registers[4];   // EAX, EBX, ECX, and EDX
    ULONG64 vmcr;

    svmSupported = FALSE;

    //
    // Test if the current processor is AMD one. An AMD processor should return
    // "AuthenticAMD" from CPUID function 0. See "Function 0h-Maximum Standard
    // Function Number and Vendor String".
    //
    __cpuid(registers, CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING);
    if ((registers[1] != 'htuA') ||
        (registers[3] != 'itne') ||
        (registers[2] != 'DMAc'))
    {
        SvDebugPrint("[SvmSupport] FAIL: not AMD vendor (EBX=%08X EDX=%08X ECX=%08X)\n",
            registers[1], registers[3], registers[2]);
        goto Exit;
    }

    //
    // Test if the SVM feature is supported by the current processor. See
    // "Enabling SVM" and "CPUID Fn8000_0001_ECX Feature Identifiers".
    //
    __cpuid(registers, CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS_EX);
    if ((registers[2] & CPUID_FN8000_0001_ECX_SVM) == 0)
    {
        SvDebugPrint("[SvmSupport] FAIL: SVM feature bit not set (ECX=%08X)\n", registers[2]);
        goto Exit;
    }

    //
    // Test if the Nested Page Tables feature is supported by the current
    // processor. See "Enabling Nested Paging" and "CPUID Fn8000_000A_EDX SVM
    // Feature Identification".
    //
    __cpuid(registers, CPUID_SVM_FEATURES);
    if ((registers[3] & CPUID_FN8000_000A_EDX_NP) == 0)
    {
        SvDebugPrint("[SvmSupport] FAIL: Nested Paging bit not set (EDX=%08X)\n", registers[3]);
        goto Exit;
    }

    g_SvmFlushByAsidSupported =
        (registers[3] & CPUID_FN8000_000A_EDX_FLUSH_BY_ASID) != 0;

    // Report NRIP_SAVE (CPUID Fn8000_000A_EDX bit 3). Diagnostic only -
    // we do not fail if it is missing because SvAdvanceGuestRip falls
    // back to known instruction lengths. VMware's nested-SVM monitor
    // often clears this bit, or sets it but does not populate NRip
    // correctly, which is exactly the case where the explicit-length
    // fallback matters.
    SvDebugPrint("[SvmSupport] SVM features EDX=%08X (NRIPS=%lu FlushByAsid=%lu DecodeAssists=%lu)\n",
        registers[3],
        (ULONG)((registers[3] >> 3) & 1u),    // NRIPS = bit 3
        (ULONG)g_SvmFlushByAsidSupported,      // FlushByAsid = bit 6
        (ULONG)((registers[3] >> 7) & 1u));   // DecodeAssists = bit 7

    //
    // Test if the SVM feature can be enabled. When VM_CR.SVMDIS is set,
    // EFER.SVME cannot be 1; therefore, SVM cannot be enabled. When
    // VM_CR.SVMDIS is clear, EFER.SVME can be written normally and SVM can be
    // enabled. See "Enabling SVM".
    //
    vmcr = __readmsr(SVM_MSR_VM_CR);
    if ((vmcr & SVM_VM_CR_SVMDIS) != 0)
    {
        SvDebugPrint("[SvmSupport] FAIL: VM_CR.SVMDIS is set (VM_CR=%016llX)\n", vmcr);
        goto Exit;
    }

    SvDebugPrint("[SvmSupport] OK: AMD SVM + NP supported, VM_CR=%016llX\n", vmcr);
    svmSupported = TRUE;

Exit:
    return svmSupported;
}
static VOID SvCalibrateCpuidCost(VOID)
{
    int regs[4];
    UINT64 best = MAXUINT64;

    for (int i = 0; i < 200; i++)
    {
        _mm_lfence();
        UINT64 a = __rdtsc();
        _mm_lfence();
        __cpuidex(regs, 0, 0);
        _mm_lfence();
        UINT64 b = __rdtsc();
        _mm_lfence();

        UINT64 d = b - a;
        if (d < best) best = d;
    }
    g_BareMetalCpuidCost = best;
    DbgPrint("[SimpleSvm] Bare-metal CPUID cost = %llu cycles\n", best);
}

/*!
    @brief      Initializes the CPUID cache globals and the valid XCR0 mask.

    @details    Captures what bare-metal returns for an out-of-range standard
                leaf (used to spoof over hypervisor-range results), records the
                maximum standard and extended leaf indices, and reads the CPUID
                XCR0 valid mask from leaf 0Dh so XSETBV emulation can validate
                guest-supplied values.
 */
static VOID SvInitCpuidCache(VOID)
{
    int regs[4];

    // ---- Standard leaves (0x00000000 – MaxStd) ----
    __cpuidex(regs, 0, 0);
    g_MaxStdCpuidLeaf = min(static_cast<UINT32>(regs[0]), 31u);
    for (UINT32 i = 0; i <= g_MaxStdCpuidLeaf; i++)
    {
        __cpuidex(regs, static_cast<int>(i), 0);
        if (i == 1)
        {
            // Capture raw ECX[31] (hypervisor-present) BEFORE clearing it for
            // the cache.  This flag drives MSR forwarding: both Hyper-V and
            // VMware respond to the HV synthetic MSR range (0x40000000+), so
            // we need to forward those accesses to the underlying hypervisor
            // whenever ANY hypervisor is present — not just "Microsoft Hv".
            // Using the vendor-string check (as we previously tried) only
            // detects Hyper-V, leaving VMware MSR accesses unforwarded →
            // #GP injected → Windows enlightened paths crash → SwapContext+0x645.
            g_RunningUnderHyperV = ((regs[2] >> 31) & 1) ? TRUE : FALSE;

            // Clear hypervisor-present (ECX[31]) and SMX (ECX[6]) in the
            // cached snapshot so the guest never sees them.
            regs[2] &= ~((1 << 31) | (1 << 6));
        }
        g_StdCpuidCache[i][0] = regs[0];
        g_StdCpuidCache[i][1] = regs[1];
        g_StdCpuidCache[i][2] = regs[2];
        g_StdCpuidCache[i][3] = regs[3];
    }

    // ---- Extended leaves (0x80000000 – MaxExt) ----
    __cpuidex(regs, static_cast<int>(0x80000000u), 0);
    g_MaxExtCpuidLeaf = static_cast<UINT32>(regs[0]);
    UINT32 extCount = min(g_MaxExtCpuidLeaf - 0x80000000u, 31u);
    g_ExtCpuidCache[0][0] = regs[0];
    g_ExtCpuidCache[0][1] = regs[1];
    g_ExtCpuidCache[0][2] = regs[2];
    g_ExtCpuidCache[0][3] = regs[3];
    for (UINT32 i = 1; i <= extCount; i++)
    {
        __cpuidex(regs, static_cast<int>(0x80000000u + i), 0);
        g_ExtCpuidCache[i][0] = regs[0];
        g_ExtCpuidCache[i][1] = regs[1];
        g_ExtCpuidCache[i][2] = regs[2];
        g_ExtCpuidCache[i][3] = regs[3];
    }

    // ---- Hypervisor-range leaves (0x40000000 – 0x40000010) ----
    // Captured before VMRUN: returns Hyper-V identity if nested, zeros if
    // bare metal. Either way the guest sees a consistent environment and
    // VMware/NDIS drivers take the code path they were designed for.
    for (int i = 0; i <= 0x10; i++)
    {
        __cpuidex(regs, static_cast<int>(0x40000000u) + i, 0);
        g_HvCpuidCache[i][0] = regs[0];
        g_HvCpuidCache[i][1] = regs[1];
        g_HvCpuidCache[i][2] = regs[2];
        g_HvCpuidCache[i][3] = regs[3];
    }

    // ---- Invalid / out-of-range sentinel ----
    __cpuidex(regs, static_cast<int>(g_MaxStdCpuidLeaf + 1), 0);
    g_InvalidCpuidLeaf[0] = regs[0];
    g_InvalidCpuidLeaf[1] = regs[1];
    g_InvalidCpuidLeaf[2] = regs[2];
    g_InvalidCpuidLeaf[3] = regs[3];

    // ---- XCR0 valid mask (XSETBV validation, not a CPUID response) ----
    __cpuidex(regs, 0x0D, 0);
    g_ValidXcr0Mask = (static_cast<UINT64>(static_cast<UINT32>(regs[3])) << 32) |
        static_cast<UINT32>(regs[0]);
    g_ValidXcr0Mask |= 1ULL;

    // g_RunningUnderHyperV is captured inside the leaf-1 loop above,
    // from the raw ECX[31] bit before it was cleared for the cache.

    // ---- CR0/CR4 required bits ----
    g_HostRequiredCr0 = __readcr0() &
        ((1ULL << 0) | (1ULL << 5) | (1ULL << 16) | (1ULL << 31));
    g_HostRequiredCr4 = __readcr4();

    DbgPrint("[SimpleSvm] CPUID cache: maxStd=%08X maxExt=%08X validXcr0=%016llX runningUnderHV=%d\n",
        g_MaxStdCpuidLeaf, g_MaxExtCpuidLeaf, g_ValidXcr0Mask, (int)g_RunningUnderHyperV);
}

/*!
    @brief      Virtualizes all processors on the system.

    @details    This function attempts to virtualize all processors on the
                system, and returns STATUS_SUCCESS if all processors are
                successfully virtualized. If any processor is not virtualized,
                this function de-virtualizes all processors and returns an error
                code.

    @result     STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
_IRQL_requires_max_(APC_LEVEL)
_IRQL_requires_min_(PASSIVE_LEVEL)
_IRQL_requires_same_
_Check_return_
static
NTSTATUS
SvVirtualizeAllProcessors(
    VOID
)
{
    NTSTATUS status;
    PSHARED_VIRTUAL_PROCESSOR_DATA sharedVpData;
    ULONG numOfProcessorsCompleted;

    sharedVpData = nullptr;
    numOfProcessorsCompleted = 0;

    //
    // Test whether the current processor supports all required SVM features. If
    // not, exit as error.
    //
    SvDebugPrint("[VirtAll] CPU count=%lu, checking SVM support...\n",
        KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS));

    if (SvIsSvmSupported() == FALSE)
    {
        SvDebugPrint("SVM is not fully supported on this processor.\n");
        status = STATUS_HV_FEATURE_UNAVAILABLE;
        goto Exit;
    }

    //
    // Allocate a data structure shared across all processors. This data is
    // page tables used for Nested Page Tables.
    //
#pragma prefast(suppress : __WARNING_MEMORY_LEAK, "Ownership is taken on success.")
    sharedVpData = static_cast<PSHARED_VIRTUAL_PROCESSOR_DATA>(
        SvAllocatePageAlingedPhysicalMemory(sizeof(SHARED_VIRTUAL_PROCESSOR_DATA)));
    if (sharedVpData == nullptr)
    {
        SvDebugPrint("Insufficient memory.\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    SvDebugPrint("[VirtAll] SharedVpData=%p (size=0x%zX)\n",
        sharedVpData, sizeof(SHARED_VIRTUAL_PROCESSOR_DATA));

    //
    // Allocate MSR permissions map (MSRPM) onto contiguous physical memory.
    //
    sharedVpData->MsrPermissionsMap = SvAllocateContiguousMemory(
        SVM_MSR_PERMISSIONS_MAP_SIZE);
    if (sharedVpData->MsrPermissionsMap == nullptr)
    {
        SvDebugPrint("Insufficient memory.\n");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }
    SvDebugPrint("[VirtAll] MsrPermissionsMap=%p\n", sharedVpData->MsrPermissionsMap);

    //
    // Build nested page table and MSRPM.
    //
    SvDebugPrint("[VirtAll] Building NPT (NCr3 base=%p)...\n",
        &sharedVpData->Pml4Entries);
    SvBuildNestedPageTables(sharedVpData);
    SvDebugPrint("[VirtAll] NPT built, NCr3 PA=%016llX\n",
        MmGetPhysicalAddress(&sharedVpData->Pml4Entries).QuadPart);
    SvBuildMsrPermissionsMap(sharedVpData->MsrPermissionsMap);
    SvDebugPrint("[VirtAll] MSRPM built\n");

#if !SHADOW_PAGING_DISABLED
    //
    // Wire any registered NPT shadow pages into the freshly-built nested page
    // tables.  Shadow entries were populated by CreateRwxHandlers which was
    // called from SvDriverInitialize earlier in DriverEntry.
    //
    SvRegisterAllShadowPages(sharedVpData);
    SvDebugPrint("[SimpleSvm] NPT shadow-page wiring complete (%lu pages).\n", g_ShadowPageCount);
#else
    SvDebugPrint("[SimpleSvm] SHADOW_PAGING_DISABLED – NPT shadow-page wiring skipped.\n");
#endif

    //
    // Execute SvVirtualizeProcessor on and virtualize each processor one-by-one.
    // How many processors were successfully virtualized is stored in the third
    // parameter.
    //
    // STATUS_SUCCESS is returned if all processor are successfully virtualized.
    // When any error occurs while virtualizing processors, this function does
    // not attempt to virtualize the rest of processor. Therefore, only part of
    // processors on the system may have been virtualized on error. In this case,
    // it is a caller's responsibility to clean-up (de-virtualize) such
    // processors.
    //
    SvDebugPrint("[VirtAll] Starting per-CPU virtualization loop...\n");
    status = SvExecuteOnEachProcessor(SvVirtualizeProcessor,
        sharedVpData,
        &numOfProcessorsCompleted);
    SvDebugPrint("[VirtAll] Per-CPU loop done: status=0x%08X completed=%lu\n",
        status, numOfProcessorsCompleted);

Exit:
    if (!NT_SUCCESS(status))
    {
        //
        // On failure, after successful allocation of shared data.
        //
        if (numOfProcessorsCompleted != 0)
        {
            //
            // If one or more processors have already been virtualized,
            // de-virtualize any of those processors, and free shared data.
            //
            NT_ASSERT(sharedVpData != nullptr);
            SvDevirtualizeAllProcessors();
        }
        else
        {
            //
            // If none of processors has not been virtualized, simply free
            // shared data.
            //
            if (sharedVpData != nullptr)
            {
                if (sharedVpData->MsrPermissionsMap != nullptr)
                {
                    SvFreeContiguousMemory(sharedVpData->MsrPermissionsMap);
                }
                SvFreePageAlingedPhysicalMemory(sharedVpData);
            }
        }
    }
    return status;
}

/*!
    @brief      Handles IRP_MJ_CREATE and IRP_MJ_CLOSE for the SimpleSvm device.
 */
static
NTSTATUS
SvDispatchCreateClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*!
    @brief      Dispatches DeviceIoControl requests to the appropriate memory
                mapping operation based on the IOCTL code.

    @details    Supported IOCTLs:
                  IOCTL_READ_MEMORY       - read_invoke  (read process memory via physical)
                  IOCTL_WRITE_MEMORY      - write_invoke (write process memory via MmCopyVirtualMemory)
                  IOCTL_TRANSLATE_ADDRESS - translate_invoke (VA -> PA via page-walk)
                  IOCTL_MM_COPY_KERNEL    - read_kernel_invoke (kernel read, physical or virtual)
                  IOCTL_GET_DTB           - dtb_invoke (get directory table base for a PID)

                All IOCTLs use METHOD_BUFFERED. The caller passes the appropriate
                invoke structure as the input buffer; for operations that return
                data the same buffer is also the output buffer (in-place update).
 */
static
NTSTATUS
SvDispatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG inputLen = stack->Parameters.DeviceIoControl.InputBufferLength;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR information = 0;

    invoke_data req = { buffer };

    switch (code)
    {
    case IOCTL_READ_MEMORY:
        if (inputLen >= sizeof(read_invoke))
        {
            status = request::read_memory(&req);
            if (NT_SUCCESS(status))
            {
                information = sizeof(read_invoke);
            }
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_WRITE_MEMORY:
        if (inputLen >= sizeof(write_invoke))
        {
            status = request::write_memory(&req);
            if (NT_SUCCESS(status))
            {
                information = sizeof(write_invoke);
            }
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_TRANSLATE_ADDRESS:
        if (inputLen >= sizeof(translate_invoke))
        {
            status = request::translate_address(&req);
            if (NT_SUCCESS(status))
            {
                information = sizeof(translate_invoke);
            }
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_MM_COPY_KERNEL:
        if (inputLen >= sizeof(read_kernel_invoke))
        {
            status = request::mm_copy_kernel(&req);
            if (NT_SUCCESS(status))
            {
                information = sizeof(read_kernel_invoke);
            }
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_GET_DTB:
        if (inputLen >= sizeof(dtb_invoke))
        {
            status = request::get_dtb(&req);
            if (NT_SUCCESS(status))
            {
                information = sizeof(dtb_invoke);
            }
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_INJECT_PML4:
        if (inputLen >= sizeof(pml4_inject_invoke))
        {
            status = request::pml4_inject(&req);
            if (NT_SUCCESS(status))
            {
                information = sizeof(pml4_inject_invoke);
            }
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_GET_MODULE_BASE:
        if (inputLen >= sizeof(get_module_base_invoke))
        {
            status = request::get_module_base(&req);
            if (NT_SUCCESS(status))
            {
                information = sizeof(get_module_base_invoke);
            }
        }
        else
        {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    case IOCTL_DUMP_SHADOW_TRACE:
        // Drain the lockless ring buffer and emit via DbgPrint at passive level.
        // Safe to call here — we are in the IOCTL dispatch routine, PASSIVE_LEVEL.
        SvDrainShadowTrace(SHADOW_TRACE_ENTRIES);
        DbgPrint("[shadow] counters: npf=%ld db=%ld fwd=%ld\n",
            g_ShadowNpfCount, g_ShadowDbCount, g_ShadowDbFwdCount);
        status = STATUS_SUCCESS;
        information = 0;
        break;

    case IOCTL_DUMP_MCA_BANKS:
        SvDumpMcaBanks();
        status = STATUS_SUCCESS;
        information = 0;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

/*!
    @brief      IoCreateDriver initialization callback.

    @details    Creates the SimpleSvm device object and its symbolic link, then
                registers IRP dispatch routines. Called by IoCreateDriver from
                DriverEntry.

    @param[in]  DriverObject  - The driver object created by IoCreateDriver.
    @param[in]  RegistryPath  - Unused.

    @result     STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
static
NTSTATUS
SvDriverInitialize(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    UNICODE_STRING deviceName, symbolicLink;
    PDEVICE_OBJECT deviceObject = nullptr;

    RtlInitUnicodeString(&deviceName, SVM_DEVICE_NAME);
    RtlInitUnicodeString(&symbolicLink, SVM_SYMBOLIC_LINK_NAME);

    status = IoCreateDevice(DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);
    if (!NT_SUCCESS(status))
    {
        SvDebugPrint("Failed to create SimpleSvm device: 0x%08X\n", status);
        return status;
    }

    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status))
    {
        SvDebugPrint("Failed to create SimpleSvm symbolic link: 0x%08X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    //
    // Register the unload routine and dispatch routines on this driver object.
    // This is the authoritative driver object when IoCreateDriver is used
    // (e.g. when the driver is manually mapped and DriverEntry's DriverObject
    // is null).
    //
    DriverObject->DriverUnload = SvDriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = SvDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SvDispatchCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SvDispatchDeviceControl;

    //
    // Attempt to hide MajorFunction[] pointers inside legitimate driver code
    // caves.  InitializeDriverState marks the hook engine active, then we scan
    // ntoskrnl for 64-byte+ padding runs (0x90/0xCC/0x00), flip those pages
    // RWX, and emit minimal 14-byte absolute-jump stubs that forward to the
    // real Sv* handlers.  If any step fails we keep the direct pointers above
    // as a safe fallback — the driver remains functional either way.
    //
    InitializeDriverState();
    {
        UNICODE_STRING icrName = RTL_CONSTANT_STRING(L"IofCompleteRequest");
        gIoCompleteRequest = (PFN_IoCompleteRequest)(ULONG_PTR)
            MmGetSystemRoutineAddress(&icrName);
    }

    {
        PVOID ntBase = NULL;
        ULONG ntSize = 0;
        if (GetNtoskrnlInfo(&ntBase, &ntSize))
        {
            SvDebugPrint("PTE hook: ntoskrnl base=%p size=0x%X\n", ntBase, ntSize);
        }

#if !SHADOW_PAGING_DISABLED
        // Walk the full PsLoadedModuleList and scan every large kernel
        // module for 64-byte+ code-cave runs.  Always runs regardless of
        // virtualisation environment — the scan itself is read-only.
        // FlipPTEToRWXSafe (PTE writes) and CreateRwxHandlers (stub emission)
        // are skipped under nested virt because modifying ntoskrnl PTEs
        // invalidates VMware's VNPT shadow entries, causing infinite nested
        // #PF loops → #DF → triple fault.
        ScanAllLoadedModules();

        {
            if (CreateRwxHandlers())
            {
                // All stubs have been written; restore every cave page to
                // R+X with Dirty=0 so MiMappedPageWriter never sees our
                // writes and doesn't try to page them back to disk.
                RestorePagesToRXAndClearDirty();

                if (g_RwxDeviceCreate)
                    DriverObject->MajorFunction[IRP_MJ_CREATE] =
                    reinterpret_cast<PDRIVER_DISPATCH>(g_RwxDeviceCreate);
                if (g_RwxDeviceClose)
                    DriverObject->MajorFunction[IRP_MJ_CLOSE] =
                    reinterpret_cast<PDRIVER_DISPATCH>(g_RwxDeviceClose);
                if (g_RwxIoctlDispatch)
                    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] =
                    reinterpret_cast<PDRIVER_DISPATCH>(g_RwxIoctlDispatch);
                if (g_RwxDriverUnload)
                    DriverObject->DriverUnload =
                    reinterpret_cast<PDRIVER_UNLOAD>(g_RwxDriverUnload);

                SvDebugPrint("PTE hook: MajorFunction[] redirected through RWX cave stubs\n");
            }
            else
            {
                SvDebugPrint("PTE hook: CreateRwxHandlers failed — using direct dispatch pointers\n");
            }
        }
#else
        SvDebugPrint("[SimpleSvm] SHADOW_PAGING_DISABLED – RWX cave stubs skipped.\n");
#endif
    }

    //
    // Use buffered I/O for all device I/O operations.
    //
    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    SvDebugPrint("SimpleSvm device created successfully.\n");
    return STATUS_SUCCESS;
}

/*!
    @brief      An entry point of this driver.

    @param[in]  DriverObject - A driver object.
    @param[in]  RegistryPath - Unused.

    @result     STATUS_SUCCESS on success; otherwise, an appropriate error code.
 */
_Use_decl_annotations_
EXTERN_C
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    UNICODE_STRING objectName;
    OBJECT_ATTRIBUTES objectAttributes;
    PCALLBACK_OBJECT callbackObject;
    PVOID callbackRegistration;

    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    SV_DEBUG_BREAK();

    callbackRegistration = nullptr;

    //
    // Opts-in no-execute (NX) nonpaged pool
    // defining POOL_NX_OPTIN as 1 and calling this function, nonpaged pool
    // allocation by the ExAllocatePool family with the NonPagedPool flag
    // automatically allocates NX nonpaged pool on Windows 8 and later versions
    // of Windows, while on Windows 7 where NX nonpaged pool is unsupported,
    // executable nonpaged pool is returned as usual.
    //
    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    //
    // Resolve undocumented kernel functions at runtime.
    //
    status = SvkmResolveImports();
    if (!NT_SUCCESS(status))
    {
        SvDebugPrint("Failed to resolve kernel imports: 0x%08X\n", status);
        goto Exit;
    }

    //
    // When manually mapped (e.g. via kdmapper) the kernel image loader never
    // registers our .pdata section.  Any exception unwind through our frames
    // then fails RtlLookupFunctionEntry → escalates to #DF → triple fault.
    //
    // RtlAddFunctionTable (exported by ntoskrnl, just absent from km headers)
    // fixes this.  Walk backwards from DriverEntry to find our MZ header and
    // register the .pdata section.  Under sc.exe this is a benign no-op since
    // the loader already registered the same table.
    //
    if (g_RtlAddFunctionTable != nullptr)
    {
        ULONG_PTR base = reinterpret_cast<ULONG_PTR>(DriverEntry) &
            ~static_cast<ULONG_PTR>(PAGE_SIZE - 1);
        for (ULONG i = 0; i < (8 * 1024 * 1024 / PAGE_SIZE); i++, base -= PAGE_SIZE)
        {
            if (*reinterpret_cast<PUSHORT>(base) != IMAGE_DOS_SIGNATURE)
                continue;
            PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
            if (dos->e_lfanew <= 0 || dos->e_lfanew > 0x1000)
                break;
            PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
                base + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE)
                break;
            PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
            for (USHORT s = 0; s < nt->FileHeader.NumberOfSections; s++, sec++)
            {
                if (RtlCompareMemory(sec->Name, ".pdata", 6) == 6 &&
                    sec->VirtualAddress && sec->SizeOfRawData)
                {
                    // Each RUNTIME_FUNCTION is 3 DWORDs (12 bytes).
                    PVOID fn = reinterpret_cast<PVOID>(base + sec->VirtualAddress);
                    ULONG count = sec->SizeOfRawData / 12;
                    if (g_RtlAddFunctionTable(fn, count, base))
                        SvDebugPrint("[SimpleSvm] Registered .pdata: base=%p entries=%lu\n",
                            reinterpret_cast<PVOID>(base), count);
                    else
                        SvDebugPrint("[SimpleSvm] RtlAddFunctionTable returned FALSE (already registered?)\n");
                }
            }
            break;
        }
    }

    //
    // Create the SimpleSvm device via IoCreateDriver so that user-mode clients
    // can open \\.\SimpleSvm and issue IOCTLs for the various memory mapping
    // operations (read, write, translate, kernel copy, get DTB).
    //
    {
        UNICODE_STRING driverName = RTL_CONSTANT_STRING(L"\\Driver\\SimpleSvmDevice");
        status = g_IoCreateDriver(&driverName, SvDriverInitialize);
        if (!NT_SUCCESS(status))
        {
            SvDebugPrint("IoCreateDriver failed: 0x%08X\n", status);
            goto Exit;
        }
    }

    //
    // Registers a power state callback (SvPowerCallbackRoutine) to handle
    // system sleep and resume to manage virtualization state.
    //
    // First, opens the \Callback\PowerState callback object provides
    // notification regarding power state changes. This is a system defined
    // callback object that was already created by Windows. To open a system
    // defined callback object, the Create parameter of ExCreateCallback must be
    // FALSE (and AllowMultipleCallbacks is ignore when the Create parameter is
    // FALSE).
    //
    objectName = RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
    objectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(&objectName,
        OBJ_CASE_INSENSITIVE);
    status = ExCreateCallback(&callbackObject, &objectAttributes, FALSE, TRUE);
    if (!NT_SUCCESS(status))
    {
        SvDebugPrint("Failed to open the power state callback object.\n");
        goto Exit;
    }

    //
    // Then, registers our callback. The open callback object must be
    // dereferenced.
    //
    callbackRegistration = ExRegisterCallback(callbackObject,
        SvPowerCallbackRoutine,
        nullptr);
    ObDereferenceObject(callbackObject);
    if (callbackRegistration == nullptr)
    {
        SvDebugPrint("Failed to register a power state callback.\n");
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    //
    // Capture the System-process CR3 once at PASSIVE_LEVEL.  This value is
    // written to CR3 on every CPU immediately before VMRUN so the host CR3
    // saved in HSAVE always maps the full kernel — safe regardless of which
    // process context called DriverEntry.
    //
    {
        KAPC_STATE apc;
        KeStackAttachProcess(PsInitialSystemProcess, &apc);
        g_SystemCr3 = __readcr3();
        KeUnstackDetachProcess(&apc);
        SvDebugPrint("[DriverEntry] System CR3 = %016llX\n", (ULONG64)g_SystemCr3);
    }

    //
    // Dump Machine Check Architecture (MCA) banks for post-triple-fault diagnostics.
    // Triple faults log entries that persist across warm resets; capture them early
    // before any other code clobbers the banks.
    //
    SvCalibrateCpuidCost();
    SvInitCpuidCache();
    SvDumpMcaBanks();

    //
    // Initialise COM1 raw output and emit a boot banner BEFORE we start
    // the trace drainer or any virtualization. If first VMRUN hangs, this
    // banner plus the per-exit serial lines are the only things that
    // will reach the host operator.
    //
    SvSerialInit();
    SvSerialString("[SV] boot \xe2\x80\x94 SimpleSvm initialising; SV_MINIMAL_VMCB=");
    SvSerialChar('0' + SV_MINIMAL_VMCB);
    SvSerialString("\n");

    //
    // Start the asynchronous VMEXIT-ring drainer BEFORE virtualizing any
    // CPU, so that records produced by the first VMRUN are not lost.
    //
    SvStartVmexitTraceDrainer();

    //
    // Virtualize all processors on the system.
    //
    SvDebugPrint("[DriverEntry] Starting SvVirtualizeAllProcessors...\n");
    status = SvVirtualizeAllProcessors();
    SvDebugPrint("[DriverEntry] SvVirtualizeAllProcessors returned 0x%08X\n", status);

Exit:
    if (NT_SUCCESS(status))
    {
        //
        // On success, save the registration handle for un-registration.
        //
        NT_ASSERT(callbackRegistration);
        g_PowerCallbackRegistration = callbackRegistration;
        SvDebugPrint("[DriverEntry] *** ALL PROCESSORS VIRTUALIZED SUCCESSFULLY ***\n");
    }
    else
    {
        //
        // On any failure, clean up stuff as needed.
        //
        SvDebugPrint("[DriverEntry] FAILED: returning status=0x%08X\n", status);
        if (callbackRegistration != nullptr)
        {
            ExUnregisterCallback(callbackRegistration);
        }
    }
    return status;
}

/*!
    @brief      Driver unload callback.

    @details    This function de-virtualize all processors on the system.

    @param[in]  DriverObject - Unused.
 */
_Use_decl_annotations_
static
VOID
SvDriverUnload(
    PDRIVER_OBJECT DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    SV_DEBUG_BREAK();

    //
    // Clean up any live PML4 injections before tearing down the hypervisor.
    // This zeros the injected PML4Es and frees backing memory, preventing a
    // MEMORY_MANAGEMENT bugcheck from dangling page table entries.
    //
    request::CleanupAllPml4Injections();

    //
    // Unregister the power state callback.
    //
    NT_ASSERT(g_PowerCallbackRegistration);
    ExUnregisterCallback(g_PowerCallbackRegistration);

    //
    // De-virtualize all processors on the system.
    //
    SvDevirtualizeAllProcessors();

    SvStopVmexitTraceDrainer();

    // Free private host page tables and per-CPU GDT copies.
    SvDestroyHostCr3();
    for (ULONG i = 0; i < HOST_GDT_MAX_CPUS; i++)
        SvDestroyHostGdt(i);
}

/*!
    @brief      PowerState callback routine.

    @details    This function de-virtualize all processors when the system is
                exiting system power state S0 (ie, the system is about to sleep
                etc), and virtualize all processors when the system has just
                reentered S0 (ie, the system has resume from sleep etc).

                Those operations are required because virtualization is cleared
                during sleep.

                For the meanings of parameters, see ExRegisterCallback in MSDN.

    @param[in]  CallbackContext - Unused.
    @param[in]  Argument1 - A PO_CB_XXX constant value.
    @param[in]  Argument2 - A value of TRUE or FALSE.
 */
_Use_decl_annotations_
static
VOID
SvPowerCallbackRoutine(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2
)
{
    UNREFERENCED_PARAMETER(CallbackContext);

    //
    // PO_CB_SYSTEM_STATE_LOCK of Argument1 indicates that a system power state
    // change is imminent.
    //
    if (Argument1 != reinterpret_cast<PVOID>(PO_CB_SYSTEM_STATE_LOCK))
    {
        goto Exit;
    }

    if (Argument2 != FALSE)
    {
        //
        // The system has just reentered S0. Re-virtualize all processors.
        //
        NT_VERIFY(NT_SUCCESS(SvVirtualizeAllProcessors()));
    }
    else
    {
        //
        // The system is about to exit system power state S0. De-virtualize all
        // processors.
        //
        SvDevirtualizeAllProcessors();
    }

Exit:
    return;
}
