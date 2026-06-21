#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <intrin.h>

// RtlPcToFileHeader is exported by ntoskrnl but not declared in all WDK headers
extern "C" NTKERNELAPI PVOID RtlPcToFileHeader(PVOID PcValue, PVOID* BaseOfImage);

// ============================================================
//  Helpers
// ============================================================

// Build a PHYSICAL_ADDRESS from a ULONG64 without designated-initializer syntax
static __forceinline PHYSICAL_ADDRESS MakePhysAddr(ULONG64 pa)
{
    PHYSICAL_ADDRESS addr;
    addr.QuadPart = (LONGLONG)pa;
    return addr;
}

// ============================================================
//  Constants
// ============================================================

#define PAGE_CHUNK          0x1000
#define SANITY_MAX_IMAGE    0x8000000       // 128 MB ceiling — covers ntoskrnl on any build
#define MAX_RWX_PAGES       64              // pages tracked across all scanned modules
#define MAX_STUB_COUNT      (MAX_RWX_PAGES * 16)
#define STUB_NAME_MAX       32
#define DRIVER_NAME_MAX     64

#define STUB_TYPE_GENERAL   0
#define STUB_TYPE_IOCTL     1
#define STUB_TYPE_CRITICAL  2

// ============================================================
//  PTE / virtual-address types
// ============================================================

// ============================================================
//  PTE / virtual-address types  (anonymous bitfields, C4201 suppressed)
// ============================================================
#pragma warning(push)
#pragma warning(disable: 4201)

typedef union _PTE_64
{
    ULONG64 AsULONG64;
    struct
    {
        ULONG64 Present : 1;    // [0]
        ULONG64 Write : 1;    // [1]
        ULONG64 UserMode : 1;    // [2]
        ULONG64 WriteThrough : 1;    // [3]
        ULONG64 CacheDisable : 1;    // [4]
        ULONG64 Accessed : 1;    // [5]
        ULONG64 Dirty : 1;    // [6]
        ULONG64 LargePage : 1;    // [7]
        ULONG64 Global : 1;    // [8]
        ULONG64 Avl : 3;    // [9:11]
        ULONG64 PageFrameNumber : 40;   // [12:51]
        ULONG64 Reserved : 11;   // [52:62]
        ULONG64 NoExecute : 1;    // [63]
    };
} PTE_64, * PPTE_64;

typedef union _VIRT_ADDR_64
{
    ULONG64 AsULONG64;
    struct
    {
        ULONG64 PageOffset : 12;   // [0:11]
        ULONG64 PTE : 9;    // [12:20]
        ULONG64 PDE : 9;    // [21:29]
        ULONG64 PDPTE : 9;    // [30:38]
        ULONG64 PML4E : 9;    // [39:47]
        ULONG64 Reserved : 16;   // [48:63]
    };
} VIRT_ADDR_64, * PVIRT_ADDR_64;

#pragma warning(pop)

// Forward declarations for hypervisor-owned contiguous-memory allocators
// (defined in SimpleSvm.cpp, which #includes this file).
// Exec/decoy pages MUST use these — ExAllocatePool2 pages have PFN
// reference counts managed by the pager; injecting their PAs raw into
// NPT entries corrupts those counts and triggers MEMORY_MANAGEMENT (0x1A).
static PVOID SvAllocateContiguousMemory(SIZE_T NumberOfBytes);
static VOID  SvFreeContiguousMemory(PVOID BaseAddress);

// ============================================================
//  Stub pool types
// ============================================================

typedef struct _STUB_INFO
{
    PVOID           StubAddress;
    SIZE_T          TargetSize;
    PVOID           SourcePage;
    const char* DriverName;             // points into DriverNameStorage below
    BOOLEAN         Active;
    PVOID           TargetAddress;
    ULONG           FunctionType;
    char            FunctionName[STUB_NAME_MAX];
    PVOID           OriginalDriverBase;
    ULONG           OriginalDriverSize;
    ULONG           PageOffset;
    PVOID           StubMdl;
    char            DriverNameStorage[DRIVER_NAME_MAX]; // owns the name string
} STUB_INFO, * PSTUB_INFO;

typedef struct _RWX_STUB_POOL
{
    STUB_INFO   Stubs[MAX_STUB_COUNT];
    ULONG       StubCount;
    PVOID       PoolPages[MAX_RWX_PAGES];
    SIZE_T      PoolPageSizes[MAX_RWX_PAGES];
    ULONG       PoolPageCount;
    SIZE_T      TotalPoolSpace;
    SIZE_T      TotalUsedSpace;
    KSPIN_LOCK  PoolLock;
} RWX_STUB_POOL, * PRWX_STUB_POOL;

// ============================================================
//  Globals  (defined here — Ptehook.cpp is #included once)
// ============================================================

static KSPIN_LOCK   g_DriverStateLock;
static BOOLEAN      g_DriverStateLockInitialized = FALSE;
static BOOLEAN      g_DriverActive = FALSE;

static RWX_STUB_POOL g_StubPool;
static BOOLEAN       g_StubPoolInitialized = FALSE;

// IoCompleteRequest function pointer resolved at runtime
typedef VOID(NTAPI* PFN_IoCompleteRequest)(PIRP Irp, CCHAR PriorityBoost);
static PFN_IoCompleteRequest gIoCompleteRequest = NULL;

// Code-buffer globals — used only by AssertCodeSpace (debug assert);
// AllocateStubFromPool is pool-based so these are not exercised at runtime.
static UCHAR* gCodeBase = NULL;
static SIZE_T  gCodeCapacity = 0;
static UCHAR* gCodeWrite = NULL;

// ============================================================
//  NPT shadow page structures
//
//  Each SHADOW_PAGE_ENTRY covers one 4KB page that contains a JMP stub.
//  Two physical pages are allocated per entry:
//    ExecVA/ExecPA  — copy of original driver bytes (real stubs); mapped into NPT
//                     only during the brief window the CPU is executing the stub.
//    DecoyVA/DecoyPA — filled with 0x90 (NOP); always-visible to read-only scanners.
//
//  State machine (per VP, shared NPT):
//    DECOY  → NPT PTE points to DecoyPA, NX=1  → instruction fetch triggers #NPF
//    #NPF   → swap to ExecPA/NX=0, set RFLAGS.TF  (single-step)
//    #DB    → swap back to DecoyPA/NX=1, clear TF
//
//  NptPte is a raw PUINT64 here; SvHandleNpf/Db in SimpleSvm.cpp casts it to
//  PML4_ENTRY_2MB* (defined in that TU).
// ============================================================
#define MAX_SHADOW_PAGES    8
#define MAX_SPLIT_PTS       8
#define MAX_SHADOW_STUBS_PER_PAGE 8

typedef struct _SHADOW_STUB_RANGE {
    UINT64 StartVa;       // guest virtual address of the first stub byte
    UINT16 Length;        // bytes that must remain visible on the exec page
    UINT16 Reserved;
} SHADOW_STUB_RANGE, * PSHADOW_STUB_RANGE;

typedef struct _SHADOW_PAGE_ENTRY {
    ULONG64  GuestPA;       // 4KB-aligned physical address of the stub page (identity-mapped: guest PA == host PA)
    ULONG64  ExecPA;        // PA of pool page with real stub bytes
    ULONG64  DecoyPA;       // PA of pool page filled with NOPs
    PVOID    ExecVA;
    PVOID    DecoyVA;
    PUINT64  NptPte;        // pointer to the split 4KB NPT PTE; NULL until SvRegisterAllShadowPages
    PMDL     CaveMdl;       // MDL keeping the cave page resident; prevents MiMappedPageWriter PFN corruption
    BOOLEAN  Active;
    BOOLEAN  InExecState;   // TRUE while exec page is currently mapped
    ULONG    StubCount;
    SHADOW_STUB_RANGE Stubs[MAX_SHADOW_STUBS_PER_PAGE];
} SHADOW_PAGE_ENTRY, * PSHADOW_PAGE_ENTRY;

static SHADOW_PAGE_ENTRY g_ShadowPages[MAX_SHADOW_PAGES];
static ULONG             g_ShadowPageCount = 0;

// Per-VMCB step state: tracks the shadow entry this VpData activated,
// and the guest's pre-step TF / DR6.BS so SvHandleDb can restore them.
typedef struct _SHADOW_STEP_STATE {
    PSHADOW_PAGE_ENTRY ActiveEntry;       // entry swapped to exec by this VMCB; NULL when idle
    bool               GuestHadTf;       // RFLAGS.TF was set by the guest before we armed ours
    bool               GuestHadBs;       // DR6.BS was set before our step
    UINT64             GuestDr6Snapshot; // DR6 captured at NPF time; masks stale hw-BP bits in SvHandleDb
} SHADOW_STEP_STATE;

// Diagnostic counters incremented atomically from VMEXIT context.
// g_ShadowNpfCount  — #NPF instruction-fetch hits on a guarded page (exec window opened)
// g_ShadowDbCount   — #DB single-steps that completed our swap-back   (exec window closed)
// g_ShadowDbFwdCount — #DB events forwarded to the guest (non-ours, or coincident hw BP/TF)
// When the driver is working correctly, NpfCount == DbCount after each round-trip.
static volatile LONG g_ShadowNpfCount = 0;
static volatile LONG g_ShadowDbCount = 0;
static volatile LONG g_ShadowDbFwdCount = 0;

// Lockless single-producer-per-CPU ring buffer for VMEXIT-context tracing.
// Writing is a single InterlockedIncrement + array store — no spinlock, no IPI,
// safe with GIF clear.  Reading/printing happens from a passive-level worker.
#define SHADOW_TRACE_ENTRIES 1024
#define SHADOW_TRACE_KIND_NPF  1
#define SHADOW_TRACE_KIND_DB   2
#define SHADOW_TRACE_KIND_FWD  3
#define SHADOW_TRACE_KIND_CONT 4

typedef struct _SHADOW_TRACE_ENTRY {
    UINT64 Tsc;
    UINT64 Gpa;
    UINT64 Dr6;       // only meaningful for KIND_DB / KIND_FWD
    UINT32 Cpu;
    UINT8  Kind;      // SHADOW_TRACE_KIND_*
    UINT8  Flags;     // bit0=hw, bit1=guestTF
    UINT8  Pad[2];
} SHADOW_TRACE_ENTRY;

static SHADOW_TRACE_ENTRY g_ShadowTrace[SHADOW_TRACE_ENTRIES];
static volatile LONG      g_ShadowTraceIdx = 0;

static __forceinline void SvShadowTrace(UINT8 kind, UINT64 gpa, UINT64 dr6, UINT8 flags)
{
    LONG i = (InterlockedIncrement(&g_ShadowTraceIdx) - 1) & (SHADOW_TRACE_ENTRIES - 1);
    g_ShadowTrace[i].Tsc = __rdtsc();
    g_ShadowTrace[i].Gpa = gpa;
    g_ShadowTrace[i].Dr6 = dr6;
    g_ShadowTrace[i].Cpu = KeGetCurrentProcessorIndex();
    g_ShadowTrace[i].Kind = kind;
    g_ShadowTrace[i].Flags = flags;
}

// Drain up to 'maxEntries' unprinted trace entries and emit them via DbgPrint.
// Call ONLY from PASSIVE_LEVEL (e.g. IOCTL handler, worker thread, timer DPC drain).
static LONG g_ShadowTracePrinted = 0;

static void SvDrainShadowTrace(ULONG maxEntries)
{
    LONG total = g_ShadowTraceIdx;         // snapshot — may still be advancing
    LONG start = g_ShadowTracePrinted;
    LONG count = total - start;
    if (count <= 0) return;
    if ((ULONG)count > maxEntries) count = (LONG)maxEntries;

    for (LONG n = 0; n < count; n++)
    {
        LONG i = (start + n) & (SHADOW_TRACE_ENTRIES - 1);
        SHADOW_TRACE_ENTRY* e = &g_ShadowTrace[i];
        const char* tag = (e->Kind == SHADOW_TRACE_KIND_NPF) ? "NPF" :
            (e->Kind == SHADOW_TRACE_KIND_DB) ? "DB " :
            (e->Kind == SHADOW_TRACE_KIND_CONT) ? "CNT" : "FWD";
        DbgPrint("[shadow-%s] cpu=%u GPA=%016llX DR6=%016llX flags=%02X tsc=%llu\n",
            tag, e->Cpu, e->Gpa, e->Dr6, e->Flags, e->Tsc);
    }
    g_ShadowTracePrinted = start + count;
}

// Tracking arrays for 4KB PTs carved out of split 2MB NPT PDEs.
// g_SplitPtPAs caches MmGetPhysicalAddress(VA).QuadPart at split time so the
// VMEXIT-context NPF handler can do the PA→VA lookup without calling any API
// that might acquire a lock (e.g. MmGetVirtualForPhysical).
static PVOID             g_SplitPtVAs[MAX_SPLIT_PTS];
static ULONG64           g_SplitPtPAs[MAX_SPLIT_PTS];   // physical address of each PT page
static ULONG64           g_SplitPtGPA2MB[MAX_SPLIT_PTS];
static ULONG             g_SplitPtCount = 0;

// Forward declarations for helpers defined in Ptehook.cpp (which #includes this file).
static PVOID GetVirtualFromPhysical(PHYSICAL_ADDRESS PhysicalAddress);
static PPTE_64 GetPTEAddress(PVOID VirtualAddress, ULONG64 CR3);

// Register StubVA's 4KB page for NPT shadow protection.
// Called from CreateRwxHandlers immediately after each EmitJumpStub.
//
// The stub bytes were just written to the cave VA, which currently maps the
// ntoskrnl physical page.  That dirtied the ntoskrnl PFN: MiMappedPageWriter
// will try to flush it, but our NPT maps that GPA to the decoy PA, not the
// real ntoskrnl PA → PFN inconsistency → MEMORY_MANAGEMENT 0x1A/0x8840.
//
// Fix: remap the cave VA's host PTE to the exec PA (a hypervisor-owned
// contiguous page).  After the remap the cave VA is backed by exec PA —
// future writes go there, the ntoskrnl PFN is never touched again, and the
// NPT only ever sees exec PA and decoy PA, neither of which is in Windows MM.
static BOOLEAN
RegisterNptShadowPage(
    _In_ PVOID  CaveVa,
    _In_ UINT64 TargetFn)
{
    PVOID  pageVa = PAGE_ALIGN(CaveVa);
    ULONG  offset = (ULONG)((ULONG_PTR)CaveVa - (ULONG_PTR)pageVa);
    PHYSICAL_ADDRESS guestPa = MmGetPhysicalAddress(pageVa);
    ULONG64 pageGpa = guestPa.QuadPart & ~(ULONG64)0xFFF;

    // Multiple cave stubs frequently live in the same cng/ntoskrnl padding
    // page.  A guest GPA has exactly one NPT PTE, so it must also have exactly
    // one exec/decoy pair.  Creating one SHADOW_PAGE_ENTRY per stub makes the
    // final registration win the PTE while SvFindShadowEntry returns the first
    // registration, exposing the wrong exec copy at runtime.
    for (ULONG i = 0; i < g_ShadowPageCount; i++)
    {
        PSHADOW_PAGE_ENTRY existing = &g_ShadowPages[i];
        if (!existing->Active || existing->GuestPA != pageGpa)
            continue;

        if (TargetFn != 0)
        {
            if (existing->StubCount >= MAX_SHADOW_STUBS_PER_PAGE)
            {
                DbgPrint("[shadow] Stub range table full for GPA=%llX\n", pageGpa);
                return FALSE;
            }

            PUCHAR s = static_cast<PUCHAR>(existing->ExecVA) + offset;
            s[0] = 0x48; s[1] = 0xB8;
            *reinterpret_cast<UINT64*>(s + 2) = TargetFn;
            s[10] = 0xFF; s[11] = 0xE0;
            s[12] = 0x90; s[13] = 0x90;

            PSHADOW_STUB_RANGE range =
                &existing->Stubs[existing->StubCount++];
            range->StartVa = (UINT64)(ULONG_PTR)CaveVa;
            range->Length = 12; // mov rax,imm64 + jmp rax; trailing NOPs never execute
            range->Reserved = 0;
        }

        DbgPrint("[shadow] Coalesced cave=%p into GPA=%llX (%lu stubs)\n",
            CaveVa, pageGpa, existing->StubCount);
        return TRUE;
    }

    if (g_ShadowPageCount >= MAX_SHADOW_PAGES)
    {
        DbgPrint("[shadow] Table full, cannot register %p\n", CaveVa);
        return FALSE;
    }

    // ── 1. Lock the original page for reading only. ───────────────────────
    PMDL mdl = IoAllocateMdl(pageVa, PAGE_SIZE, FALSE, FALSE, nullptr);
    if (!mdl)
    {
        DbgPrint("[shadow] IoAllocateMdl failed for %p\n", pageVa);
        return FALSE;
    }

    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        DbgPrint("[shadow] MmProbeAndLockPages exception on %p\n", pageVa);
        return FALSE;
    }

    PVOID lockedVa = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
    if (!lockedVa)
    {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        DbgPrint("[shadow] MmGetSystemAddressForMdlSafe failed for %p\n", pageVa);
        return FALSE;
    }

    // ── 2. Allocate exec and decoy pages. ─────────────────────────────────
    PVOID execVa = SvAllocateContiguousMemory(PAGE_SIZE);
    PVOID decoyVa = SvAllocateContiguousMemory(PAGE_SIZE);
    if (!execVa || !decoyVa)
    {
        if (execVa)  SvFreeContiguousMemory(execVa);
        if (decoyVa) SvFreeContiguousMemory(decoyVa);
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        DbgPrint("[shadow] Contiguous alloc failed for %p\n", CaveVa);
        return FALSE;
    }

    // ── 3. Populate exec and decoy based on mode. ─────────────────────────
    //
    // Both modes copy the original FIRST so the original is never written to.
    //
    RtlCopyMemory(execVa, lockedVa, PAGE_SIZE);

    if (TargetFn != 0)
    {
        // Stub mode: decoy = original content (unmodified, MM-safe),
        //            exec  = original + stub at cave offset.
        RtlCopyMemory(decoyVa, lockedVa, PAGE_SIZE);
        // Inline stub: mov rax, imm64 (48 B8 + 8-byte target) + jmp rax (FF E0) + nop nop
        PUCHAR s = static_cast<PUCHAR>(execVa) + offset;
        s[0] = 0x48; s[1] = 0xB8;
        *reinterpret_cast<UINT64*>(s + 2) = TargetFn;
        s[10] = 0xFF; s[11] = 0xE0;
        s[12] = 0x90; s[13] = 0x90;
    }
    else
    {
        // Stealth mode: decoy = zeros (physical scanner sees nothing),
        //               exec  = original payload (already copied above).
        RtlZeroMemory(decoyVa, PAGE_SIZE);
    }

    // ── 4. Record physical addresses. ─────────────────────────────────────
    PHYSICAL_ADDRESS execPa = MmGetPhysicalAddress(execVa);
    PHYSICAL_ADDRESS decoyPa = MmGetPhysicalAddress(decoyVa);

    // ── 5. Fill shadow table entry. ───────────────────────────────────────
    PSHADOW_PAGE_ENTRY e = &g_ShadowPages[g_ShadowPageCount++];
    e->GuestPA = guestPa.QuadPart & ~(ULONG64)0xFFF;
    e->ExecPA = execPa.QuadPart & ~(ULONG64)0xFFF;
    e->ExecVA = execVa;
    e->DecoyPA = decoyPa.QuadPart & ~(ULONG64)0xFFF;
    e->DecoyVA = decoyVa;
    e->CaveMdl = mdl;
    e->Active = TRUE;
    e->NptPte = nullptr;
    e->InExecState = FALSE;
    e->StubCount = 0;
    RtlZeroMemory(e->Stubs, sizeof(e->Stubs));
    if (TargetFn != 0)
    {
        e->Stubs[0].StartVa = (UINT64)(ULONG_PTR)CaveVa;
        e->Stubs[0].Length = 12;
        e->StubCount = 1;
    }

    DbgPrint("[shadow] %s cave=%p GPA=%llX exec=%llX decoy=%llX\n",
        TargetFn ? "stub" : "stealth",
        CaveVa, e->GuestPA, e->ExecPA, e->DecoyPA);

    return TRUE;
}

// ============================================================
//  Helper: locate ntoskrnl image base + size via PE headers
// ============================================================

static BOOLEAN GetNtoskrnlInfo(PVOID* BaseOut, ULONG* SizeOut)
{
    PVOID base = NULL;
    RtlPcToFileHeader((PVOID)(ULONG_PTR)MmGetPhysicalAddress, &base);
    if (!base)
        return FALSE;

    __try
    {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return FALSE;

        PIMAGE_NT_HEADERS nt =
            (PIMAGE_NT_HEADERS)((PUCHAR)base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return FALSE;

        *BaseOut = base;
        *SizeOut = nt->OptionalHeader.SizeOfImage;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
}

// ============================================================
//  ZwQuerySystemInformation module enumeration
// ============================================================

#define SVM_SystemModuleInformation 11u

typedef struct _SVM_MODULE_INFO
{
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} SVM_MODULE_INFO, * PSVM_MODULE_INFO;

typedef struct _SVM_MODULE_LIST
{
    ULONG          NumberOfModules;
    SVM_MODULE_INFO Modules[1];
} SVM_MODULE_LIST, * PSVM_MODULE_LIST;

extern "C" NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG  SystemInformationClass,
    PVOID  SystemInformation,
    ULONG  SystemInformationLength,
    PULONG ReturnLength
);

// Forward declaration — defined in Ptehook.cpp
static VOID ScanDriverForRWXPagesWithMDL(const char* name, PVOID base, ULONG size);

#pragma warning(push)
#pragma warning(disable: 4505)
// Enumerate loaded kernel modules via ZwQuerySystemInformation and scan every
// .sys module for 64-byte+ code-cave padding runs suitable for JMP stubs.
static VOID ScanAllLoadedModules(VOID)
{
    // Resolve ntoskrnl range once for explicit exclusion below.
    PVOID ntBase = NULL;
    ULONG ntSize = 0;
    GetNtoskrnlInfo(&ntBase, &ntSize);

    // Query required buffer size — first call with NULL intentionally fails
    // with STATUS_INFO_LENGTH_MISMATCH and fills in the needed length.
    ULONG needed = 0;
    ZwQuerySystemInformation(SVM_SystemModuleInformation, NULL, 0, &needed);
    if (needed == 0)
    {
        DbgPrint("[scan] ZwQuerySystemInformation size query returned 0\n");
        return;
    }
    needed += PAGE_SIZE; // extra room for modules loaded between calls

    PSVM_MODULE_LIST mods = (PSVM_MODULE_LIST)
        ExAllocatePool2(POOL_FLAG_NON_PAGED, needed, 'MVSS');
    if (!mods)
    {
        DbgPrint("[scan] Failed to allocate module list buffer\n");
        return;
    }

    NTSTATUS status = ZwQuerySystemInformation(SVM_SystemModuleInformation,
        mods, needed, &needed);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[scan] ZwQuerySystemInformation failed: 0x%08X\n", status);
        ExFreePoolWithTag(mods, 'MVSS');
        return;
    }

    ULONG scanned = 0;
    for (ULONG i = 0; i < mods->NumberOfModules; i++)
    {
        PSVM_MODULE_INFO mod = &mods->Modules[i];
        PVOID base = mod->ImageBase;
        ULONG size = mod->ImageSize;

        // Only substantial kernel-space images.
        if (!base || size < 0x40000 || size > SANITY_MAX_IMAGE)
            continue;
        if ((ULONG_PTR)base < 0xFFFF000000000000ULL)
            continue;

        // Skip ntoskrnl — its PTE pages are write-protected by design.
        if (ntBase && ntSize &&
            (ULONG_PTR)base >= (ULONG_PTR)ntBase &&
            (ULONG_PTR)base < (ULONG_PTR)ntBase + ntSize)
            continue;

        // FullPathName is always null-terminated within its 256-byte array.
        // OffsetToFileName points at just the filename component.
        const char* name = (const char*)mod->FullPathName + mod->OffsetToFileName;
        SIZE_T nlen = strnlen(name, sizeof(mod->FullPathName) - mod->OffsetToFileName);

        // Only scan .sys files — excludes ntoskrnl.exe, hal.dll, etc.
        if (nlen < 5)
            continue;
        const char* ext = name + nlen - 4;
        if (!((ext[0] == '.') &&
            ((ext[1] | 0x20) == 's') &&
            ((ext[2] | 0x20) == 'y') &&
            ((ext[3] | 0x20) == 's')))
            continue;

        char narrowName[DRIVER_NAME_MAX] = { 0 };
        SIZE_T copyLen = nlen < (DRIVER_NAME_MAX - 1) ? nlen : (DRIVER_NAME_MAX - 1);
        RtlCopyMemory(narrowName, name, copyLen);

        ScanDriverForRWXPagesWithMDL(narrowName, base, size);
        scanned++;
    }

    ExFreePoolWithTag(mods, 'MVSS');
    DbgPrint("[scan] Scanned %lu modules — pool has %lu stubs\n",
        scanned, g_StubPool.StubCount);
}
#pragma warning(pop)
