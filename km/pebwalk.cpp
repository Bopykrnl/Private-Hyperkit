// pebwalk.cpp — included as part of SimpleSvm.cpp single-TU build.
// Walks a target process's PEB entirely via physical memory reads using
// translate_linear + read_physical. No KeStackAttachProcess, no virtual
// address space switch, no AC-visible cross-process callstack.

// ============================================================
//  Minimal physical-read PEB/LDR structures
//  All pointers stored as uintptr_t (64-bit VA in target process).
//  We read them physically so we never touch the target address space.
// ============================================================

// UNICODE_STRING as it appears in 64-bit target process memory
typedef struct _UNICODE_STRING_T
{
    USHORT   Length;
    USHORT   MaximumLength;
    UINT32   Pad;
    UINT64   Buffer;    // VA in target process
} UNICODE_STRING_T;

// Minimal LDR_DATA_TABLE_ENTRY fields we actually use
typedef struct _LDR_ENTRY_T
{
    UINT64 InLoadOrderFlink;    // +0x00  LIST_ENTRY.Flink
    UINT64 InLoadOrderBlink;    // +0x08
    UINT64 InMemoryOrderFlink;  // +0x10
    UINT64 InMemoryOrderBlink;  // +0x18
    UINT64 InInitOrderFlink;    // +0x20
    UINT64 InInitOrderBlink;    // +0x28
    UINT64 DllBase;             // +0x30
    UINT64 EntryPoint;          // +0x38
    UINT64 SizeOfImage;         // +0x40  (stored as ULONG but padded to 8)
    UNICODE_STRING_T FullDllName;   // +0x48
    UNICODE_STRING_T BaseDllName;   // +0x58
} LDR_ENTRY_T;

// Minimal PEB_LDR_DATA fields
typedef struct _PEB_LDR_T
{
    UINT32 Length;              // +0x00
    UINT32 Initialized;         // +0x04
    UINT64 SsHandle;            // +0x08
    UINT64 InLoadOrderFlink;    // +0x10  InLoadOrderModuleList.Flink
    UINT64 InLoadOrderBlink;    // +0x18
} PEB_LDR_T;

// Minimal PEB fields (64-bit)
typedef struct _PEB_T
{
    UINT8  InheritedAddressSpace;   // +0x000
    UINT8  ReadImageFileExecOptions;// +0x001
    UINT8  BeingDebugged;           // +0x002
    UINT8  BitField;                // +0x003
    UINT32 Pad;                     // +0x004
    UINT64 Mutant;                  // +0x008
    UINT64 ImageBaseAddress;        // +0x010
    UINT64 Ldr;                     // +0x018  → PEB_LDR_DATA VA in target
} _PEB_T;

// ----------------------------------------------------------------
//  PhysReadT<T> — read sizeof(T) bytes from a target-process VA
//  using the target's DTB for translation.
// ----------------------------------------------------------------
template<typename T>
static T PhysReadVA(uintptr_t targetDtb, uintptr_t va)
{
    T val = {};
    if (!va) return val;

    uintptr_t pa = request::translate_linear(targetDtb, va);
    if (!pa) return val;

    size_t bytes = 0;
    request::read_physical(pa, &val, sizeof(T), &bytes);
    return val;
}

// Read a UNICODE_STRING_T's content (up to maxChars wide chars) into buf.
static BOOLEAN PhysReadUnicodeString(
    uintptr_t targetDtb,
    const UNICODE_STRING_T& us,
    WCHAR* buf, SIZE_T maxChars)
{
    if (!us.Buffer || !us.Length) return FALSE;
    SIZE_T charCount = us.Length / sizeof(WCHAR);
    if (charCount >= maxChars) charCount = maxChars - 1;

    // The string may span a page boundary — read byte by byte in page chunks
    SIZE_T remaining = charCount * sizeof(WCHAR);
    uintptr_t srcVA  = (uintptr_t)us.Buffer;
    PUCHAR    dst    = (PUCHAR)buf;

    while (remaining > 0)
    {
        uintptr_t pa = request::translate_linear(targetDtb, srcVA);
        if (!pa) return FALSE;

        SIZE_T chunk = PAGE_SIZE - (pa & 0xFFF);
        if (chunk > remaining) chunk = remaining;

        size_t got = 0;
        if (!NT_SUCCESS(request::read_physical(pa, dst, chunk, &got))) return FALSE;

        dst       += chunk;
        srcVA     += chunk;
        remaining -= chunk;
    }

    buf[charCount] = L'\0';
    return TRUE;
}

// ----------------------------------------------------------------
//  GetProcessModuleBase — physical PEB walk, no address space switch
//
//  targetDtb must already be resolved (e.g. from get_dtb IOCTL).
//  Returns the DllBase VA in the target process, or 0 on failure.
// ----------------------------------------------------------------
static uintptr_t GetProcessModuleBase(uintptr_t targetDtb, const WCHAR* moduleName)
{
    if (!targetDtb || !moduleName) return 0;

    // Copy the module name to kernel stack before any physical reads
    WCHAR nameBuffer[128] = {};
    __try {
        wcsncpy(nameBuffer, moduleName, 127);
        nameBuffer[127] = L'\0';
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

    // Read PEB address from EPROCESS — PsGetProcessPeb returns a VA valid
    // in the target's address space. We translate it physically instead.
    // EPROCESS.Peb is at +0x550 on Win10/11 x64 (consistent across builds).
    // We receive the EPROCESS pointer from the caller; locate it via physical.
    // Simpler: accept the PEB VA directly as a parameter derived from EPROCESS.
    // Callers should use GetProcessPebVA() below to obtain it.
    return 0;   // see GetProcessModuleBaseFromPeb below
}

// Resolve the target process's PEB VA from the EPROCESS kernel object.
// EPROCESS.Peb is at +0x550 on Win10/11 x64. The EPROCESS object lives in
// non-paged pool so MmGetPhysicalAddress is safe; no attachment needed.
static uintptr_t GetProcessPebVA(PEPROCESS process)
{
    if (!process) return 0;

    // Read EPROCESS.Peb (pointer-sized field at +0x550) via physical mapping
    // of the kernel object — identical pattern to how get_dtb reads the DTB.
    PVOID pebFieldVA  = (PVOID)((ULONG_PTR)process + 0x550);
    PHYSICAL_ADDRESS pebFieldPA  = MmGetPhysicalAddress(pebFieldVA);
    PVOID pebFieldKVA = MmGetVirtualForPhysical(pebFieldPA);
    if (!pebFieldKVA) return 0;
    return *(uintptr_t*)pebFieldKVA;
}

// ----------------------------------------------------------------
//  GetProcessModuleBaseFromPeb — the real implementation
//
//  pebVA  = target process PEB virtual address (from GetProcessPebVA)
//  dtb    = target process CR3 / directory table base
// ----------------------------------------------------------------
static uintptr_t GetProcessModuleBaseFromPeb(
    uintptr_t pebVA,
    uintptr_t dtb,
    const WCHAR* moduleName)
{
    if (!pebVA || !dtb || !moduleName) return 0;

    // Copy module name to stack
    WCHAR nameBuffer[128] = {};
    __try {
        wcsncpy(nameBuffer, moduleName, 127);
        nameBuffer[127] = L'\0';
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }

    // Read PEB.Ldr VA
    _PEB_T peb = PhysReadVA<_PEB_T>(dtb, pebVA);
    if (!peb.Ldr) return 0;

    // Read PEB_LDR_DATA
    PEB_LDR_T ldr = PhysReadVA<PEB_LDR_T>(dtb, peb.Ldr);
    if (!ldr.InLoadOrderFlink) return 0;

    // The InLoadOrderModuleList head is at PEB_LDR_DATA + 0x10
    uintptr_t listHeadVA = peb.Ldr + offsetof(PEB_LDR_T, InLoadOrderFlink);
    uintptr_t entryVA    = ldr.InLoadOrderFlink;

    ULONG guard = 0;
    while (entryVA && entryVA != listHeadVA && guard++ < 512)
    {
        // LDR_DATA_TABLE_ENTRY.InLoadOrderLinks is the first field,
        // so entryVA IS the base of the LDR_ENTRY_T struct.
        LDR_ENTRY_T entry = PhysReadVA<LDR_ENTRY_T>(dtb, entryVA);

        if (entry.BaseDllName.Buffer && entry.BaseDllName.Length)
        {
            WCHAR dllName[128] = {};
            if (PhysReadUnicodeString(dtb, entry.BaseDllName, dllName, 128))
            {
                if (_wcsicmp(dllName, nameBuffer) == 0)
                    return (uintptr_t)entry.DllBase;
            }
        }

        entryVA = entry.InLoadOrderFlink;
    }

    return 0;
}

// ----------------------------------------------------------------
//  Public entry point — given a PID and module name, returns the
//  DllBase VA in that process. Zero on failure.
// ----------------------------------------------------------------
static uintptr_t GetModuleBaseByPid(HANDLE pid, const WCHAR* moduleName)
{
    PEPROCESS process = NULL;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return 0;

    uintptr_t pebVA = GetProcessPebVA(process);

    // Get the physical DTB for this process via the same physical mapping
    // used by get_dtb: read EPROCESS.DirectoryTableBase at +0x28
    uintptr_t dtb = 0;
    {
        PVOID dtbFieldVA = (PVOID)((ULONG_PTR)process + 0x28);
        PHYSICAL_ADDRESS dtbFieldPA = MmGetPhysicalAddress(dtbFieldVA);
        PVOID dtbFieldKVA = MmGetVirtualForPhysical(dtbFieldPA);
        if (dtbFieldKVA)
            dtb = *(uintptr_t*)dtbFieldKVA & ~(uintptr_t)0xFFF;
    }

    ObDereferenceObject(process);

    if (!dtb || !pebVA) return 0;

    return GetProcessModuleBaseFromPeb(pebVA, dtb, moduleName);
}
