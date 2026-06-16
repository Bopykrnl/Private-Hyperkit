#include "Ptehook.hpp"

#pragma warning(disable: 4505) // unreferenced static function — many statics here are only called via #include from SimpleSvm.cpp

// RWX handler pointers
static PVOID g_RwxDeviceCreate = NULL;
static PVOID g_RwxDeviceClose = NULL;
static PVOID g_RwxIoctlDispatch = NULL;
static PVOID g_RwxDriverUnload = NULL;
static PVOID g_RwxUnSupportedIO = NULL;

/* ========= Helper Functions ========= */
static BOOLEAN IsDriverActive() {
    if (!g_DriverStateLockInitialized) return FALSE;
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DriverStateLock, &oldIrql);
    BOOLEAN active = g_DriverActive;
    KeReleaseSpinLock(&g_DriverStateLock, oldIrql);
    return active;
}

static VOID InitializeDriverState() {
    if (!g_DriverStateLockInitialized) {
        KeInitializeSpinLock(&g_DriverStateLock);
        g_DriverStateLockInitialized = TRUE;
    }
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_DriverStateLock, &oldIrql);
    g_DriverActive = TRUE;
    KeReleaseSpinLock(&g_DriverStateLock, oldIrql);
}

/* ========= PTE Functions ========= */

static PVOID GetVirtualFromPhysical(PHYSICAL_ADDRESS PhysicalAddress) {
    return MmGetVirtualForPhysical(PhysicalAddress);
}

static PPTE_64 GetPTEAddress(PVOID VirtualAddress, ULONG64 CR3) {
    VIRT_ADDR_64 virtAddr;
    virtAddr.AsULONG64 = (ULONG64)VirtualAddress;

    ULONG64 pml4Base = CR3 & 0xFFFFFFFFFFFFF000ULL;
    PPTE_64 pml4 = (PPTE_64)GetVirtualFromPhysical(MakePhysAddr(pml4Base));
    if (!pml4 || !pml4[virtAddr.PML4E].Present) return NULL;

    ULONG64 pdpteBase = (pml4[virtAddr.PML4E].PageFrameNumber << 12);
    PPTE_64 pdpte = (PPTE_64)GetVirtualFromPhysical(MakePhysAddr(pdpteBase));
    if (!pdpte || !pdpte[virtAddr.PDPTE].Present) return NULL;
    if (pdpte[virtAddr.PDPTE].LargePage) return &pdpte[virtAddr.PDPTE]; // 1 GB huge page

    ULONG64 pdeBase = (pdpte[virtAddr.PDPTE].PageFrameNumber << 12);
    PPTE_64 pde = (PPTE_64)GetVirtualFromPhysical(MakePhysAddr(pdeBase));
    if (!pde || !pde[virtAddr.PDE].Present) return NULL;
    if (pde[virtAddr.PDE].LargePage) return &pde[virtAddr.PDE]; // 2 MB large page

    ULONG64 pteBase = (pde[virtAddr.PDE].PageFrameNumber << 12);
    PPTE_64 pte = (PPTE_64)GetVirtualFromPhysical(MakePhysAddr(pteBase));
    if (!pte) return NULL;
    return &pte[virtAddr.PTE];
}

static BOOLEAN FlipPTEToRWXSafe(PVOID VirtualAddress, ULONG64 CR3) {
    if (!IsDriverActive()) return FALSE;

    VIRT_ADDR_64 virtAddr;
    virtAddr.AsULONG64 = (ULONG64)VirtualAddress;

    // Walk PML4
    ULONG64 pml4Base = CR3 & 0xFFFFFFFFFFFFF000ULL;
    PPTE_64 pml4 = (PPTE_64)GetVirtualFromPhysical(MakePhysAddr(pml4Base));
    if (!pml4 || !pml4[virtAddr.PML4E].Present) return FALSE;
    PPTE_64 pml4Entry = &pml4[virtAddr.PML4E];

    // Walk PDPTE
    PPTE_64 pdpte = (PPTE_64)GetVirtualFromPhysical(
        MakePhysAddr((ULONG64)pml4Entry->PageFrameNumber << 12));
    if (!pdpte || !pdpte[virtAddr.PDPTE].Present) return FALSE;
    PPTE_64 pdpteEntry = &pdpte[virtAddr.PDPTE];

    if (pml4Entry->NoExecute) pml4Entry->NoExecute = 0;

    if (pdpteEntry->LargePage) {
        pdpteEntry->Write = 1;
        pdpteEntry->NoExecute = 0;
        __invlpg(VirtualAddress);
        return TRUE;
    }

    // Walk PDE
    PPTE_64 pde = (PPTE_64)GetVirtualFromPhysical(
        MakePhysAddr((ULONG64)pdpteEntry->PageFrameNumber << 12));
    if (!pde || !pde[virtAddr.PDE].Present) return FALSE;
    PPTE_64 pdeEntry = &pde[virtAddr.PDE];

    if (pdpteEntry->NoExecute) pdpteEntry->NoExecute = 0;

    if (pdeEntry->LargePage) {
        pdeEntry->Write = 1;
        pdeEntry->NoExecute = 0;
        __invlpg(VirtualAddress);
        return TRUE;
    }

    // Walk PTE (4 KB page)
    PPTE_64 pte = (PPTE_64)GetVirtualFromPhysical(
        MakePhysAddr((ULONG64)pdeEntry->PageFrameNumber << 12));
    if (!pte || !pte[virtAddr.PTE].Present) return FALSE;

    if (pdeEntry->NoExecute) pdeEntry->NoExecute = 0;

    PTE_64 mod = pte[virtAddr.PTE];
    mod.Write = 1;
    mod.NoExecute = 0;
    mod.Present = 1;
    pte[virtAddr.PTE] = mod;
    __invlpg(VirtualAddress);
    return TRUE;
}

/* ========= RWX Pool Functions ========= */
static BOOLEAN ProcessRwxPageSafeWithMDL(PVOID PageAddress, const char* DriverName,
    PVOID DriverBase, ULONG DriverSize) {
    if (!IsDriverActive()) return FALSE;

    if (!g_StubPoolInitialized) {
        RtlZeroMemory(&g_StubPool, sizeof(g_StubPool));
        KeInitializeSpinLock(&g_StubPool.PoolLock);
        g_StubPoolInitialized = TRUE;
        DbgPrint("[pool] Initialized RWX stub pool\n");
    }

    PUCHAR page = (PUCHAR)PageAddress;
    ULONG stubsCreated = 0;
    SIZE_T totalUnusedSpace = 0;
    SIZE_T currentStart = 0;
    SIZE_T currentSize = 0;
    BOOLEAN inUnused = FALSE;

    for (SIZE_T i = 0; i < PAGE_CHUNK; i++) {
        if (!IsDriverActive()) break;

        UCHAR byte = page[i];

        if (byte == 0x90 || byte == 0xCC || byte == 0x00) {
            if (!inUnused) {
                currentStart = i;
                currentSize = 1;
                inUnused = TRUE;
            }
            else {
                currentSize++;
            }
        }
        else {
            if (inUnused && currentSize >= 64) {
                KIRQL oldIrql;
                KeAcquireSpinLock(&g_StubPool.PoolLock, &oldIrql);

                if (g_StubPool.StubCount < MAX_STUB_COUNT) {
                    PVOID stubVa = page + currentStart;
                    const ULONG64 kMinKernelVa2 = 0xFFFF800000000000ULL;
                    if ((ULONG64)stubVa >= kMinKernelVa2 &&
                        stubVa != (PVOID)(ULONG_PTR)-1LL) {

                        PSTUB_INFO stub = &g_StubPool.Stubs[g_StubPool.StubCount];
                        stub->StubAddress = stubVa;
                        stub->TargetSize = currentSize;
                        stub->SourcePage = PageAddress;
                        strncpy(stub->DriverNameStorage, DriverName, DRIVER_NAME_MAX - 1);
                        stub->DriverNameStorage[DRIVER_NAME_MAX - 1] = '\0';
                        stub->DriverName = stub->DriverNameStorage;
                        stub->Active = TRUE;
                        stub->TargetAddress = stub->StubAddress;
                        stub->FunctionType = STUB_TYPE_GENERAL;
                        strncpy(stub->FunctionName, "SafePadding", STUB_NAME_MAX - 1);
                        stub->FunctionName[STUB_NAME_MAX - 1] = '\0';
                        stub->OriginalDriverBase = DriverBase;
                        stub->OriginalDriverSize = DriverSize;
                        stub->PageOffset = (ULONG)currentStart;
                        stub->StubMdl = NULL;

                        g_StubPool.StubCount++;
                        totalUnusedSpace += currentSize;
                        stubsCreated++;
                    }
                }

                KeReleaseSpinLock(&g_StubPool.PoolLock, oldIrql);
            }
            inUnused = FALSE;
            currentSize = 0;
        }
    }

    // Check final block
    if (inUnused && currentSize >= 64 && IsDriverActive()) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_StubPool.PoolLock, &oldIrql);

        if (g_StubPool.StubCount < MAX_STUB_COUNT) {
            PVOID stubVa2 = page + currentStart;
            const ULONG64 kMinKernelVa3 = 0xFFFF800000000000ULL;
            if ((ULONG64)stubVa2 >= kMinKernelVa3 &&
                stubVa2 != (PVOID)(ULONG_PTR)-1LL) {

                PSTUB_INFO stub = &g_StubPool.Stubs[g_StubPool.StubCount];
                stub->StubAddress = stubVa2;
                stub->TargetSize = currentSize;
                stub->SourcePage = PageAddress;
                strncpy(stub->DriverNameStorage, DriverName, DRIVER_NAME_MAX - 1);
                stub->DriverNameStorage[DRIVER_NAME_MAX - 1] = '\0';
                stub->DriverName = stub->DriverNameStorage;
                stub->Active = TRUE;
                stub->TargetAddress = stub->StubAddress;
                stub->FunctionType = STUB_TYPE_GENERAL;
                strncpy(stub->FunctionName, "SafePadding", STUB_NAME_MAX - 1);
                stub->FunctionName[STUB_NAME_MAX - 1] = '\0';
                stub->OriginalDriverBase = DriverBase;
                stub->OriginalDriverSize = DriverSize;
                stub->PageOffset = (ULONG)currentStart;
                stub->StubMdl = NULL;

                g_StubPool.StubCount++;
                totalUnusedSpace += currentSize;
                stubsCreated++;
            }
        }

        KeReleaseSpinLock(&g_StubPool.PoolLock, oldIrql);
    }

    if (stubsCreated > 0) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_StubPool.PoolLock, &oldIrql);

        if (g_StubPool.PoolPageCount < MAX_RWX_PAGES) {
            g_StubPool.PoolPages[g_StubPool.PoolPageCount] = PageAddress;
            g_StubPool.PoolPageSizes[g_StubPool.PoolPageCount] = totalUnusedSpace;
            g_StubPool.PoolPageCount++;
            g_StubPool.TotalPoolSpace += totalUnusedSpace;
        }

        KeReleaseSpinLock(&g_StubPool.PoolLock, oldIrql);
        return TRUE;
    }

    return FALSE;
}

static VOID ScanDriverForRWXPagesWithMDL(const char* name, PVOID base, ULONG size) {
    if (!base || !size || size > SANITY_MAX_IMAGE) return;
    if (!IsDriverActive()) return;

    DbgPrint("[scan] Processing driver: %s (base=%p, size=0x%X)\n", name, base, size);

    ULONG stubsBefore = g_StubPool.StubCount;

    for (SIZE_T offset = 0; offset < size; offset += PAGE_CHUNK) {
        if (!IsDriverActive()) break;

        PUCHAR pageVA = (PUCHAR)base + offset;

        // MmIsAddressValid must come first: for non-paged kernel addresses with
        // invalid PTEs Windows bugchecks in MiSystemFault before SEH gets control.
        if (!MmIsAddressValid(pageVA))
            continue;

        // Stubs are written into a fresh exec shadow page (never the original),
        // so no PTE flip is needed.  Just scan for code-cave slots.
        ProcessRwxPageSafeWithMDL(pageVA, name, base, size);
    }

    DbgPrint("[scan] Driver %s: created %lu stubs\n", name, g_StubPool.StubCount - stubsBefore);
}

PVOID AllocateStubFromPool(SIZE_T Size, ULONG FunctionType, const char* FunctionName) {
    if (!g_StubPoolInitialized || Size == 0) return NULL;

    Size = (Size + 7) & ~7;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_StubPool.PoolLock, &oldIrql);

    for (ULONG i = 0; i < g_StubPool.StubCount; i++) {
        PSTUB_INFO stub = &g_StubPool.Stubs[i];
        if (!stub->Active || stub->TargetSize < Size)
            continue;

        PVOID result = stub->StubAddress;

        // VA sanity check — safe at any IRQL (no MM calls).
        const ULONG64 kMinKernelVa = 0xFFFF800000000000ULL;
        if ((ULONG64)result < kMinKernelVa ||
            result == (PVOID)(ULONG_PTR)-1LL ||
            (ULONG64)result + Size < (ULONG64)result)
            continue;

        // Mark slot consumed while we still hold the lock, then drop it
        // before touching the stub memory.  RtlZeroMemory on a paged
        // code-cave VA at DISPATCH_LEVEL (spinlock held) triggers a
        // page-fault → bugcheck 0x7E because faults are illegal at DPC.
        stub->Active = FALSE;
        stub->FunctionType = FunctionType;
        if (FunctionName) {
            strncpy(stub->FunctionName, FunctionName, STUB_NAME_MAX - 1);
            stub->FunctionName[STUB_NAME_MAX - 1] = '\0';
        }
        g_StubPool.TotalUsedSpace += Size;
        KeReleaseSpinLock(&g_StubPool.PoolLock, oldIrql);

        // RtlZeroMemory on the cave VA removed: the original page is
        // read-only and never written to in the split-shadow model.
        // Stubs go into the exec shadow page inside RegisterNptShadowPage.

        DbgPrint("[stub] Allocated %Iu bytes for %s at %p\n",
            Size, FunctionName ? FunctionName : "unknown", result);
        return result;
    }

    KeReleaseSpinLock(&g_StubPool.PoolLock, oldIrql);
    return NULL;
}

/* ========= SAFE Self-Contained RWX Handlers (Simple Jump Approach) ========= */

static VOID EmitJumpStub(PUCHAR dest, UINT64 targetAddr)
{
    dest[0] = 0x48; dest[1] = 0xB8;    // mov rax, imm64
    *(UINT64*)(dest + 2) = targetAddr;
    dest[10] = 0xFF; dest[11] = 0xE0;    // jmp rax
    dest[12] = 0x90; dest[13] = 0x90;    // nop nop
}

static __forceinline VOID AssertCodeSpace(size_t neededBytes)
{
    UNREFERENCED_PARAMETER(neededBytes);
    // Conservative bounds check using globals provided elsewhere in this file
    if (!gCodeWrite || !gCodeBase || !gCodeCapacity) return;
    SIZE_T used = (SIZE_T)(gCodeWrite - gCodeBase);
    (void)used; // Suppress unused variable warning in release builds
    NT_ASSERT(used + neededBytes <= gCodeCapacity);
}

static PVOID EmitAbsoluteCall(UCHAR** p, UINT64 target) {
    const SIZE_T kSizeAbsCall = 12; // mov rax,imm64 (10) + call rax (2)
    AssertCodeSpace(kSizeAbsCall);
    UCHAR* q = *p;
    q[0] = 0x48; q[1] = 0xB8; *(UINT64*)&q[2] = target;
    q[10] = 0xFF; q[11] = 0xD0;
    *p = q + kSizeAbsCall;
    return q;
}

static VOID EmitStackAlignmentAssert(UCHAR** p)
{
    const SIZE_T kSizeAssert = 13;
    AssertCodeSpace(kSizeAssert);
    UCHAR* q = *p;
    q[0] = 0x48; q[1] = 0x89; q[2] = 0xE0;
    q[3] = 0x48; q[4] = 0x83; q[5] = 0xE0; q[6] = 0x0F;
    q[7] = 0x48; q[8] = 0x85; q[9] = 0xC0;
    q[10] = 0x74; q[11] = 0x01;
    q[12] = 0xCC;
    *p = q + kSizeAssert;
}

// NEW: Minimal, Windows x64 ABI-compliant forwarder: sub rsp,28 / mov rax,target / call rax / add rsp,28 / ret
static PVOID EmitAbiForwarder(UCHAR** p, UINT64 targetFn)
{
    const SIZE_T sz = 4 /*sub*/ + 2 /*mov opcode*/ + 8 /*imm64*/ + 2 /*call rax*/ + 4 /*add*/ + 1 /*ret*/;
    AssertCodeSpace(sz);
    UCHAR* q = *p;
    // sub rsp, 0x28
    q[0] = 0x48; q[1] = 0x83; q[2] = 0xEC; q[3] = 0x28; q += 4;
    // mov rax, imm64
    q[0] = 0x48; q[1] = 0xB8; *(UINT64*)&q[2] = targetFn; q += 10;
    // call rax
    q[0] = 0xFF; q[1] = 0xD0; q += 2;
    // add rsp, 0x28
    q[0] = 0x48; q[1] = 0x83; q[2] = 0xC4; q[3] = 0x28; q += 4;
    // ret
    q[0] = 0xC3; q += 1;
    PVOID start = *p;
    *p = q;
    return start;
}

#ifdef DeviceCreate  // only defined when #included from SimpleSvm.cpp

// Emit CREATE handler (Windows ABI forward to DeviceCreate)
static PVOID EmitCreateForwardHandler(UCHAR** p) {
    return EmitAbiForwarder(p, (UINT64)(ULONG_PTR)DeviceCreate); // Forward to C handler (reason: avoid IRP field poking in asm, keep ABI strict)
}

// Emit CLOSE handler (Windows ABI forward to DeviceClose)
static PVOID EmitCloseForwardHandler(UCHAR** p) {
    return EmitAbiForwarder(p, (UINT64)(ULONG_PTR)DeviceClose);
}

// Emit CREATE/CLOSE handler
static PVOID EmitCreateCloseHandler(UCHAR** p) {
    // Deprecated: kept for compatibility; forward to DeviceCreate by default
    return EmitCreateForwardHandler(p);
}

// Emit CREATE handler (Windows ABI, direct complete IRP for handle creation)
static PVOID EmitCreateHandleHandler(UCHAR** p) {
    const SIZE_T kSz = 4 /*sub*/ + 7 /*status*/ + 12 /*info (64-bit zero/one)*/ + 3 /*mov rcx,rdx*/ + 5 /*mov edx,imm*/ + 12 /*abs call*/ + 5 /*mov eax,status*/ + 4 /*add*/ + 1 /*ret*/;
    AssertCodeSpace(kSz);

    UCHAR* start = *p;
    UCHAR* q = *p;

    // Prologue: shadow space + alignment (ABI compliant)
    q[0] = 0x48; q[1] = 0x83; q[2] = 0xEC; q[3] = 0x28; q += 4;        // sub rsp, 28h

    // Irp->IoStatus.Status = STATUS_SUCCESS
    q[0] = 0xC7; q[1] = 0x42; q[2] = 0x30; *(ULONG*)&q[3] = (ULONG)STATUS_SUCCESS; q += 7; // mov dword ptr [rdx+30h], STATUS_SUCCESS

    // Irp->IoStatus.Information = FILE_OPENED (1)   // Reason: for handle creation paths, set Information to FILE_OPENED
    q[0] = 0x48; q[1] = 0xC7; q[2] = 0x42; q[3] = 0x38; *(UINT32*)&q[4] = 1; q += 8;       // mov qword ptr [rdx+38h], 1

    // IoCompleteRequest(Irp, IO_NO_INCREMENT)
    q[0] = 0x48; q[1] = 0x89; q[2] = 0xD1; q += 3;                      // mov rcx, rdx
    q[0] = 0xBA; *(UINT32*)&q[1] = IO_NO_INCREMENT; q += 5;             // mov edx, IO_NO_INCREMENT (0)
    EmitAbsoluteCall(&q, (UINT64)(ULONG_PTR)gIoCompleteRequest);         // call IoCompleteRequest

    // Return STATUS_SUCCESS in EAX
    q[0] = 0xB8; *(ULONG*)&q[1] = (ULONG)STATUS_SUCCESS; q += 5;         // mov eax, STATUS_SUCCESS

    // Epilogue
    q[0] = 0x48; q[1] = 0x83; q[2] = 0xC4; q[3] = 0x28; q += 4;          // add rsp, 28h
    q[0] = 0xC3; q += 1;                                                 // ret

    *p = q;
    return start;
}

static PVOID EmitUnsupportedHandler(UCHAR** p) {
    // Size estimate (conservative)
    const SIZE_T kSz = 4 /*sub*/ + 13 /*assert*/ + 7 /*mov [rdx+30],status*/ + 8 /*mov [rdx+38],0*/ +
        3 /*mov rcx,rdx*/ + 5 /*mov edx,imm32*/ + 12 /*abs call*/ + 5 /*mov eax,status*/ + 4 /*add*/ + 1 /*ret*/;
    AssertCodeSpace(kSz);

    UCHAR* start = *p;
    UCHAR* q = *p;

    // Prologue
    q[0] = 0x48; q[1] = 0x83; q[2] = 0xEC; q[3] = 0x28; q += 4;
    EmitStackAlignmentAssert(&q);

    // IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST (Irp in RDX)
    q[0] = 0xC7; q[1] = 0x42; q[2] = 0x30; *(ULONG*)&q[3] = (ULONG)STATUS_INVALID_DEVICE_REQUEST; q += 7;
    // IoStatus.Information = 0
    q[0] = 0x48; q[1] = 0xC7; q[2] = 0x42; q[3] = 0x38; *(UINT32*)&q[4] = 0; q += 8;

    // Prepare IoCompleteRequest(IRP, IO_NO_INCREMENT)
    q[0] = 0x48; q[1] = 0x89; q[2] = 0xD1; q += 3;                 // mov rcx, rdx
    q[0] = 0xBA; *(UINT32*)&q[1] = IO_NO_INCREMENT; q += 5;         // mov edx, IO_NO_INCREMENT
    EmitAbsoluteCall(&q, (UINT64)(ULONG_PTR)gIoCompleteRequest);

    // Return status in eax
    q[0] = 0xB8; *(ULONG*)&q[1] = (ULONG)STATUS_INVALID_DEVICE_REQUEST; q += 5;  // mov eax, STATUS_INVALID_DEVICE_REQUEST

    // Epilogue
    q[0] = 0x48; q[1] = 0x83; q[2] = 0xC4; q[3] = 0x28; q += 4;    // add rsp, 0x28
    q[0] = 0xC3; q += 1;                                           // ret

    *p = q;
    return start;
}

static PVOID EmitIoctlForwardHandler(UCHAR** p) {
    // Forward to IoctlDispatch with strict ABI compliance
    return EmitAbiForwarder(p, (UINT64)(ULONG_PTR)IoctlDispatch);
}

// SAFE: Revert to simple jump stubs that call original functions (safer approach)
static BOOLEAN CreateRwxHandlers() {
    DbgPrint("[rwx-handlers] Creating MINIMAL jump stubs for perfect ABI transparency...\n");

    // Simple absolute jump stubs (mov rax, imm64; jmp rax) - no stack manipulation at all
    // This is the SAFEST approach for Windows ABI compliance

#define EMIT_JMP_STUB(globalPtr, targetFn, typeName)                               \
    (globalPtr) = AllocateStubFromPool(14, STUB_TYPE_IOCTL, typeName "Jmp");    \
    if (globalPtr) {                                                             \
        RegisterNptShadowPage(globalPtr, (UINT64)(ULONG_PTR)(targetFn));        \
        DbgPrint("[rwx-handlers] " typeName " stub at %p -> %p\n",              \
                 (globalPtr), (PVOID)(targetFn));                                 \
    }

    EMIT_JMP_STUB(g_RwxDeviceCreate, DeviceCreate, "DeviceCreate")
        EMIT_JMP_STUB(g_RwxDeviceClose, DeviceClose, "DeviceClose")
        EMIT_JMP_STUB(g_RwxIoctlDispatch, IoctlDispatch, "IoctlDispatch")
        EMIT_JMP_STUB(g_RwxUnSupportedIO, UnSupportedIO, "UnSupportedIO")
        EMIT_JMP_STUB(g_RwxDriverUnload, DriverUnload, "DriverUnload")

        BOOLEAN success = (g_RwxDeviceCreate && g_RwxDeviceClose && g_RwxUnSupportedIO &&
            g_RwxIoctlDispatch && g_RwxDriverUnload);

    if (success) {
        DbgPrint("[rwx-handlers] ========== MINIMAL JMP RWX HANDLERS ==========\n");
        DbgPrint("[rwx-handlers] DeviceCreate:   %p (JMP->%p)\n", g_RwxDeviceCreate, DeviceCreate);
        DbgPrint("[rwx-handlers] DeviceClose:    %p (JMP->%p)\n", g_RwxDeviceClose, DeviceClose);
        DbgPrint("[rwx-handlers] UnSupportedIO:  %p (JMP->%p)\n", g_RwxUnSupportedIO, UnSupportedIO);
        DbgPrint("[rwx-handlers] IoctlDispatch:  %p (JMP->%p)\n", g_RwxIoctlDispatch, IoctlDispatch);
        DbgPrint("[rwx-handlers] DriverUnload:   %p (JMP->%p)\n", g_RwxDriverUnload, DriverUnload);
        DbgPrint("[rwx-handlers] \n");
        DbgPrint("[rwx-handlers] ARCHITECTURE: Minimal JMP stubs only\n");
        DbgPrint("[rwx-handlers] - NO stack manipulation in RWX code\n");
        DbgPrint("[rwx-handlers] - NO IRQL issues from RWX stubs\n");
        DbgPrint("[rwx-handlers] - Perfect Windows ABI transparency\n");
        DbgPrint("[rwx-handlers] - All IRP completion in stable C code\n");
        DbgPrint("[rwx-handlers] ============================================\n");
    }
    else {

        DbgPrint("[rwx-handlers] FAILED: Could not allocate minimal JMP handlers\n");
    }

    return success;
}

#endif // DeviceCreate

/* ========= Support Functions ========= */
static BOOLEAN FlipPteToRXAndClearDirty(PVOID VirtualAddress, ULONG64 CR3) {
    if (!IsDriverActive()) return FALSE;

    PPTE_64 leaf = GetPTEAddress(VirtualAddress, CR3);
    if (!leaf || !leaf->Present) return FALSE;

    leaf->Write = 0;   // back to read-only
    leaf->NoExecute = 0;   // keep executable
    leaf->Dirty = 0;   // hide stub write from MiMappedPageWriter
    __invlpg(VirtualAddress);
    return TRUE;
}

static NTSTATUS RestorePagesToRXAndClearDirty(VOID)
{
    if (!IsDriverActive())
        return STATUS_UNSUCCESSFUL;

    ULONG64 cr3 = __readcr3();
    ULONG ok = 0, fail = 0;

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_StubPool.PoolLock, &oldIrql);

    for (ULONG i = 0; i < g_StubPool.PoolPageCount; i++)
    {
        PVOID page = g_StubPool.PoolPages[i];
        if (!page) continue;

        // Release lock around PTE walk (can't hold spinlock during memory ops).
        KeReleaseSpinLock(&g_StubPool.PoolLock, oldIrql);
        if (FlipPteToRXAndClearDirty(page, cr3)) ok++;
        else fail++;
        KeAcquireSpinLock(&g_StubPool.PoolLock, &oldIrql);
    }

    KeReleaseSpinLock(&g_StubPool.PoolLock, oldIrql);

    DbgPrint("[restore] %lu pages restored to R+X (Dirty=0), %lu failures\n", ok, fail);
    return fail == 0 ? STATUS_SUCCESS : STATUS_PARTIAL_COPY;
}