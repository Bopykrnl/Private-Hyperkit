#pragma once
#include <ntifs.h>
#include <ntimage.h>
#include <string.h>

// RtlPcToFileHeader is exported by ntoskrnl but not declared in all WDK headers
extern "C" NTKERNELAPI PVOID RtlPcToFileHeader(PVOID PcValue, PVOID* BaseOfImage);

//
// Device and symbolic link names for the IOCTL interface.
//
#define SVM_DEVICE_NAME         L"\\Device\\SimpleSvm"
#define SVM_SYMBOLIC_LINK_NAME  L"\\DosDevices\\SimpleSvm"

//
// IOCTL codes for each mapping operation.
// Method: METHOD_BUFFERED, Access: FILE_ANY_ACCESS
//
#define IOCTL_READ_MEMORY       CTL_CODE(0x8000, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_MEMORY      CTL_CODE(0x8000, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TRANSLATE_ADDRESS CTL_CODE(0x8000, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MM_COPY_KERNEL    CTL_CODE(0x8000, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_DTB           CTL_CODE(0x8000, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_INJECT_PML4       CTL_CODE(0x8000, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_MODULE_BASE   CTL_CODE(0x8000, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DUMP_SHADOW_TRACE CTL_CODE(0x8000, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DUMP_MCA_BANKS    CTL_CODE(0x8000, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef NTSTATUS (NTAPI* PFN_IoCreateDriver)(
    _In_opt_ PUNICODE_STRING DriverName,
    _In_ PDRIVER_INITIALIZE InitializationFunction
);
typedef NTSTATUS (NTAPI* PFN_MmCopyVirtualMemory)(
    _In_  PEPROCESS SourceProcess,
    _In_  PVOID     SourceAddress,
    _In_  PEPROCESS TargetProcess,
    _Out_ PVOID     TargetAddress,
    _In_  SIZE_T    BufferSize,
    _In_  KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T   ReturnSize
);
// RtlAddFunctionTable is exported by ntoskrnl but not declared in km headers.
typedef BOOLEAN (NTAPI* PFN_RtlAddFunctionTable)(
    _In_ PVOID  FunctionTable,
    _In_ ULONG  EntryCount,
    _In_ ULONG64 BaseAddress
);

inline PFN_IoCreateDriver        g_IoCreateDriver        = nullptr;
inline PFN_MmCopyVirtualMemory   g_MmCopyVirtualMemory   = nullptr;
inline PFN_RtlAddFunctionTable   g_RtlAddFunctionTable   = nullptr;

//
// Inline wrapper so qtx_import(MmCopyVirtualMemory) resolves to the
// runtime-resolved pointer while all other qtx_import(x) calls go
// directly to the named kernel export.
//
inline NTSTATUS MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID     SourceAddress,
    PEPROCESS TargetProcess,
    PVOID     TargetAddress,
    SIZE_T    BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T   ReturnSize
)
{
    return g_MmCopyVirtualMemory(SourceProcess, SourceAddress, TargetProcess,
                                 TargetAddress, BufferSize, PreviousMode,
                                 ReturnSize);
}

inline NTSTATUS SvkmResolveImports()
{
    UNICODE_STRING name;

    RtlInitUnicodeString(&name, L"IoCreateDriver");
    g_IoCreateDriver = reinterpret_cast<PFN_IoCreateDriver>(
        MmGetSystemRoutineAddress(&name));
    if (!g_IoCreateDriver)
        return STATUS_NOT_FOUND;

    RtlInitUnicodeString(&name, L"MmCopyVirtualMemory");
    g_MmCopyVirtualMemory = reinterpret_cast<PFN_MmCopyVirtualMemory>(
        MmGetSystemRoutineAddress(&name));
    if (!g_MmCopyVirtualMemory)
        return STATUS_NOT_FOUND;

    // RtlAddFunctionTable is NOT on MmGetSystemRoutineAddress's whitelist so we
    // must find it by walking ntoskrnl's export directory manually.
    // Strategy: use RtlPcToFileHeader on a known ntoskrnl symbol to get the
    // image base, then parse the PE export table.
    {
        PVOID imageBase = nullptr;
        RtlPcToFileHeader(reinterpret_cast<PVOID>(MmGetSystemRoutineAddress), &imageBase);
        if (imageBase)
        {
            PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(imageBase);
            PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(
                reinterpret_cast<ULONG_PTR>(imageBase) + dos->e_lfanew);
            auto& expDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (expDir.VirtualAddress && expDir.Size)
            {
                PIMAGE_EXPORT_DIRECTORY exp = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
                    reinterpret_cast<ULONG_PTR>(imageBase) + expDir.VirtualAddress);
                PULONG  names   = reinterpret_cast<PULONG>(
                    reinterpret_cast<ULONG_PTR>(imageBase) + exp->AddressOfNames);
                PUSHORT ordinals = reinterpret_cast<PUSHORT>(
                    reinterpret_cast<ULONG_PTR>(imageBase) + exp->AddressOfNameOrdinals);
                PULONG  funcs   = reinterpret_cast<PULONG>(
                    reinterpret_cast<ULONG_PTR>(imageBase) + exp->AddressOfFunctions);
                for (ULONG i = 0; i < exp->NumberOfNames; i++)
                {
                    PCSTR fnName = reinterpret_cast<PCSTR>(
                        reinterpret_cast<ULONG_PTR>(imageBase) + names[i]);
                    if (strcmp(fnName, "RtlAddFunctionTable") == 0)
                    {
                        g_RtlAddFunctionTable = reinterpret_cast<PFN_RtlAddFunctionTable>(
                            reinterpret_cast<ULONG_PTR>(imageBase) + funcs[ordinals[i]]);
                        break;
                    }
                }
            }
        }
        DbgPrint("[SimpleSvm] RtlAddFunctionTable resolved: %p\n",
                 reinterpret_cast<PVOID>(g_RtlAddFunctionTable));
    }

    return STATUS_SUCCESS;
}

//
// Simple import macro - resolves directly to the kernel function
//
#define qtx_import(x) x

//
// Debug print helpers
//
#define print_dbg(x) DbgPrint(x)
#define _(x) (x)

//
// Driver status codes
//
namespace driver
{
    enum status : NTSTATUS
    {
        successful_operation = STATUS_SUCCESS,
        failed_sanity_check = STATUS_UNSUCCESSFUL,
    };
}

//
// Request invoke structures
//

struct invoke_data
{
    PVOID data;
};

struct write_invoke
{
    uintptr_t   address;
    uintptr_t   pid;
    PVOID       buffer;
    SIZE_T      size;
};

struct read_invoke
{
    uintptr_t   address;
    uintptr_t   pid;
    uintptr_t   dtb;
    PVOID       buffer;
    SIZE_T      size;
};

struct translate_invoke
{
    uintptr_t   virtual_address;
    uintptr_t   directory_base;
    void* physical_address;
};

struct read_kernel_invoke
{
    uintptr_t   address;
    void* buffer;
    SIZE_T      size;
    ULONG       memory_type;
};

struct dtb_invoke
{
    uintptr_t   pid;
    uintptr_t   dtb;
};

//
// PML4 injection — allocate physically-resident pages, inject a free PML4
// slot into the target process, and copy the caller's payload in.
// The resulting VA (in target's address space) is written back to injected_va.
// No VAD entry is created; the allocation is invisible to NtQueryVirtualMemory.
//
struct pml4_inject_invoke
{
    uintptr_t   target_pid;     // [in]  PID of target process
    uintptr_t   payload_buffer; // [in]  kernel VA of payload to copy
    SIZE_T      payload_size;   // [in]  size in bytes (rounded up to pages)
    uintptr_t   injected_va;    // [out] VA in target's address space where payload appears
};

// PEB walk — resolve a module's DllBase VA in a target process entirely
// via physical memory reads (no KeStackAttachProcess, no AC-visible callstack).
struct get_module_base_invoke
{
    uintptr_t   pid;              // [in]  target process PID
    WCHAR       module_name[128]; // [in]  e.g. L"GameAssembly.dll"
    uintptr_t   module_base;      // [out] DllBase VA in target process, 0 on failure
};

//
// Module utilities
//
namespace modules
{
    inline bool safe_copy(void* dst, void* src, SIZE_T size)
    {
        __try
        {
            RtlCopyMemory(dst, src, size);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }
}