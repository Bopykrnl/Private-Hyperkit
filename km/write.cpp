
#pragma once
#include "Svmkm.hpp"

namespace request
{
    // Physical write: map each target page via MmGetVirtualForPhysical and
    // copy directly. No MmCopyVirtualMemory — zero Windows memory manager
    // involvement, no ETW trace, no AC-hookable export.
    _declspec(noinline) NTSTATUS write_memory(invoke_data* request)
    {
        write_invoke data = {};

        if (!modules::safe_copy(&data, request->data, sizeof(write_invoke)))
            return STATUS_INVALID_PARAMETER;

        if (!data.address || !data.pid || !data.buffer || !data.size
            || data.address >= 0x7FFFFFFFFFFF)
            return STATUS_INVALID_PARAMETER;

        PEPROCESS process = nullptr;
        if (!NT_SUCCESS(qtx_import(PsLookupProcessByProcessId)(
                (HANDLE)data.pid, &process)))
            return STATUS_NOT_FOUND;

        // Grab the target DTB directly from EPROCESS.DirectoryTableBase (+0x28)
        PHYSICAL_ADDRESS dtbPhys;
        dtbPhys.QuadPart = 0x28;   // used as offset below, not a real PA
        uintptr_t targetDtb = 0;
        {
            PHYSICAL_ADDRESS eproc;
            eproc.QuadPart = (LONGLONG)MmGetPhysicalAddress((PVOID)((ULONG_PTR)process + 0x28)).QuadPart;
            // Read DirectoryTableBase directly from physical EPROCESS
            PVOID dtbVA = MmGetVirtualForPhysical(
                MmGetPhysicalAddress((PVOID)((ULONG_PTR)process + 0x28)));
            if (dtbVA)
                targetDtb = *(uintptr_t*)dtbVA;
        }

        if (!targetDtb)
        {
            qtx_import(ObfDereferenceObject)(process);
            return STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status   = STATUS_SUCCESS;
        SIZE_T   remaining = data.size;
        uintptr_t srcVA   = (uintptr_t)data.buffer;
        uintptr_t dstVA   = data.address;

        while (remaining > 0)
        {
            uintptr_t targetPA = translate_linear(targetDtb, dstVA);
            if (!targetPA) { status = STATUS_ACCESS_VIOLATION; break; }

            // How many bytes until the end of this physical page
            SIZE_T chunk = PAGE_SIZE - (targetPA & 0xFFF);
            if (chunk > remaining) chunk = remaining;

            // Get a kernel VA that maps this physical page
            PHYSICAL_ADDRESS pa;
            pa.QuadPart = (LONGLONG)(targetPA & ~(uintptr_t)0xFFF);
            PVOID pageKVA = MmGetVirtualForPhysical(pa);
            if (!pageKVA) { status = STATUS_UNSUCCESSFUL; break; }

            ULONG_PTR dstKVA = (ULONG_PTR)pageKVA + (targetPA & 0xFFF);

            __try {
                RtlCopyMemory((PVOID)dstKVA, (PVOID)srcVA, chunk);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            srcVA     += chunk;
            dstVA     += chunk;
            remaining -= chunk;
        }

        qtx_import(ObfDereferenceObject)(process);
        return status;
    }
}
