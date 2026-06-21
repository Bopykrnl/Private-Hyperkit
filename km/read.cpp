#pragma once
#include "Svmkm.hpp"

// Forward declaration — defined in pebwalk.cpp which is included after read.cpp
// in the single-TU build order.
static uintptr_t GetModuleBaseByPid(HANDLE pid, const WCHAR* moduleName);

namespace request
{
    auto read_physical(
        uintptr_t address,
        PVOID buffer,
        size_t size,
        size_t* bytes) -> NTSTATUS
    {
        MM_COPY_ADDRESS target_address = { 0 };
        target_address.PhysicalAddress.QuadPart = address;
        return qtx_import(MmCopyMemory)(buffer, target_address, size, MM_COPY_MEMORY_PHYSICAL, bytes);
    }

    auto read_virtual(
        uintptr_t address,
        PVOID buffer,
        size_t size,
        size_t* bytes) -> NTSTATUS
    {
        MM_COPY_ADDRESS target_address = { 0 };
        target_address.PhysicalAddress.QuadPart = address;
        return qtx_import(MmCopyMemory)(buffer, target_address, size, MM_COPY_MEMORY_VIRTUAL, bytes);
    }

    template <class t>
    t read_kernel_virtual(uintptr_t address) {

        t response{ };

        size_t bytes;
        read_virtual(
            address,
            &response,
            sizeof(t),
            &bytes
        );

        return response;
    }

    auto translate_linear(
        uintptr_t directory_base,
        uintptr_t address) -> uintptr_t {

        directory_base &= ~0xf;

        auto virt_addr = address & ~(~0ul << 12);
        auto pte = ((address >> 12) & (0x1ffll));
        auto pt = ((address >> 21) & (0x1ffll));
        auto pd = ((address >> 30) & (0x1ffll));
        auto pdp = ((address >> 39) & (0x1ffll));
        auto p_mask = ((~0xfull << 8) & 0xfffffffffull);

        size_t readsize = 0;
        uintptr_t pdpe = 0;
        read_physical(directory_base + 8 * pdp, &pdpe, sizeof(pdpe), &readsize);
        if (~pdpe & 1) {
            return 0;
        }

        uintptr_t pde = 0;
        read_physical((pdpe & p_mask) + 8 * pd, &pde, sizeof(pde), &readsize);
        if (~pde & 1) {
            return 0;
        }

        /* 1GB large page, use pde's 12-34 bits */
        if (pde & 0x80)
            return (pde & (~0ull << 42 >> 12)) + (address & ~(~0ull << 30));

        uintptr_t pteAddr = 0;
        read_physical((pde & p_mask) + 8 * pt, &pteAddr, sizeof(pteAddr), &readsize);
        if (~pteAddr & 1) {
            return 0;
        }

        /* 2MB large page */
        if (pteAddr & 0x80) {
            return (pteAddr & p_mask) + (address & ~(~0ull << 21));
        }

        address = 0;
        read_physical((pteAddr & p_mask) + 8 * pte, &address, sizeof(address), &readsize);
        address &= p_mask;

        if (!address) {
            return 0;
        }

        return address + virt_addr;
    }

    auto find_min(INT32 g, SIZE_T f) -> ULONG64
    {
        INT32 h = (INT32)f;
        ULONG64 result = 0;

        result = (((g) < (h)) ? (g) : (h));

        return result;
    }

    auto translate_address(invoke_data* request) -> driver::status
    {
        translate_invoke data = { 0 };

        if (!modules::safe_copy(
            &data,
            request->data,
            sizeof(translate_invoke))) {
            return driver::status::failed_sanity_check;
        }

        if (!data.virtual_address || !data.directory_base)
            return driver::status::failed_sanity_check;

        auto physical_address = translate_linear(
            data.directory_base,
            data.virtual_address);
        if (!physical_address) {
            return driver::status::failed_sanity_check;
        }

        reinterpret_cast<translate_invoke*> (request->data)->physical_address =
            reinterpret_cast<void*>(physical_address);

        return driver::status::successful_operation;
    }

    auto mm_copy_kernel(invoke_data* request) -> driver::status
    {
        read_kernel_invoke data = { 0 };
        size_t bytes = 0;

        if (!modules::safe_copy(
            &data,
            request->data,
            sizeof(read_kernel_invoke))) {
            return driver::status::failed_sanity_check;
        }

        auto result = STATUS_SUCCESS;

        switch (data.memory_type) {

        case MM_COPY_MEMORY_PHYSICAL:
        {
            result = read_physical(
                data.address,
                data.buffer,
                data.size,
                &bytes
            );

            break;
        }

        case MM_COPY_MEMORY_VIRTUAL:
        {
            result = read_virtual(
                data.address,
                data.buffer,
                data.size,
                &bytes
            );

            break;
        }

        default: {
            break;
        }

        }

        if (!NT_SUCCESS(result)) {
            return driver::status::failed_sanity_check;
        }

        return driver::status::successful_operation;
    }

    auto get_dtb(invoke_data* request) -> driver::status
    {
        dtb_invoke data = { 0 };

        if (!modules::safe_copy(
            &data,
            request->data,
            sizeof(dtb_invoke))) {
            return driver::status::failed_sanity_check;
        }

        auto* output = reinterpret_cast<dtb_invoke*>(request->data);
        output->dtb = 0;

        if (data.pid == 0 || data.pid > MAXULONG) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "SimpleSvm: GET_DTB rejected invalid PID 0x%llX\n",
                static_cast<ULONG64>(data.pid));
            return static_cast<driver::status>(STATUS_INVALID_PARAMETER);
        }

        PEPROCESS process = nullptr;
        const NTSTATUS lookupStatus = qtx_import(PsLookupProcessByProcessId)(
            reinterpret_cast<HANDLE>(data.pid),
            &process);
        if (!NT_SUCCESS(lookupStatus) || process == nullptr) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "SimpleSvm: GET_DTB PsLookupProcessByProcessId failed "
                "PID=%llu status=0x%08X\n",
                static_cast<ULONG64>(data.pid),
                static_cast<ULONG>(lookupStatus));
            return static_cast<driver::status>(lookupStatus);
        }

        // DirectoryTableBase is at 0x28 in the native x64 EPROCESS layout.
        // Do not fall back to a build-dependent field: returning unrelated
        // EPROCESS data as a CR3 makes every later translation unsafe.
        uintptr_t process_dtb = 0;
        SIZE_T bytes = 0;
        const NTSTATUS readStatus = read_virtual(
            reinterpret_cast<uintptr_t>(process) + 0x28,
            &process_dtb,
            sizeof(process_dtb),
            &bytes);

        if (!NT_SUCCESS(readStatus) ||
            bytes != sizeof(process_dtb) ||
            process_dtb == 0) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "SimpleSvm: GET_DTB DirectoryTableBase read failed "
                "PID=%llu status=0x%08X bytes=%llu dtb=0x%llX\n",
                static_cast<ULONG64>(data.pid),
                static_cast<ULONG>(readStatus),
                static_cast<ULONG64>(bytes),
                static_cast<ULONG64>(process_dtb));
            qtx_import(ObfDereferenceObject)(process);
            return driver::status::failed_sanity_check;
        }

        output->dtb = process_dtb;

        qtx_import(ObfDereferenceObject)(process);
        return driver::status::successful_operation;
    }

    // now we are acc reading physical,
    // if the read fails the sanity check failed
    auto read_memory(invoke_data* request) -> driver::status
    {
        read_invoke data = { 0 };

        if (!modules::safe_copy(
            &data,
            request->data,
            sizeof(read_invoke))) {
            return driver::status::failed_sanity_check;
        }

        if (data.address >= 0x7FFFFFFFFFFF) {
            return driver::status::failed_sanity_check;
        }

        PEPROCESS process = 0;
        if (!NT_SUCCESS(qtx_import(PsLookupProcessByProcessId)(
            reinterpret_cast<HANDLE>(data.pid),
            &process))) {
            return driver::status::failed_sanity_check;
        }

        NTSTATUS  status = STATUS_SUCCESS;
        SIZE_T    remaining = data.size;
        uintptr_t srcVA = data.address;
        uintptr_t dstVA = (uintptr_t)data.buffer;

        while (remaining > 0)
        {
            auto physical_address = translate_linear(data.dtb, srcVA);
            if (!physical_address) {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            // Bytes available until end of this physical page
            SIZE_T chunk = PAGE_SIZE - (physical_address & 0xFFF);
            if (chunk > remaining) chunk = remaining;

            size_t bytes = 0;
            if (!NT_SUCCESS(read_physical(physical_address, reinterpret_cast<PVOID>(dstVA), chunk, &bytes)))
            {
                status = STATUS_UNSUCCESSFUL;
                break;
            }

            srcVA += chunk;
            dstVA += chunk;
            remaining -= chunk;
        }

        qtx_import(ObfDereferenceObject)(process);
        return NT_SUCCESS(status)
            ? driver::status::successful_operation
            : driver::status::failed_sanity_check;
    }

    auto get_module_base(invoke_data* request) -> driver::status
    {
        get_module_base_invoke data = {};

        if (!modules::safe_copy(&data, request->data, sizeof(get_module_base_invoke)))
            return driver::status::failed_sanity_check;

        data.module_name[127] = L'\0';

        data.module_base = GetModuleBaseByPid(
            reinterpret_cast<HANDLE>(data.pid),
            data.module_name);

        if (!modules::safe_copy(request->data, &data, sizeof(get_module_base_invoke)))
            return driver::status::failed_sanity_check;

        return data.module_base
            ? driver::status::successful_operation
            : driver::status::failed_sanity_check;
    }
}
