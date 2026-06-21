// pebwalk.cpp - included as part of the SimpleSvm.cpp single-TU build.
// Resolves a module base by attaching to the target process and walking the
// native 64-bit PEB loader list.  No EPROCESS or CR3 offsets are hard coded.

typedef PVOID(NTAPI* PFN_PS_GET_PROCESS_PEB)(
    _In_ PEPROCESS Process);

typedef struct _SVM_PEB_LDR_DATA64
{
    ULONG Length;
    BOOLEAN Initialized;
    UCHAR Padding0[3];
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} SVM_PEB_LDR_DATA64, * PSVM_PEB_LDR_DATA64;

typedef struct _SVM_LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    ULONG Padding0;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} SVM_LDR_DATA_TABLE_ENTRY64, * PSVM_LDR_DATA_TABLE_ENTRY64;

typedef struct _SVM_PEB64
{
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG Padding0;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PSVM_PEB_LDR_DATA64 Ldr;
} SVM_PEB64, * PSVM_PEB64;

static_assert(FIELD_OFFSET(SVM_PEB64, Ldr) == 0x18,
    "Unexpected native PEB.Ldr layout");
static_assert(FIELD_OFFSET(SVM_PEB_LDR_DATA64, InMemoryOrderModuleList) == 0x20,
    "Unexpected native PEB_LDR_DATA layout");
static_assert(FIELD_OFFSET(SVM_LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks) == 0x10,
    "Unexpected native LDR_DATA_TABLE_ENTRY layout");
static_assert(FIELD_OFFSET(SVM_LDR_DATA_TABLE_ENTRY64, DllBase) == 0x30,
    "Unexpected native LDR_DATA_TABLE_ENTRY.DllBase layout");

// The UNICODE_STRING descriptor is copied to kernel stack before this helper is
// called.  Only Buffer points into the attached process.
static BOOLEAN SvCopyAttachedUnicodeString(
    _In_ const UNICODE_STRING* Source,
    _Out_writes_(DestinationChars) WCHAR* Destination,
    _In_ SIZE_T DestinationChars)
{
    if (!Source || !Destination || DestinationChars == 0)
        return FALSE;

    Destination[0] = L'\0';

    if (!Source->Buffer || Source->Length == 0 ||
        (Source->Length & (sizeof(WCHAR) - 1)) != 0 ||
        Source->Length > Source->MaximumLength)
    {
        return FALSE;
    }

    SIZE_T chars = Source->Length / sizeof(WCHAR);
    if (chars >= DestinationChars)
        chars = DestinationChars - 1;

    const SIZE_T bytes = chars * sizeof(WCHAR);
    __try
    {
        ProbeForRead(Source->Buffer, bytes, sizeof(WCHAR));
        RtlCopyMemory(Destination, Source->Buffer, bytes);
        Destination[chars] = L'\0';
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Destination[0] = L'\0';
        return FALSE;
    }
}

static PFN_PS_GET_PROCESS_PEB SvResolvePsGetProcessPeb(VOID)
{
    UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"PsGetProcessPeb");
    return reinterpret_cast<PFN_PS_GET_PROCESS_PEB>(
        MmGetSystemRoutineAddress(&routineName));
}

// Public entry point used by request::get_module_base.  The IOCTL ABI remains
// unchanged: return the requested module's DllBase, or zero on failure.
static uintptr_t GetModuleBaseByPid(HANDLE pid, const WCHAR* moduleName)
{
    if (!pid || !moduleName || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return 0;

    WCHAR requestedName[128] = {};
    __try
    {
        wcsncpy(requestedName, moduleName, RTL_NUMBER_OF(requestedName) - 1);
        requestedName[RTL_NUMBER_OF(requestedName) - 1] = L'\0';
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return 0;
    }

    if (requestedName[0] == L'\0')
        return 0;

    PFN_PS_GET_PROCESS_PEB getProcessPeb = SvResolvePsGetProcessPeb();
    if (!getProcessPeb)
        return 0;

    PEPROCESS process = nullptr;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)) || !process)
        return 0;

    uintptr_t result = 0;
    KAPC_STATE apcState = {};
    BOOLEAN attached = FALSE;

    __try
    {
        PSVM_PEB64 peb = static_cast<PSVM_PEB64>(getProcessPeb(process));
        if (!peb)
            __leave;

        KeStackAttachProcess(reinterpret_cast<PRKPROCESS>(process), &apcState);
        attached = TRUE;

        PSVM_PEB_LDR_DATA64 ldr = nullptr;
        __try
        {
            ProbeForRead(peb, sizeof(*peb), __alignof(SVM_PEB64));
            ldr = peb->Ldr;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            ldr = nullptr;
        }

        if (!ldr)
            __leave;

        LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
        LIST_ENTRY* link = nullptr;
        __try
        {
            ProbeForRead(ldr, sizeof(*ldr), __alignof(SVM_PEB_LDR_DATA64));
            if (!ldr->Initialized)
                __leave;
            link = head->Flink;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            link = nullptr;
        }

        for (ULONG iteration = 0;
             link && link != head && iteration < 1024;
             iteration++)
        {
            PSVM_LDR_DATA_TABLE_ENTRY64 userEntry = CONTAINING_RECORD(
                link,
                SVM_LDR_DATA_TABLE_ENTRY64,
                InMemoryOrderLinks);

            SVM_LDR_DATA_TABLE_ENTRY64 entry = {};
            __try
            {
                ProbeForRead(userEntry, sizeof(*userEntry),
                    __alignof(SVM_LDR_DATA_TABLE_ENTRY64));
                RtlCopyMemory(&entry, userEntry, sizeof(entry));
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                break;
            }

            // Save the next link before touching the name buffer.  The loader
            // list is user-owned and may change while it is being inspected.
            link = entry.InMemoryOrderLinks.Flink;

            if (!entry.DllBase || entry.SizeOfImage == 0 ||
                entry.SizeOfImage >= 0x50000000UL)
            {
                continue;
            }

            WCHAR currentName[128] = {};
            if (SvCopyAttachedUnicodeString(
                    &entry.BaseDllName,
                    currentName,
                    RTL_NUMBER_OF(currentName)) &&
                _wcsicmp(currentName, requestedName) == 0)
            {
                result = reinterpret_cast<uintptr_t>(entry.DllBase);
                break;
            }
        }
    }
    __finally
    {
        if (attached)
            KeUnstackDetachProcess(&apcState);
        ObDereferenceObject(process);
    }

    return result;
}
