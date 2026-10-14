//本页负责动态解析回调
//ACE被TVM VM了内部没法静态解析
#include "SignCallBack.h"
#include "SignCallBackConfig.h"

extern PVOID 执念LookupKernelSymbol(_In_ PCSTR SymbolName);
extern BOOLEAN 执念IsAceAddress(PVOID Addr);

// ntoskrnl 范围
static PVOID g_NtBase = NULL;
static ULONG g_NtSize = 0;

typedef struct _执念_MOD_INFO2 {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} 执念_MOD_INFO2, *P执念_MOD_INFO2;

typedef struct _执念_MODS2 {
    ULONG NumberOfModules;
    执念_MOD_INFO2 Modules[1];
} 执念_MODS2, *P执念_MODS2;

EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG, PVOID, ULONG, PULONG);

static BOOLEAN 执念GetKernelRange(VOID)
{
    if (g_NtBase && g_NtSize)
        return TRUE;

    ULONG bufSize = 0;
    ZwQuerySystemInformation(11, NULL, 0, &bufSize);
    if (!bufSize) return FALSE;
    bufSize += 0x2000;

    P执念_MODS2 mods = (P执念_MODS2)ExAllocatePoolWithTag(NonPagedPool, bufSize, 执念_TAG);
    if (!mods) return FALSE;

    if (!NT_SUCCESS(ZwQuerySystemInformation(11, mods, bufSize, &bufSize))) {
        ExFreePoolWithTag(mods, 执念_TAG);
        return FALSE;
    }

    for (ULONG i = 0; i < mods->NumberOfModules; i++) {
        PCHAR n = (PCHAR)mods->Modules[i].FullPathName +
                  mods->Modules[i].OffsetToFileName;
        if (_stricmp(n, "ntoskrnl.exe") == 0 || _stricmp(n, "ntkrnlmp.exe") == 0) {
            g_NtBase = mods->Modules[i].ImageBase;
            g_NtSize = mods->Modules[i].ImageSize;
            break;
        }
    }

    ExFreePoolWithTag(mods, 执念_TAG);
    return g_NtBase != NULL;
}
static BOOLEAN 执念LooksLikeCallbackBlock(PVOID entry, _Out_ PVOID* OutFn)
{
    *OutFn = NULL;
    if (!entry) return FALSE;
    if (!MmIsAddressValid(entry)) return FALSE;

    __try {
        // 内核地址必须 >= 0xFFFF800000000000
        ULONG_PTR e = (ULONG_PTR)entry;
        if (e < 0xFFFF800000000000ULL)
            return FALSE;

        PVOID fn = *(PVOID*)((PUCHAR)entry + 0x08);
        if (!fn) return FALSE;

        ULONG_PTR f = (ULONG_PTR)fn;
        if (f < 0xFFFF800000000000ULL)
            return FALSE;
        if (!MmIsAddressValid(fn))
            return FALSE;

        *OutFn = fn;
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}
//暴力扫ntoskrnl内存
typedef struct _执念_FOUND_ARRAY {
    PVOID  Address;
    ULONG  TotalNonNull;
    ULONG  AceHits;
    ULONG  AceIndices[8];
    PVOID  AceFunctions[8];
} 执念_FOUND_ARRAY, *P执念_FOUND_ARRAY;

#define 执念_MAX_FOUND 16
static 执念_FOUND_ARRAY g_Found[执念_MAX_FOUND];
static ULONG g_FoundCount = 0;

ULONG 执念BruteForceScanArrays(VOID)
{
    if (!执念GetKernelRange()) {
        DbgPrint("[执念-RT] cannot get kernel range\n");
        return 0;
    }

    DbgPrint("[执念-RT] brute force scan: nt=%p size=0x%X\n", g_NtBase, g_NtSize);

    g_FoundCount = 0;

    PVOID* p = (PVOID*)g_NtBase;
    ULONG_PTR start = (ULONG_PTR)g_NtBase;
    ULONG_PTR end = start + g_NtSize;

    for (ULONG_PTR addr = start; addr + 512 <= end; addr += 8) {

        PVOID* arr = (PVOID*)addr;

        if (!MmIsAddressValid(arr))
            continue;

        ULONG nonNull = 0;
        ULONG aceHits = 0;
        ULONG aceIdx[8] = { 0 };
        PVOID aceFn[8] = { 0 };

        __try {
            for (ULONG i = 0; i < 64; i++) {
                PVOID entry = arr[i];
                if (!entry) continue;
                nonNull++;
                if (nonNull > 24) break;

                PVOID fn = NULL;
                if (执念LooksLikeCallbackBlock(entry, &fn)) {
                    if (执念IsAceAddress(fn) && aceHits < 8) {
                        aceIdx[aceHits] = i;
                        aceFn[aceHits] = fn;
                        aceHits++;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            continue;
        }

        if (aceHits >= 1 && nonNull >= 1 && nonNull <= 16) {
            if (g_FoundCount < 执念_MAX_FOUND) {
                P执念_FOUND_ARRAY f = &g_Found[g_FoundCount++];
                f->Address = arr;
                f->TotalNonNull = nonNull;
                f->AceHits = aceHits;
                for (ULONG k = 0; k < aceHits && k < 8; k++) {
                    f->AceIndices[k] = aceIdx[k];
                    f->AceFunctions[k] = aceFn[k];
                }
            }
        }
    }

    // 打印出来
    DbgPrint("[执念-RT] ===== brute force found %u candidate arrays =====\n", g_FoundCount);
    for (ULONG i = 0; i < g_FoundCount; i++) {
        P执念_FOUND_ARRAY f = &g_Found[i];
        DbgPrint("[执念-RT] [%u] array=%p nonNull=%u aceHits=%u\n",
                 i, f->Address, f->TotalNonNull, f->AceHits);
        for (ULONG k = 0; k < f->AceHits && k < 8; k++) {
            DbgPrint("[执念-RT]      idx=%u fn=%p\n", f->AceIndices[k], f->AceFunctions[k]);
        }
    }

    return g_FoundCount;
}

PVOID 执念GetFoundArray(_In_ ULONG Index, _Out_opt_ ULONG* OutAceHits)
{
    if (Index >= g_FoundCount) {
        if (OutAceHits) *OutAceHits = 0;
        return NULL;
    }
    if (OutAceHits) *OutAceHits = g_Found[Index].AceHits;
    return g_Found[Index].Address;
}

ULONG 执念GetFoundCount(VOID) { return g_FoundCount; }

// 比按「回调类型」分类: 不管他是哪个类型的回调
// 只要 block->Function 在 ACE模块范围内, 就换成 stub，让其不执行
extern PVOID 执念GetStubForTarget(_In_ 执念_TARGET Target);
extern 执念_SLOT g_执念Slots[执念_TARGET_COUNT];

NTSTATUS 执念NeutralizeByScan(VOID)
{
    ULONG found = 执念BruteForceScanArrays();
    if (found == 0) {
        DbgPrint("[执念-RT] no arrays found, cannot neutralize\n");
        return STATUS_NOT_FOUND;
    }

    ULONG total = 0;

    for (ULONG i = 0; i < found; i++) {
        P执念_FOUND_ARRAY f = &g_Found[i];

        for (ULONG k = 0; k < f->AceHits; k++) {
            PVOID entry = ((PVOID*)f->Address)[f->AceIndices[k]];
            if (!entry) continue;

            PVOID* fnField = (PVOID*)((PUCHAR)entry + 0x08);
            PVOID currentFn = *fnField;
            if (!执念IsAceAddress(currentFn)) continue;
            PVOID stub = 执念GetStubForTarget(执念_TARGET_LOAD_IMAGE);
            if (!stub) continue;

            __try {
                KIRQL irql = KeRaiseIrqlToDpcLevel();
                ULONG_PTR cr0 = __readcr0();
                __writecr0(cr0 & ~0x10000ULL);

                InterlockedExchangePointer(fnField, stub);

                __writecr0(cr0);
                KeLowerIrql(irql);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }

            DbgPrint("[执念-RT] neutralized: block=%p fn %p -> %p\n",
                     entry, currentFn, stub);
            total++;
        }
    }

    DbgPrint("[执念-RT] total neutralized = %u\n", total);
    return total ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}
static PVOID g_AceFns[32] = { 0 };
static ULONG g_AceFnCount = 0;

VOID 执念CollectAceFunctions(VOID)
{
    g_AceFnCount = 0;

    for (ULONG i = 0; i < g_FoundCount; i++) {
        P执念_FOUND_ARRAY f = &g_Found[i];
        for (ULONG k = 0; k < f->AceHits; k++) {
            if (g_AceFnCount < 32)
                g_AceFns[g_AceFnCount++] = f->AceFunctions[k];
        }
    }
    for (ULONG i = 0; i < g_AceFnCount; i++) {
        for (ULONG j = i + 1; j < g_AceFnCount; ) {
            if (g_AceFns[i] == g_AceFns[j]) {
                for (ULONG m = j; m + 1 < g_AceFnCount; m++)
                    g_AceFns[m] = g_AceFns[m + 1];
                g_AceFnCount--;
            } else {
                j++;
            }
        }
    }

    DbgPrint("[执念-RT] collected %u unique ACE callback functions:\n", g_AceFnCount);
    for (ULONG i = 0; i < g_AceFnCount; i++)
        DbgPrint("[执念-RT]   [%u] %p\n", i, g_AceFns[i]);
}

ULONG 执念GetAceFnCount(VOID) { return g_AceFnCount; }
PVOID 执念GetAceFn(_In_ ULONG Index)
{
    if (Index >= g_AceFnCount) return NULL;
    return g_AceFns[Index];
}
