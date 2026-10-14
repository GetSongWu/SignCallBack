//
#include "SignCallBack.h"
#include "SignCallBackConfig.h"
typedef struct _执念_SYM_RVA {
    PCWSTR Name;
    ULONG  Rva;
} 执念_SYM_RVA;

static const 执念_SYM_RVA g_SymRvas[] = {
    { L"PspLoadImageNotifyRoutine",     0x0F04980 },
    { L"PspCreateThreadNotifyRoutine",  0x0F04580 },
    { L"PspCreateProcessNotifyRoutine", 0x0F04780 },
    { L"ObpCallPreOperationCallbacks",  0x0826870 },
    { L"CallbackListHead",              0x0EF6CA0 },
};
#define 执念_SYM_COUNT (sizeof(g_SymRvas)/sizeof(g_SymRvas[0]))
#define 执念_CALLBACK_ARRAY_SIZE 64
// EX_CALLBACK_ROUTINE_BLOCK 里 Function 的偏移
#define 执念_BLOCK_FUNCTION_OFF  0x08
#define 执念_ENTRY_ALIGN_MASK    (~(ULONG_PTR)0xF)
#define 执念_BLOCK_OF(entry)  ((PVOID)((ULONG_PTR)(entry) & 执念_ENTRY_ALIGN_MASK))
//空stub函数
VOID 执念AceStubLoadImage(PUNICODE_STRING FullImageName, HANDLE ProcessId,
                         PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(FullImageName);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageInfo);
#if 执念_TRACE_CALLBACK_FIRE
    DbgPrint("[执念-FIRE] LoadImage stub hit (blocked ACE)\n");
#endif
}

// CreateProcess 回调 Ex: NTSTATUS (*)(PEPROCESS, HANDLE, PPS_CREATE_NOTIFY_INFO)
NTSTATUS 执念AceStubCreateProcessEx(PEPROCESS Process, HANDLE ProcessId,
                                   PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(CreateInfo);
#if 执念_TRACE_CALLBACK_FIRE
    DbgPrint("[执念-FIRE] CreateProcessEx stub hit (blocked ACE)\n");
#endif
    return STATUS_SUCCESS;
}

// CreateThread 回调: VOID (*)(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
VOID 执念AceStubCreateThread(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ThreadId);
    UNREFERENCED_PARAMETER(Create);
#if 执念_TRACE_CALLBACK_FIRE
    DbgPrint("[执念-FIRE] CreateThread stub hit (blocked ACE)\n");
#endif
}
extern PVOID 执念FindAceDriverBase(_Out_opt_ PULONG OutSize);
static PVOID g_AceBase = NULL;
static ULONG g_AceSize = 0;
// github已发布，不要被骗了
typedef struct _执念_SCRUB_TARGET {
    执念_TARGET Target;
    PCWSTR     Name;
    ULONG      SymRva;          // 数组在 ntoskrnl 里的 RVA
    PVOID      StubFunc;        // 用来替换的空函数
    BOOLEAN    Enabled;

    // 运行时
    PVOID      ArrayVa;         // 数组实际地址
    ULONG      HitIndex;        // 命中了下标
    PVOID      OriginalFunc;    // 原始函数指针 (用于还原)
    BOOLEAN    Scrubbed;
} 执念_SCRUB_TARGET, *P执念_SCRUB_TARGET;

static 执念_SCRUB_TARGET g_ScrubTargets[] = {
    {
        执念_TARGET_LOAD_IMAGE, L"LoadImage",
        0x0F04980, (PVOID)执念AceStubLoadImage,
        执念_TARGET_ENABLE_LOAD_IMAGE,
        NULL, 0xFFFFFFFF, NULL, FALSE
    },
    {
        执念_TARGET_CREATE_PROC, L"CreateProcessEx",
        0x0F04780, (PVOID)执念AceStubCreateProcessEx,
        执念_TARGET_ENABLE_CREATE_PROC,
        NULL, 0xFFFFFFFF, NULL, FALSE
    },
    {
        执念_TARGET_CREATE_THREAD, L"CreateThread",
        0x0F04580, (PVOID)执念AceStubCreateThread,
        执念_TARGET_ENABLE_CREATE_THREAD,
        NULL, 0xFFFFFFFF, NULL, FALSE
    },
};
#define 执念_SCRUB_COUNT (sizeof(g_ScrubTargets)/sizeof(g_ScrubTargets[0]))
BOOLEAN 执念GetSiteInfo(_In_ ULONG Index, _Out_ PULONG OutRva,
                       _Out_ PVOID* OutAddr, _Out_ PBOOLEAN OutValidated,
                       _Out_ PBOOLEAN OutPatched);
static ULONG 执念TargetToSiteIndex(执念_TARGET t)
{
    switch (t) {
    case 执念_TARGET_PROCESS_OB:  return 0;
    case 执念_TARGET_CREATE_PROC: return 1;
    case 执念_TARGET_LOAD_IMAGE:  return 2;
    case 执念_TARGET_REGISTRY:    return 3;
    case 执念_TARGET_SHUTDOWN:    return 4;
    default:                     return 0xFFFFFFFF;
    }
}
//本项目是开源的！如果你是被收费的骗了，请申请退款！
extern BOOLEAN 执念GetNtoskrnlRange(PVOID* OutBase, PULONG OutSize);
//全部遍历，找到ACE创建的回调替换成我们的stub
static NTSTATUS 执念ScrubOne(P执念_SCRUB_TARGET t, PVOID NtBase)
{
    if (!t->Enabled) {
        DbgPrint("[执念-SCRUB] %ws DISABLED by config\n", t->Name);
        return STATUS_NOT_SUPPORTED;
    }
    t->ArrayVa = (PVOID)((ULONG_PTR)NtBase + t->SymRva);
    DbgPrint("[执念-SCRUB] %ws array @ %p (RVA 0x%X)\n",
             t->Name, t->ArrayVa, t->SymRva);

    if (!MmIsAddressValid(t->ArrayVa)) {
        DbgPrint("[执念-SCRUB] %ws array NOT MAPPED\n", t->Name);
        return STATUS_INVALID_ADDRESS;
    }

    //取ACE回调地址
    ULONG siteIdx = 执念TargetToSiteIndex(t->Target);
    if (siteIdx == 0xFFFFFFFF) {
        DbgPrint("[执念-SCRUB] %ws no site index\n", t->Name);
        return STATUS_INVALID_PARAMETER;
    }

    ULONG   aceRva = 0;
    PVOID   aceAddr = NULL;
    BOOLEAN validated = FALSE, patched = FALSE;

    if (!执念GetSiteInfo(siteIdx, &aceRva, &aceAddr, &validated, &patched) ||
        !validated || !aceAddr) {
        DbgPrint("[执念-SCRUB] %ws ACE callback address not resolved\n", t->Name);
        return STATUS_NOT_FOUND;
    }

    DbgPrint("[执念-SCRUB] %ws looking for ACE callback %p\n", t->Name, aceAddr);
    {
        PUCHAR p = (PUCHAR)t->ArrayVa - 0x40;
        DbgPrint("[执念-SCRUB] --- memory dump around array (%p .. %p) ---\n",
                 p, p + 0x180);

        __try {
            for (ULONG off = 0; off < 0x180; off += 0x10) {
                if (!MmIsAddressValid(p + off)) {
                    DbgPrint("[执念-SCRUB]   +%03X  <not mapped>\n", off);
                    continue;
                }
                PULONG64 q = (PULONG64)(p + off);
                DbgPrint("[执念-SCRUB]   +%03X  %016llX %016llX\n",
                         off, q[0], q[1]);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[执念-SCRUB]   dump EXCEPTION 0x%08X\n", GetExceptionCode());
        }
        __try {
            PVOID* arr = (PVOID*)t->ArrayVa;
            ULONG nonNull = 0;
            for (ULONG i = 0; i < 执念_CALLBACK_ARRAY_SIZE; i++) {
                if (arr[i]) nonNull++;
            }
            DbgPrint("[执念-SCRUB]   array has %u non-NULL entries (of %u)\n",
                     nonNull, (ULONG)执念_CALLBACK_ARRAY_SIZE);

            DbgPrint("[执念-SCRUB]   arr[0]=%p arr[1]=%p arr[2]=%p arr[3]=%p\n",
                     arr[0], arr[1], arr[2], arr[3]);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[执念-SCRUB]   array read EXCEPTION 0x%08X\n", GetExceptionCode());
        }
    }
    ULONG found = 0;

    __try {
        PVOID* arr = (PVOID*)t->ArrayVa;

        for (ULONG i = 0; i < 执念_CALLBACK_ARRAY_SIZE; i++) {
            PVOID entry = arr[i];
            if (!entry)
                continue;

            PVOID block = 执念_BLOCK_OF(entry);
            if (!MmIsAddressValid(block))
                continue;

            PVOID fn = *(PVOID*)((PUCHAR)block + 执念_BLOCK_FUNCTION_OFF);
            if (!fn)
                continue;
            BOOLEAN isAce = FALSE;
            PCSTR   how = "";

            if (fn == aceAddr) {
                isAce = TRUE;
                how = "exact entry";
            } else if ((ULONG_PTR)fn >= (ULONG_PTR)g_AceBase &&
                       (ULONG_PTR)fn <  (ULONG_PTR)g_AceBase + g_AceSize) {
                isAce = TRUE;
                how = "inside ACE module";
            }

            DbgPrint("[执念-SCRUB]   [%u] entry=%p block=%p fn=%p%s%s%s\n",
                     i, entry, block, fn,
                     isAce ? "   <== MATCH (" : "",
                     isAce ? how : "",
                     isAce ? ")" : "");

            if (isAce) {
                t->HitIndex = i;
                t->OriginalFunc = fn;

                PVOID* slot = (PVOID*)((PUCHAR)block + 执念_BLOCK_FUNCTION_OFF);
                *slot = t->StubFunc;

                PVOID rb = *slot;
                DbgPrint("[执念-SCRUB]   -> replaced: %p -> %p (readback %p %s)\n",
                         fn, t->StubFunc, rb,
                         (rb == t->StubFunc) ? "OK" : "!!FAILED");

                if (rb == t->StubFunc) {
                    t->Scrubbed = TRUE;
                    found++;
                } else {
                    t->OriginalFunc = NULL;
                    t->HitIndex = 0xFFFFFFFF;
                }
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[执念-SCRUB] %ws EXCEPTION 0x%08X during array walk\n",
                 t->Name, GetExceptionCode());
        return STATUS_UNSUCCESSFUL;
    }

    if (found == 0) {
        DbgPrint("[执念-SCRUB] %ws ACE callback NOT FOUND in array\n", t->Name);
        DbgPrint("[执念-SCRUB]   (ACE may register via a different API for this type)\n");
        return STATUS_NOT_FOUND;
    }

    DbgPrint("[执念-SCRUB] %ws SCRUBBED at index %u\n", t->Name, t->HitIndex);
    return STATUS_SUCCESS;
}
//本项目是开源的！如果你是被收费的骗了，请申请退款！
NTSTATUS 执念UnscrubAll(VOID)
{
    ULONG restored = 0;

    for (ULONG i = 0; i < 执念_SCRUB_COUNT; i++) {
        P执念_SCRUB_TARGET t = &g_ScrubTargets[i];

        if (!t->Scrubbed || !t->ArrayVa || t->HitIndex == 0xFFFFFFFF)
            continue;

        __try {
            PVOID* arr = (PVOID*)t->ArrayVa;
            PVOID entry = arr[t->HitIndex];
            if (entry) {
                PVOID block = 执念_BLOCK_OF(entry);
                if (MmIsAddressValid(block)) {
                    *(PVOID*)((PUCHAR)block + 执念_BLOCK_FUNCTION_OFF) = t->OriginalFunc;

                    PVOID rb = *(PVOID*)((PUCHAR)block + 执念_BLOCK_FUNCTION_OFF);
                    DbgPrint("[执念-SCRUB] %ws restored index %u -> %p (readback %p %s)\n",
                             t->Name, t->HitIndex, t->OriginalFunc, rb,
                             (rb == t->OriginalFunc) ? "OK" : "!!FAILED");
                    restored++;
                    t->Scrubbed = FALSE;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            DbgPrint("[执念-SCRUB] %ws restore EXCEPTION 0x%08X\n",
                     t->Name, GetExceptionCode());
        }
    }

    DbgPrint("[执念-SCRUB] restored %u target(s)\n", restored);
    return STATUS_SUCCESS;
}
#define 执念_DATA_RVA_START  0x00E00000
#define 执念_DATA_RVA_END    0x00FC2700

static VOID 执念FindPointerHome(PVOID NtBase, PVOID AceFunc, PCWSTR Tag)
{
    DbgPrint("[执念-HOME] searching .data for pointer to %p (%ws)\n", AceFunc, Tag);

    ULONG hits = 0;
    PUCHAR start = (PUCHAR)NtBase + 执念_DATA_RVA_START;
    ULONG  count = (执念_DATA_RVA_END - 执念_DATA_RVA_START) / 8;

    __try {
        for (ULONG i = 0; i < count; i++) {
            PULONG64 slot = (PULONG64)start + i;

            if (!MmIsAddressValid(slot))
                continue;

            if (*slot != (ULONG64)(ULONG_PTR)AceFunc)
                continue;

            hits++;
            ULONG rva = 执念_DATA_RVA_START + i * 8;

            DbgPrint("[执念-HOME]   HIT #%u  %p (ntoskrnl+0x%X)\n",
                     hits, slot, rva);

            // 打印前后各 0x20 字节
            PULONG64 ctx = slot - 4;
            if (MmIsAddressValid(ctx)) {
                for (ULONG k = 0; k < 8; k++) {
                    DbgPrint("[执念-HOME]     %c0x%02X: %016llX\n",
                             (k == 4) ? '>' : ' ',
                             (ULONG)((i - 4 + k) * 8),
                             ctx[k]);
                }
            }

            if (hits >= 8) {
                DbgPrint("[执念-HOME]   (stopping after 8 hits)\n");
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[执念-HOME] EXCEPTION 0x%08X\n", GetExceptionCode());
    }

    if (hits == 0) {
        DbgPrint("[执念-HOME]   no reference found in .data\n");
        DbgPrint("[执念-HOME]   -> ACE callback address is not stored as a raw\n");
        DbgPrint("[执念-HOME]      pointer in ntoskrnl .data; it must live in a\n");
        DbgPrint("[执念-HOME]      heap-allocated structure (ExAllocatePoolWithTag)\n");
    } else {
        DbgPrint("[执念-HOME]   total %u hit(s)\n", hits);
    }
}

typedef struct _执念_KNOWN_EXPORT {
    PCWSTR Name;
    ULONG  PdbRva;
} 执念_KNOWN_EXPORT;

static const 执念_KNOWN_EXPORT g_KnownExports[] = {
    { L"NtCreateFile",                 0x6157F0 },
    { L"MmIsAddressValid",             0x5318F0 },
    { L"PsSetLoadImageNotifyRoutine",  0x781800 },
    { L"PsSetCreateThreadNotifyRoutine", 0x7817E0 },
    { L"CmRegisterCallbackEx",         0x866B50 },
    { L"ObRegisterCallbacks",          0x7B6AE0 },
    { L"IoRegisterShutdownNotification", 0x7AAF70 },
    { L"ZwQuerySystemInformation",     0x3F3740 },
    { L"RtlInitUnicodeString",         0x321C90 },
    { L"MmGetPhysicalAddress",         0x361410 },
};
#define 执念_KNOWN_COUNT (sizeof(g_KnownExports)/sizeof(g_KnownExports[0]))

VOID 执念ValidateNtoskrnlBase(PVOID ReportedBase)
{
    DbgPrint("[执念-BASE] ===== ntoskrnl base validation =====\n");
    DbgPrint("[执念-BASE] module list reported base = %p\n", ReportedBase);

    for (ULONG i = 0; i < 执念_KNOWN_COUNT; i++) {
        if (g_KnownExports[i].PdbRva == 0)
            continue;

        UNICODE_STRING nm;
        RtlInitUnicodeString(&nm, g_KnownExports[i].Name);

        PVOID fn = MmGetSystemRoutineAddress(&nm);
        if (!fn) {
            DbgPrint("[执念-BASE] %-30ws NOT EXPORTED\n", g_KnownExports[i].Name);
            continue;
        }

        ULONGLONG implied = (ULONGLONG)(ULONG_PTR)fn - g_KnownExports[i].PdbRva;

        DbgPrint("[执念-BASE] %-30ws addr=%p  -0x%X  => base=%p\n",
                 g_KnownExports[i].Name, fn, g_KnownExports[i].PdbRva,
                 (PVOID)(ULONG_PTR)implied);
    }
    __try {
        if (MmIsAddressValid(ReportedBase)) {
            PUSHORT mz = (PUSHORT)ReportedBase;
            DbgPrint("[执念-BASE] reported base MZ = 0x%04X %s\n",
                     *mz, (*mz == 0x5A4D) ? "(valid PE header)" : "(NOT a PE header!)");
        } else {
            DbgPrint("[执念-BASE] reported base not mapped\n");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[执念-BASE] MZ check EXCEPTION\n");
    }

    DbgPrint("[执念-BASE] =======================================\n");
}

NTSTATUS 执念ScrubAceCallbacks(VOID)
{
    DbgPrint("[执念-SCRUB] 开启摘除回调\n");

    PVOID ntBase = NULL;
    ULONG ntSize = 0;

    if (!执念GetNtoskrnlRange(&ntBase, &ntSize)) {
        DbgPrint("[执念-SCRUB] !! cannot get ntoskrnl range\n");
        return STATUS_NOT_FOUND;
    }

    DbgPrint("[执念-SCRUB] ntoskrnl base=%p size=0x%X\n", ntBase, ntSize);

    // 检查RVA是否合理，因为是通过RVA计算的，实验数据有限所以验证下更安全
    for (ULONG i = 0; i < 执念_SCRUB_COUNT; i++) {
        P执念_SCRUB_TARGET t = &g_ScrubTargets[i];
        if (t->SymRva >= ntSize) {
            DbgPrint("[执念-SCRUB] !! %ws RVA 0x%X outside ntoskrnl (size 0x%X)\n",
                     t->Name, t->SymRva, ntSize);
            DbgPrint("[执念-SCRUB] !! 符号表过期\n");
            return STATUS_REVISION_MISMATCH;
        }
    }
    g_AceBase = 执念FindAceDriverBase(&g_AceSize);//匹配ACE模块范围
    DbgPrint("[执念-SCRUB] ACE range: base=%p size=0x%X\n", g_AceBase, g_AceSize);
    if (!g_AceBase) {
        DbgPrint("[执念-SCRUB] !! ACE模块没有找到\n");
        return STATUS_NOT_FOUND;
    }

    ULONG ok = 0;
    for (ULONG i = 0; i < 执念_SCRUB_COUNT; i++) {
        if (NT_SUCCESS(执念ScrubOne(&g_ScrubTargets[i], ntBase)))
            ok++;
    }
    //全部没找到的情况下直接输出方便后续修复
    if (ok == 0) {
        DbgPrint("[执念-SCRUB] 没有任何目标，请自行根据dbgview输出适配哈\n");
    }

    DbgPrint("[执念-SCRUB] scrubbed %u/%u target(s)\n", ok, (ULONG)执念_SCRUB_COUNT);
    return ok ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}
