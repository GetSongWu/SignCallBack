#include "SignCallBack.h"
#include "SignCallBackConfig.h"

//指针
typedef struct _执念_KERNEL_ARRAYS {
    PVOID*  LoadImageNotify;      // PspLoadImageNotifyRoutine
    PVOID*  CreateProcessNotify;  // PspCreateProcessNotifyRoutine
    PVOID*  CreateThreadNotify;   // PspCreateThreadNotifyRoutine
    PVOID   CmpCallbackListHead;  // CmpCallbackListHead
    PVOID   ObPreOpCallbacks;     // ObpCallPreOperationCallbacks
    PVOID   ShutdownListHead;     // PopShutdownListHead
} 执念_KERNEL_ARRAYS, *P执念_KERNEL_ARRAYS;

static 执念_KERNEL_ARRAYS g_KArrays = { 0 };

//定位ACE模块位置
typedef struct _执念_RTL_PROCESS_MODULE_INFORMATION {
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
} 执念_RTL_PROCESS_MODULE_INFORMATION, *P执念_RTL_PROCESS_MODULE_INFORMATION;

typedef struct _执念_RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    执念_RTL_PROCESS_MODULE_INFORMATION Modules[1];
} 执念_RTL_PROCESS_MODULES, *P执念_RTL_PROCESS_MODULES;

EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

// 缓存
static PVOID g_CachedAceBase = NULL;
static ULONG g_CachedAceSize = 0;
static BOOLEAN g_AceCacheValid = FALSE;
//遍历模块列表，找ACE-BOOT
PVOID 执念FindAceDriverBase(_Out_opt_ PULONG OutSize)
{
    if (g_AceCacheValid && g_CachedAceBase) {
        if (OutSize) *OutSize = g_CachedAceSize;
        return g_CachedAceBase;
    }

    ULONG BufSize = 0;
    ZwQuerySystemInformation(11, NULL, 0, &BufSize);
    if (BufSize == 0)
        return NULL;

    BufSize += 0x2000;
    P执念_RTL_PROCESS_MODULES Mods =
        (P执念_RTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, BufSize, 执念_TAG);
    if (!Mods)
        return NULL;

    NTSTATUS st = ZwQuerySystemInformation(11, Mods, BufSize, &BufSize);
    if (!NT_SUCCESS(st)) {
        ExFreePoolWithTag(Mods, 执念_TAG);
        return NULL;
    }

    PVOID Found = NULL;
    ULONG FoundSize = 0;
    for (ULONG i = 0; i < Mods->NumberOfModules; i++) {
        P执念_RTL_PROCESS_MODULE_INFORMATION e = &Mods->Modules[i];
        PCHAR name = (PCHAR)e->FullPathName + e->OffsetToFileName;
        CHAR lower[256] = { 0 };
        for (int k = 0; k < 255 && name[k]; k++) {
            CHAR c = name[k];
            lower[k] = (c >= 'A' && c <= 'Z') ? (CHAR)(c + 32) : c;//大小写转换
        }

        if (strstr(lower, "ace-boot") != NULL ||
            strstr(lower, "ace-boot64") != NULL) {
            Found = e->ImageBase;
            FoundSize = e->ImageSize;
            DbgPrint("[执念] ACE模块已找到: %s base=%p size=0x%X\n",
                     name, Found, FoundSize);
            break;
        }
    }

    ExFreePoolWithTag(Mods, 执念_TAG);

    if (Found) {
        g_CachedAceBase = Found;
        g_CachedAceSize = FoundSize;
        g_AceCacheValid = TRUE;
    }

    if (OutSize) *OutSize = FoundSize;
    return Found;
}

VOID 执念InvalidateAceCache(VOID)
{
    g_AceCacheValid = FALSE;
    g_CachedAceBase = NULL;
    g_CachedAceSize = 0;
}

static BOOLEAN g_IsAceAddrWarned = FALSE;

BOOLEAN 执念IsAceAddress(PVOID Addr)
{
    if (!Addr) return FALSE;

    ULONG size = 0;
    PVOID base = 执念FindAceDriverBase(&size);
    if (!base || !size) {
        extern PVOID 执念FallbackAceBase(_Out_opt_ PULONG OutSize);
        base = 执念FallbackAceBase(&size);

        if (!base || !size) {
            if (!g_IsAceAddrWarned) {
                DbgPrint("[执念] !! 执念IsAceAddress: ACE base unresolved "
                         "(tried module list + driver object), all checks will FAIL\n");
                g_IsAceAddrWarned = TRUE;
            }
            return FALSE;
        }
    }

    ULONG_PTR a = (ULONG_PTR)Addr;
    ULONG_PTR b = (ULONG_PTR)base;
    return (a >= b && a < b + size);
}
PVOID* 执念GetArrayPtr(ULONG Index)
{
    switch (Index) {
    case 0: return g_KArrays.LoadImageNotify;
    case 1: return g_KArrays.CreateProcessNotify;
    case 2: return g_KArrays.CreateThreadNotify;
    case 3: return (PVOID*)g_KArrays.CmpCallbackListHead;
    case 4: return (PVOID*)g_KArrays.ObPreOpCallbacks;
    case 5: return (PVOID*)g_KArrays.ShutdownListHead;
    default: return NULL;
    }
}
//本项目是开源的！如果你是被收费的骗了，请申请退款！
typedef struct _执念_MODULE {
    PVOID Base;
    ULONG Size;
} 执念_MODULE;

static BOOLEAN 执念FindModule(PCWSTR Name, _Out_ 执念_MODULE* Out)
{
    ULONG BufSize = 0;
    ZwQuerySystemInformation(11, NULL, 0, &BufSize);
    if (!BufSize) return FALSE;
    BufSize += 0x2000;
    P执念_RTL_PROCESS_MODULES Mods =
        (P执念_RTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, BufSize, 执念_TAG);
    if (!Mods) return FALSE;
    if (!NT_SUCCESS(ZwQuerySystemInformation(11, Mods, BufSize, &BufSize))) {
        ExFreePoolWithTag(Mods, 执念_TAG);
        return FALSE;
    }

    BOOLEAN ok = FALSE;
    for (ULONG i = 0; i < Mods->NumberOfModules; i++) {
        P执念_RTL_PROCESS_MODULE_INFORMATION e = &Mods->Modules[i];
        PCHAR n = (PCHAR)e->FullPathName + e->OffsetToFileName;
        if (_stricmp(n, "ntoskrnl.exe") == 0 || _stricmp(n, "ntkrnlmp.exe") == 0) {
            Out->Base = e->ImageBase;//匹配ntoskrnl
            Out->Size = e->ImageSize;
            ok = TRUE;
            break;
        }
    }
    ExFreePoolWithTag(Mods, 执念_TAG);
    return ok;
}

static PVOID 执念PatternScan(PVOID Base, ULONG Size, const UCHAR* Pat, const CHAR* Mask, ULONG Len)
{
    PUCHAR s = (PUCHAR)Base;
    PUCHAR end = s + Size - Len;
    for (PUCHAR p = s; p <= end; p++) {
        BOOLEAN hit = TRUE;
        for (ULONG i = 0; i < Len; i++) {
            if (Mask[i] == 'x' && p[i] != Pat[i]) { hit = FALSE; break; }
        }
        if (hit) return p;
    }
    return NULL;
}

//扫数组本体，也可以用符号表定位，我推荐是自己去写一个符号加载器的，直接pdb解析即可
typedef struct _执念_SYMBOL_ENTRY {
    PCSTR Name;
    PVOID Address;
} 执念_SYMBOL_ENTRY;

//开源_执念
//QQ:2693529153
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途
NTSTATUS 执念ResolveKernelCallbackArrays(VOID)
{
    执念_MODULE nt = { 0 };
    if (!执念FindModule(L"ntoskrnl.exe", &nt)) {
        DbgPrint("[执念] ntoskrnl not found\n");
        return STATUS_NOT_FOUND;
    }
    DbgPrint("[执念] ntoskrnl base=%p size=0x%X\n", nt.Base, nt.Size);
    g_KArrays.LoadImageNotify     = (PVOID*)执念LookupKernelSymbol("PspLoadImageNotifyRoutine");
    g_KArrays.CreateProcessNotify = (PVOID*)执念LookupKernelSymbol("PspCreateProcessNotifyRoutine");
    g_KArrays.CreateThreadNotify  = (PVOID*)执念LookupKernelSymbol("PspCreateThreadNotifyRoutine");
    g_KArrays.CmpCallbackListHead = 执念LookupKernelSymbol("CmpCallbackListHead");
    g_KArrays.ObPreOpCallbacks    = 执念LookupKernelSymbol("ObpCallPreOperationCallbacks");
    g_KArrays.ShutdownListHead    = 执念LookupKernelSymbol("PopShutdownListHead");
//win11 24h2 特征，其他版本自行匹配
    if (!g_KArrays.LoadImageNotify) {
        // PsSetLoadImageNotifyRoutine 特征
        static const UCHAR pat[] = {
            0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74,
            0x24, 0x10, 0x57, 0x48, 0x83, 0xEC, 0x20, 0x48,
            0x8B, 0xF1, 0x33, 0xDB
        };
        static const CHAR msk[] = "xxxxxxxxxxxxxxxxxxxx";
        PVOID f = 执念PatternScan(nt.Base, nt.Size, pat, msk, sizeof(pat));
        if (f) {
            PUCHAR p = (PUCHAR)f;
            for (ULONG i = 0; i < 0x200; i++) {
                if (p[i] == 0x48 && p[i+1] == 0x8D && p[i+2] == 0x0D) {
                    INT32 disp = *(INT32*)&p[i+3];
                    PVOID arr = (PVOID)(p + i + 7 + disp);
                    if (MmIsAddressValid(arr)) {
                        g_KArrays.LoadImageNotify = (PVOID*)arr;
                        DbgPrint("[执念] PspLoadImageNotifyRoutine @ %p (scan)\n", arr);
                        break;
                    }
                }
            }
        }
    }

    if (!g_KArrays.CreateProcessNotify) {
        // PsSetCreateProcessNotifyRoutineEx 特征
        static const UCHAR pat[] = {
            0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74,
            0x24, 0x10, 0x48, 0x89, 0x7C, 0x24, 0x18, 0x55,
            0x48, 0x8B, 0xEC
        };
        static const CHAR msk[] = "xxxxxxxxxxxxxxxxxxx";
        PVOID f = 执念PatternScan(nt.Base, nt.Size, pat, msk, sizeof(pat));
        if (f) {
            PUCHAR p = (PUCHAR)f;
            for (ULONG i = 0; i < 0x200; i++) {
                if (p[i] == 0x48 && p[i+1] == 0x8D && p[i+2] == 0x0D) {
                    INT32 disp = *(INT32*)&p[i+3];
                    PVOID arr = (PVOID)(p + i + 7 + disp);
                    if (MmIsAddressValid(arr)) {
                        g_KArrays.CreateProcessNotify = (PVOID*)arr;
                        DbgPrint("[执念] PspCreateProcessNotifyRoutine @ %p (scan)\n", arr);
                        break;
                    }
                }
            }
        }
    }

    DbgPrint("[执念] arrays: LoadImage=%p CreateProc=%p CmpHead=%p ObPre=%p Shutdown=%p\n",
             g_KArrays.LoadImageNotify, g_KArrays.CreateProcessNotify,
             g_KArrays.CmpCallbackListHead, g_KArrays.ObPreOpCallbacks,
             g_KArrays.ShutdownListHead);

    return STATUS_SUCCESS;
}

//查注册该回调的模块是不是Ace
typedef struct _执念_CALLBACK_BLOCK {
    ULONG_PTR RundownProtect;   // +0x00
    PVOID     Function;         // +0x08  回调函数入口
    PVOID     Context;          // +0x10
} 执念_CALLBACK_BLOCK, *P执念_CALLBACK_BLOCK;

// 用回调函数地址判断模块到底是谁
BOOLEAN 执念CallbackBelongsToAce(_In_ PVOID BlockOrFunc)
{
    if (!BlockOrFunc) return FALSE;
    if (!MmIsAddressValid(BlockOrFunc)) return FALSE;

    // 先当成 block 试
    P执念_CALLBACK_BLOCK blk = (P执念_CALLBACK_BLOCK)BlockOrFunc;
    PVOID fn = blk->Function;
    if (!MmIsAddressValid(fn)) {
        // 不是 block, 直接当函数地址
        fn = BlockOrFunc;
    }

    return 执念IsAceAddress(fn);
}
//解析回调函数
NTSTATUS 执念ResolveAceCallbacks(VOID)
{
    ULONG aceSize = 0;
    PVOID aceBase = 执念FindAceDriverBase(&aceSize);
    if (!aceBase) {
        DbgPrint("[执念] ACE-BOOT.sys not loaded\n");
        return STATUS_NOT_FOUND;
    }
    DbgPrint("[执念] ACE-BOOT.sys base=%p size=0x%X\n", aceBase, aceSize);

    执念ResolveKernelCallbackArrays();
    struct { PVOID* Arr; PCWSTR Tag; 执念_TARGET T; } slots[] = {
        { g_KArrays.LoadImageNotify,     L"LoadImage",     执念_TARGET_LOAD_IMAGE  },
        { g_KArrays.CreateProcessNotify, L"CreateProcess", 执念_TARGET_CREATE_PROC },
        { g_KArrays.CreateThreadNotify,  L"CreateThread",  执念_TARGET_COUNT /*不在目标里 */ },
    };

    for (ULONG s = 0; s < ARRAYSIZE(slots); s++) {
        if (!slots[s].Arr) continue;
        if (slots[s].T >= 执念_TARGET_COUNT) continue;

        for (ULONG i = 0; i < 64; i++) {
            PVOID entry = slots[s].Arr[i];
            if (!entry) continue;

            if (执念CallbackBelongsToAce(entry)) {
                P执念_SLOT slot = &g_执念Slots[slots[s].T];
                if (!slot->EntryAddress) {
                    slot->EntryAddress = entry;
                    P执念_CALLBACK_BLOCK blk = (P执念_CALLBACK_BLOCK)entry;
                    slot->OriginalEntry = blk->Function;
                    DbgPrint("[执念] %ws ACE entry[%u] = %p, fn = %p\n",
                             slots[s].Tag, i, entry, blk->Function);
                }
            }
        }
    }

   //遍历链表，找AXE注册的回调
    if (g_KArrays.CmpCallbackListHead) {
        PLIST_ENTRY head = (PLIST_ENTRY)g_KArrays.CmpCallbackListHead;
        if (MmIsAddressValid(head)) {
            PLIST_ENTRY cur = head->Flink;
            ULONG guard = 0;
            while (cur && cur != head && guard++ < 128) {
                if (!MmIsAddressValid(cur)) break;
                // 扫这个节点前后 0x40 字节,指向ACE
                PVOID* p = (PVOID*)cur;
                for (ULONG k = 0; k < 8; k++) {
                    if (MmIsAddressValid(&p[k]) && 执念IsAceAddress(p[k])) {
                        if (!g_执念Slots[执念_TARGET_REGISTRY].EntryAddress) {
                            g_执念Slots[执念_TARGET_REGISTRY].EntryAddress = cur;
                            g_执念Slots[执念_TARGET_REGISTRY].OriginalEntry = p[k];
                            DbgPrint("[执念] Registry ACE node=%p fn=%p\n", cur, p[k]);
                        }
                        break;
                    }
                }
                cur = cur->Flink;
            }
        }
    }

    执念ResolveProcessObCallbacks();
    执念ResolveShutdownCallbacks();
    return STATUS_SUCCESS;
}
//开源_执念
//QQ:2693529153
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途