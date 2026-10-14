//诊断用的
#include "SignCallBack.h"
#include "SignCallBackConfig.h"

extern PVOID 执念LookupKernelSymbol(_In_ PCSTR SymbolName);

typedef struct _执念_MOD_INFO {
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
} 执念_MOD_INFO, *P执念_MOD_INFO;

typedef struct _执念_MODS {
    ULONG NumberOfModules;
    执念_MOD_INFO Modules[1];
} 执念_MODS, *P执念_MODS;

EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);
static PCSTR 执念ModuleNameByAddress(PVOID Addr, _Out_ PVOID* OutBase, _Out_ PULONG OutSize)
{
    if (OutBase) *OutBase = NULL;
    if (OutSize) *OutSize = 0;
    if (!Addr) return "<null>";

    ULONG bufSize = 0;
    ZwQuerySystemInformation(11, NULL, 0, &bufSize);
    if (!bufSize) return "<qsi-fail>";
    bufSize += 0x2000;

    P执念_MODS mods = (P执念_MODS)ExAllocatePoolWithTag(NonPagedPool, bufSize, 执念_TAG);
    if (!mods) return "<alloc-fail>";

    if (!NT_SUCCESS(ZwQuerySystemInformation(11, mods, bufSize, &bufSize))) {
        ExFreePoolWithTag(mods, 执念_TAG);
        return "<qsi-fail2>";
    }

    PCSTR found = "<not-in-any-module>";
    ULONG_PTR a = (ULONG_PTR)Addr;

    for (ULONG i = 0; i < mods->NumberOfModules; i++) {
        P执念_MOD_INFO e = &mods->Modules[i];
        ULONG_PTR base = (ULONG_PTR)e->ImageBase;
        if (a >= base && a < base + e->ImageSize) {
            found = (PCSTR)(e->FullPathName + e->OffsetToFileName);
            if (OutBase) *OutBase = e->ImageBase;
            if (OutSize) *OutSize = e->ImageSize;
            break;
        }
    }
    static CHAR s_NameBuf[260];
    if (found != s_NameBuf) {
        ULONG n = 0;
        while (found[n] && n < 259) { s_NameBuf[n] = found[n]; n++; }
        s_NameBuf[n] = 0;
        found = s_NameBuf;
    }

    ExFreePoolWithTag(mods, 执念_TAG);
    return found;
}

//遍历回调
static ULONG 执念DumpCallbackArray(
    PCSTR ArrayName, PVOID* Arr, ULONG Count, ULONG* OutAceHits)
{
    if (!Arr) {
        DbgPrint("[执念] %s: array = NULL\n", ArrayName);
        return 0;
    }

    ULONG used = 0;
    ULONG ace = 0;

    DbgPrint("[执念] ---- %s @ %p ----\n", ArrayName, Arr);

    for (ULONG i = 0; i < Count; i++) {
        PVOID entry = Arr[i];
        if (!entry) continue;

        if (!MmIsAddressValid(entry)) {
            DbgPrint("[执念]   [%02u] %p  <invalid>\n", i, entry);
            used++;
            continue;
        }

        // entry 是 EX_CALLBACK_ROUTINE_BLOCK, 功能 在 +0x08
        PVOID fn = NULL;
        __try {
            fn = *(PVOID*)((PUCHAR)entry + 0x08);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            fn = NULL;
        }

        PVOID modBase = NULL; ULONG modSize = 0;
        PCSTR modName = 执念ModuleNameByAddress(fn ? fn : entry, &modBase, &modSize);

        DbgPrint("[执念]   [%02u] block=%p fn=%p mod=%s\n",
                 i, entry, fn, modName);

        used++;

        // 判断是否 ACE
        if (modName && (modName[0] == 'A' || modName[0] == 'a')) {
            CHAR lower[16] = { 0 };
            for (int k = 0; k < 9 && modName[k]; k++) {
                CHAR c = modName[k];
                lower[k] = (c >= 'A' && c <= 'Z') ? (c + 32) : c;
            }
            if (lower[0]=='a'&&lower[1]=='c'&&lower[2]=='e'&&lower[3]=='-') {
                ace++;
                DbgPrint("[执念]   ^^^^ ACE HIT at index %u\n", i);
                if (OutAceHits) (*OutAceHits)++;
            }
        }
    }

    DbgPrint("[执念]   used=%u ace=%u\n", used, ace);
    return used;
}


VOID 执念Diagnose(VOID)
{
    DbgPrint("\n");
    ULONG aceSize = 0;
    PVOID aceBase = 执念FindAceDriverBase(&aceSize);
    if (aceBase) {
        DbgPrint("[执念] ACE-BOOT.sys FOUND base=%p size=0x%X\n", aceBase, aceSize);
    } else {
        DbgPrint("[执念] !! ACE-BOOT.sys 没有在系统模块列表内找到\n");
        DbgPrint("[执念]    可能原因: 模块名不同 / 被隐藏 / 尚未加载\n");
    }

    {
        ULONG bufSize = 0;
        ZwQuerySystemInformation(11, NULL, 0, &bufSize);
        if (bufSize) {
            bufSize += 0x2000;
            P执念_MODS mods = (P执念_MODS)ExAllocatePoolWithTag(NonPagedPool, bufSize, 执念_TAG);
            if (mods && NT_SUCCESS(ZwQuerySystemInformation(11, mods, bufSize, &bufSize))) {
                DbgPrint("[执念] --- modules containing 'ACE' or 'anti' ---\n");
                ULONG shown = 0;
                for (ULONG i = 0; i < mods->NumberOfModules && shown < 24; i++) {
                    P执念_MOD_INFO e = &mods->Modules[i];
                    PCHAR n = (PCHAR)e->FullPathName + e->OffsetToFileName;

                    CHAR lower[256] = { 0 };
                    for (int k = 0; k < 255 && n[k]; k++) {
                        CHAR c = n[k];
                        lower[k] = (c >= 'A' && c <= 'Z') ? (c + 32) : c;
                    }

                    if (strstr(lower, "ace") || strstr(lower, "anti")) {
                        DbgPrint("[执念]   %p size=0x%-8X %s\n",
                                 e->ImageBase, e->ImageSize, n);
                        shown++;
                    }
                }
                if (shown == 0)
                    DbgPrint("[执念]   (none found!)\n");
            }
            if (mods) ExFreePoolWithTag(mods, 执念_TAG);
        }
    }

    PVOID ntBase = 执念LookupKernelSymbol("NtCreateFile");
    DbgPrint("[执念] ntoskrnl sample symbol NtCreateFile = %p\n", ntBase);
    extern NTSTATUS 执念ResolveKernelCallbackArrays(VOID);
    执念ResolveKernelCallbackArrays();
    //dump数组
    extern PVOID* 执念GetArrayPtr(ULONG Index);
    ULONG totalAce = 0;

    执念DumpCallbackArray("PspLoadImageNotifyRoutine",
                         执念GetArrayPtr(0), 64, &totalAce);
    执念DumpCallbackArray("PspCreateProcessNotifyRoutine",
                         执念GetArrayPtr(1), 64, &totalAce);
    执念DumpCallbackArray("PspCreateThreadNotifyRoutine",
                         执念GetArrayPtr(2), 64, &totalAce);

    DbgPrint("[执念] arrays total ACE hits = %u\n", totalAce);
}
