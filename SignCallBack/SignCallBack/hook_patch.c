
 /*  ACE-BOOT.sys v1.0.2606.17242 表:
 *   ProcessObCallback(PRE)  0x22940   40 53 48 83 EC 20 48 8B
 *   CreateProcessEx         0x0C4A0   40 55 56 41 56 41 57 48
 *   LoadImage               0x0AC80   48 89 5C 24 10 48 89 4C
 *   CmpCallback             0x19C40   40 53 48 83 EC 20 48 8B
 *   Shutdown                0x0A2F0   40 53 48 83 EC 20 B9 08
 */

#include "SignCallBack.h"
#include "SignCallBackConfig.h"

extern PVOID 执念FindAceDriverBase(_Out_opt_ PULONG OutSize);

#define 执念_EXPECT_LEN  8
#define 执念_PATCH_LEN   3

typedef struct _执念_SITE {
    执念_TARGET Target;
    PCWSTR     Name;
    ULONG      Rva;
    UCHAR      Expect[执念_EXPECT_LEN];
    BOOLEAN    Enabled;

    // 运行时状态
    PVOID      Addr;
    UCHAR      Original[执念_EXPECT_LEN];
    BOOLEAN    Validated;
    BOOLEAN    Patched;
} 执念_SITE, *P执念_SITE;

static 执念_SITE g_Sites[] = {
    {
        执念_TARGET_PROCESS_OB, L"ProcessObCallback(PRE)", 0x22940,
        { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B },
        执念_TARGET_ENABLE_PROCESS_OB,
        NULL, { 0 }, FALSE, FALSE
    },
    {
        执念_TARGET_CREATE_PROC, L"CreateProcessEx", 0x0C4A0,
        { 0x40, 0x55, 0x56, 0x41, 0x56, 0x41, 0x57, 0x48 },
        执念_TARGET_ENABLE_CREATE_PROC,
        NULL, { 0 }, FALSE, FALSE
    },
    {
        执念_TARGET_LOAD_IMAGE, L"LoadImage", 0x0AC80,
        { 0x48, 0x89, 0x5C, 0x24, 0x10, 0x48, 0x89, 0x4C },
        执念_TARGET_ENABLE_LOAD_IMAGE,
        NULL, { 0 }, FALSE, FALSE
    },
    {
        执念_TARGET_REGISTRY, L"CmpCallback", 0x19C40,
        { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0x8B },
        执念_TARGET_ENABLE_REGISTRY,
        NULL, { 0 }, FALSE, FALSE
    },
    {
        执念_TARGET_SHUTDOWN, L"Shutdown", 0x0A2F0,
        { 0x40, 0x53, 0x48, 0x83, 0xEC, 0x20, 0xB9, 0x08 },
        执念_TARGET_ENABLE_SHUTDOWN,
        NULL, { 0 }, FALSE, FALSE
    },
};

#define 执念_SITE_COUNT  (sizeof(g_Sites) / sizeof(g_Sites[0]))
static const UCHAR g_PatchBytes[执念_PATCH_LEN] = { 0x33, 0xC0, 0xC3 };
extern PCSTR 执念ExceptionName(ULONG Code);
extern VOID  执念DiagnoseControlRegs(VOID);
extern volatile LONG g_Cr0Writable;
static volatile ULONG g_LastExceptionCode = 0;
static LONG 执念Write_Cr0Method(PVOID Addr, const UCHAR* Bytes, ULONG Len)
{
    volatile ULONG_PTR savedCr0 = 0;
    volatile ULONG     wrote = 0;
    LONG result = -1;

    __try {
        savedCr0 = __readcr0();
        DbgPrint("[执念-WR/CR0] cr0 = %016llX (WP=%u)\n",
                 (ULONG64)savedCr0, (ULONG)((savedCr0 & 0x10000ULL) ? 1 : 0));

        __writecr0(savedCr0 & ~0x10000ULL);
        DbgPrint("[执念-WR/CR0] WP cleared\n");

        for (ULONG i = 0; i < Len; i++) {
            PUCHAR p = (PUCHAR)Addr + i;
            *p = Bytes[i];
            wrote = i + 1;
            DbgPrint("[执念-WR/CR0]   [%u] %p <- %02X (readback %02X %s)\n",
                     i, p, Bytes[i], *p, (*p == Bytes[i]) ? "OK" : "!!MISMATCH");
        }

        __writecr0(savedCr0);
        DbgPrint("[执念-WR/CR0] cr0 restored\n");
        result = 1;
    } __except (g_LastExceptionCode = GetExceptionCode(),
                EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[执念-WR/CR0] !! EXCEPTION 0x%08X  %s\n",
                 g_LastExceptionCode, 执念ExceptionName(g_LastExceptionCode));
        DbgPrint("[执念-WR/CR0] !! wrote %u/%u bytes before fault\n",
                 (ULONG)wrote, Len);
        result = -1;
    }

    if (savedCr0) {
        __try { __writecr0((ULONG_PTR)savedCr0); }
        __except (EXCEPTION_EXECUTE_HANDLER) { }
    }

    return result;
}
static ULONG_PTR 执念FlushWorker(ULONG_PTR Argument)
{
    if (Argument)
        __invlpg((PVOID)Argument);
    return 0;
}

static volatile LONG g_DiagDone = 0;

BOOLEAN 执念WriteCode(PVOID Addr, const UCHAR* Bytes, ULONG Len)
{
    if (!Addr || !Bytes || !Len)
        return FALSE;

    DbgPrint("[执念-WR] ==== write %p (%u bytes) ====\n", Addr, Len);
    if (InterlockedCompareExchange(&g_DiagDone, 1, 0) == 0) {
        执念DiagnoseControlRegs();
    }
    执念ProbePage(Addr);
    if (执念_ENABLE_CR0_METHOD && g_Cr0Writable == 1) {
        DbgPrint("[执念-WR] --- trying CR0.WP method ---\n");
        if (执念Write_Cr0Method(Addr, Bytes, Len) == 1) {
            DbgPrint("[执念-WR] SUCCEEDED via CR0.WP\n");
            KeIpiGenericCall(执念FlushWorker, (ULONG_PTR)Addr);
            return TRUE;
        }
        DbgPrint("[执念-WR] CR0.WP method failed, falling back to PTE\n");
    } else {
        DbgPrint("[执念-WR] CR0.WP method skipped (CET locks CR0.WP on this machine)\n");
    }
    DbgPrint("[执念-WR] --- trying PTE method (MiGetPteAddress) ---\n");
    if (执念WriteCodeViaPte(Addr, Bytes, Len)) {
        DbgPrint("[执念-WR] SUCCEEDED via PTE\n");
        KeIpiGenericCall(执念FlushWorker, (ULONG_PTR)Addr);
        return TRUE;
    }

    DbgPrint("[执念-WR] !! ALL METHODS FAILED at %p\n", Addr);
    return FALSE;
}
NTSTATUS 执念ResolveByRva(VOID)
{
    ULONG aceSize = 0;
    PVOID aceBase = 执念FindAceDriverBase(&aceSize);

    if (!aceBase || !aceSize) {
        DbgPrint("[执念-RVA] !! ACE base not found, cannot resolve\n");
        return STATUS_NOT_FOUND;
    }

    DbgPrint("[执念-RVA] ACE base=%p size=0x%X\n", aceBase, aceSize);
    DbgPrint("[执念-RVA] ---- validating %u sites ----\n", (ULONG)执念_SITE_COUNT);

    ULONG validated = 0;

    for (ULONG i = 0; i < 执念_SITE_COUNT; i++) {
        P执念_SITE s = &g_Sites[i];

        //计算地址
        PVOID addr = (PVOID)((ULONG_PTR)aceBase + s->Rva);
        s->Addr = addr;

        //判断是否位于ACE模块内
        ULONG_PTR a = (ULONG_PTR)addr;
        ULONG_PTR b = (ULONG_PTR)aceBase;
        if (a < b || a >= b + aceSize) {
            DbgPrint("[执念-RVA] [%u] %ws RVA=0x%05X -> %p  OUT OF RANGE\n",
                     i, s->Name, s->Rva, addr);
            continue;
        }

        //是否可读
        if (!MmIsAddressValid(addr)) {
            DbgPrint("[执念-RVA] [%u] %ws %p  NOT MAPPED\n",
                     i, s->Name, addr);
            continue;
        }

        UCHAR cur[执念_EXPECT_LEN] = { 0 };
        BOOLEAN readOk = FALSE;

        __try {
            for (ULONG k = 0; k < 执念_EXPECT_LEN; k++)
                cur[k] = ((PUCHAR)addr)[k];
            readOk = TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            readOk = FALSE;
        }

        if (!readOk) {
            DbgPrint("[执念-RVA] [%u] %ws %p  READ FAULT\n", i, s->Name, addr);
            continue;
        }

        //校验字节
        BOOLEAN match = TRUE;
        for (ULONG k = 0; k < 执念_EXPECT_LEN; k++) {
            if (cur[k] != s->Expect[k]) { match = FALSE; break; }
        }

        for (ULONG k = 0; k < 执念_EXPECT_LEN; k++)
            s->Original[k] = cur[k];

        if (!match) {
            DbgPrint("[执念-RVA] [%u] %ws %p  BYTE MISMATCH\n", i, s->Name, addr);
            DbgPrint("[执念-RVA]      expect: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                     s->Expect[0], s->Expect[1], s->Expect[2], s->Expect[3],
                     s->Expect[4], s->Expect[5], s->Expect[6], s->Expect[7]);
            DbgPrint("[执念-RVA]      actual: %02X %02X %02X %02X %02X %02X %02X %02X\n",
                     cur[0], cur[1], cur[2], cur[3], cur[4], cur[5], cur[6], cur[7]);
            DbgPrint("[执念-RVA]      -> SKIP (跳过了不写)\n");
            continue;
        }

        s->Validated = TRUE;
        validated++;

        DbgPrint("[执念-RVA] [%u] %ws RVA=0x%05X addr=%p  VALIDATED OK\n",
                 i, s->Name, s->Rva, addr);
    }

    DbgPrint("[执念-RVA] validated %u/%u\n", validated, (ULONG)执念_SITE_COUNT);


    for (ULONG i = 0; i < 执念_SITE_COUNT; i++) {
        P执念_SITE s = &g_Sites[i];
        P执念_SLOT slot = &g_执念Slots[s->Target];
        if (s->Validated) {
            slot->EntryAddress = s->Addr;
            slot->OriginalEntry = s->Addr;
        }
    }

    return validated ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}
//应用patch
NTSTATUS 执念ApplyPatches(VOID)
{
    ULONG applied = 0;

    DbgPrint("[执念-PATCH] ---- applying patches ----\n");

    for (ULONG i = 0; i < 执念_SITE_COUNT; i++) {
        P执念_SITE s = &g_Sites[i];

        if (!s->Enabled) {
            DbgPrint("[执念-PATCH] [%u] %ws DISABLED by config\n", i, s->Name);
            continue;
        }

        if (!s->Validated) {
            DbgPrint("[执念-PATCH] [%u] %ws not validated, skip\n", i, s->Name);
            continue;
        }

        if (s->Patched) {
            DbgPrint("[执念-PATCH] [%u] %ws already patched\n", i, s->Name);
            continue;
        }

        if (!执念WriteCode(s->Addr, g_PatchBytes, 执念_PATCH_LEN)) {
            DbgPrint("[执念-PATCH] [%u] %ws write FAILED\n", i, s->Name);
            continue;
        }

        s->Patched = TRUE;
        applied++;

        P执念_SLOT slot = &g_执念Slots[s->Target];
        slot->Hooked = TRUE;
        slot->ViaEpt = FALSE;

        DbgPrint("[执念-PATCH] [%u] %ws %p  PATCHED  (was %02X %02X %02X, now %02X %02X %02X)\n",
                 i, s->Name, s->Addr,
                 s->Original[0], s->Original[1], s->Original[2],
                 g_PatchBytes[0], g_PatchBytes[1], g_PatchBytes[2]);
    }

    DbgPrint("[执念-PATCH] applied %u patch(es)\n", applied);
    return applied ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}
//恢复patch
NTSTATUS 执念RestorePatches(VOID)
{
    ULONG restored = 0;

    for (ULONG i = 0; i < 执念_SITE_COUNT; i++) {
        P执念_SITE s = &g_Sites[i];
        if (!s->Patched || !s->Addr)
            continue;

        if (执念WriteCode(s->Addr, s->Original, 执念_PATCH_LEN)) {
            s->Patched = FALSE;
            restored++;
            DbgPrint("[执念-PATCH] [%u] %ws restored\n", i, s->Name);

            P执念_SLOT slot = &g_执念Slots[s->Target];
            slot->Hooked = FALSE;
        }
    }

    DbgPrint("[执念-PATCH] restored %u\n", restored);
    return STATUS_SUCCESS;
}
ULONG 执念GetSiteCount(VOID) { return (ULONG)执念_SITE_COUNT; }

BOOLEAN 执念GetSiteInfo(
    _In_ ULONG Index,
    _Out_ PULONG OutRva,
    _Out_ PVOID* OutAddr,
    _Out_ PBOOLEAN OutValidated,
    _Out_ PBOOLEAN OutPatched)
{
    if (Index >= 执念_SITE_COUNT)
        return FALSE;

    P执念_SITE s = &g_Sites[Index];
    if (OutRva)       *OutRva = s->Rva;
    if (OutAddr)      *OutAddr = s->Addr;
    if (OutValidated) *OutValidated = s->Validated;
    if (OutPatched)   *OutPatched = s->Patched;
    return TRUE;
}

NTSTATUS 执念PatchAllAceCallbacks(VOID)
{
    DbgPrint("[执念-PATCH] ===== RVA-based patching =====\n");

    NTSTATUS st = 执念ResolveByRva();
    if (!NT_SUCCESS(st)) {
        DbgPrint("[执念-PATCH] resolve failed 0x%08X\n", st);
        return st;
    }

    return 执念ApplyPatches();
}
