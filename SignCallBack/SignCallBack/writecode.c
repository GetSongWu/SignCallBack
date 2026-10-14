
#include "SignCallBack.h"
#include "SignCallBackConfig.h"
extern PVOID 执念LookupKernelSymbol(_In_ PCSTR SymbolName);
#define 执念_CR0_WP      0x00010000ULL
#define 执念_CR0_PG      0x80000000ULL
#define 执念_CR0_PE      0x00000001ULL
#define 执念_CR4_CET     0x00000080ULL   // bit 7  (CET)
#define 执念_CR4_PGE     0x00000080ULL   // bit 7  (PGE, 同名位不同 CR)
#define 执念_CR4_PCE     0x00000100ULL   // bit 8
#define 执念_CR4_OSFXSR  0x00000200ULL   // bit 9
#define 执念_CR4_OSXMMEX 0x00000400ULL   // bit 10
#define 执念_CR4_UMIP    0x00000800ULL   // bit 11
#define 执念_CR4_LA57    0x00001000ULL   // bit 12
#define 执念_CR4_VMXE    0x00002000ULL   // bit 13
#define 执念_CR4_SMXE    0x00004000ULL   // bit 14
#define 执念_CR4_FSGSBASE 0x00010000ULL  // bit 16
#define 执念_CR4_PCIDE   0x00020000ULL   // bit 17
#define 执念_CR4_OSXSAVE 0x00040000ULL   // bit 18
#define 执念_CR4_SMEP    0x00100000ULL   // bit 20
#define 执念_CR4_SMAP    0x00200000ULL   // bit 21
#define 执念_CR4_PKE     0x00400000ULL   // bit 22
#define 执念_CR4_CET_    0x00800000ULL   // bit 23
// 异常码
PCSTR 执念ExceptionName(ULONG Code)
{
    switch (Code) {
    case 0xC0000005: return "STATUS_ACCESS_VIOLATION";
    case 0x80000003: return "STATUS_BREAKPOINT";
    case 0xC000001D: return "STATUS_ILLEGAL_INSTRUCTION (#UD)";
    case 0xC0000096: return "STATUS_PRIVILEGED_INSTRUCTION (#GP)";
    case 0xC0000006: return "STATUS_IN_PAGE_ERROR";
    case 0xC000009A: return "STATUS_INSUFFICIENT_RESOURCES";
    default:         return "(unknown)";
    }
}

static LONG 执念TestA_WriteBack(PVOID* OutCr0)
{
    ULONG_PTR cr0 = 0;
    LONG ok = -1;

    __try {
        cr0 = __readcr0();
        DbgPrint("[执念-CR] test A: read cr0 = %016llX\n", (ULONG64)cr0);

        // 关键: 写回完全相同的值
        __writecr0(cr0);
        DbgPrint("[执念-CR] test A: write-back SAME value -> OK\n");
        ok = 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[执念-CR] test A: write-back SAME value -> #GP/EXCEPTION 0x%08X\n",
                 GetExceptionCode());
        ok = -1;
    }

    if (OutCr0) *OutCr0 = (PVOID)cr0;
    return ok;
}
static LONG 执念TestB_ClearWp(ULONG_PTR Cr0)
{
    LONG ok = -1;

    __try {
        __writecr0(Cr0 & ~执念_CR0_WP);
        DbgPrint("[执念-CR] test B: clear WP -> OK\n");
        ok = 1;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[执念-CR] test B: clear WP -> EXCEPTION 0x%08X\n",
                 GetExceptionCode());
        ok = -1;
    }

    __try { __writecr0(Cr0); } __except (EXCEPTION_EXECUTE_HANDLER) { }

    return ok;
}

static VOID 执念TestC_ReadBack(ULONG_PTR Expected)
{
    ULONG_PTR now = 0;
    __try {
        now = __readcr0();
        DbgPrint("[执念-CR] test C: cr0 now = %016llX (WP=%u, expected %016llX)\n",
                 (ULONG64)now, (ULONG)((now & 执念_CR0_WP) ? 1 : 0),
                 (ULONG64)Expected);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[执念-CR] test C: read-back FAILED 0x%08X\n", GetExceptionCode());
    }
}

static VOID 执念TestD_Cr4(VOID)
{
    ULONG_PTR cr4 = 0;

    __try {
        cr4 = __readcr4();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[执念-CR] test D: __readcr4 FAILED 0x%08X\n", GetExceptionCode());
        return;
    }

    DbgPrint("[执念-CR] test D: cr4 = %016llX\n", (ULONG64)cr4);
    DbgPrint("[执念-CR]   PGE(7)=%u   PCE(8)=%u   OSFXSR(9)=%u  OSXMMEXCPT(10)=%u\n",
             (ULONG)((cr4 & 执念_CR4_PGE) ? 1 : 0),
             (ULONG)((cr4 & 执念_CR4_PCE) ? 1 : 0),
             (ULONG)((cr4 & 执念_CR4_OSFXSR) ? 1 : 0),
             (ULONG)((cr4 & 执念_CR4_OSXMMEX) ? 1 : 0));
    DbgPrint("[执念-CR]   UMIP(11)=%u  LA57(12)=%u  VMXE(13)=%u  SMXE(14)=%u\n",
             (ULONG)((cr4 & 执念_CR4_UMIP) ? 1 : 0),
             (ULONG)((cr4 & 执念_CR4_LA57) ? 1 : 0),
             (ULONG)((cr4 & 执念_CR4_VMXE) ? 1 : 0),
             (ULONG)((cr4 & 执念_CR4_SMXE) ? 1 : 0));
    DbgPrint("[执念-CR]   FSGSBASE(16)=%u PCIDE(17)=%u OSXSAVE(18)=%u\n",
             (ULONG)((cr4 & 执念_CR4_FSGSBASE) ? 1 : 0),
             (ULONG)((cr4 & 执念_CR4_PCIDE) ? 1 : 0),
             (ULONG)((cr4 & 执念_CR4_OSXSAVE) ? 1 : 0));
    DbgPrint("[执念-CR]   SMEP(20)=%u  SMAP(21)=%u  PKE(22)=%u  CET(23)=%u\n",
             (ULONG)((cr4 & 执念_CR4_SMEP) ? 1 : 0),
             (ULONG)((cr4 & 执念_CR4_SMAP) ? 1 : 0),
             (ULONG)((cr4 & 执念_CR4_PKE) ? 1 : 0),
             (ULONG)((cr4 & 执念_CR4_CET_) ? 1 : 0));
}

volatile LONG g_Cr0Writable = 0;
VOID 执念DiagnoseControlRegs(VOID)
{
    DbgPrint("[执念-CR]诊断开始\n");

    PVOID cr0 = NULL;
    LONG a = 执念TestA_WriteBack(&cr0);

    g_Cr0Writable = (a == 1) ? 1 : -1;

    if (a == 1) {
        执念TestC_ReadBack((ULONG_PTR)cr0);
        执念TestB_ClearWp((ULONG_PTR)cr0);
        执念TestC_ReadBack((ULONG_PTR)cr0);
    } else {
        DbgPrint("[执念-CR] test A failed -> skipping B/C (write to CR0 unusable)\n");
    }

    执念TestD_Cr4();

    DbgPrint("[执念-CR] ------------- conclusion -------------\n");
    if (a == 1) {
        DbgPrint("[执念-CR] MOV CR0 executes fine; WP-clear rejection would be a fixed-bit issue\n");
    } else {
        DbgPrint("[执念-CR] Even write-back of identical value fails\n");
        DbgPrint("[执念-CR] -> CR0 is locked, or __writecr0 intrinsic is unusable here\n");
        DbgPrint("[执念-CR] -> must use PTE method (no privileged instruction involved)\n");
    }
    DbgPrint("[执念-CR] ============================================================\n");
}
typedef PVOID (NTAPI *PFN_MiGetPteAddress)(PVOID VirtualAddress);

static PFN_MiGetPteAddress g_MiGetPteAddress = NULL;
static BOOLEAN             g_MiLookupDone = FALSE;

// mov rax, 0xFFFFF68000000000  =  48 B8 00 00 00 00 00 F6 FF FF
static const UCHAR g_PteSig[] = {
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF6, 0xFF, 0xFF
};
#define 执念_PTE_SIG_LEN  (sizeof(g_PteSig))

// 取 ntoskrnl 基址和大小
typedef struct _执念_SIG_MODULE {
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
} 执念_SIG_MODULE, *P执念_SIG_MODULE;

typedef struct _执念_SIG_MODULES {
    ULONG          NumberOfModules;
    执念_SIG_MODULE Modules[1];
} 执念_SIG_MODULES, *P执念_SIG_MODULES;

EXTERN_C NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

static BOOLEAN 执念GetNtoskrnlRangeImpl(PVOID* OutBase, PULONG OutSize)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"MmIsAddressValid");

    PVOID fn = MmGetSystemRoutineAddress(&name);
    if (!fn) {
        DbgPrint("[执念-SIG] MmGetSystemRoutineAddress(MmIsAddressValid) failed\n");
        return FALSE;
    }

    ULONG need = 0;
    ZwQuerySystemInformation(11, NULL, 0, &need);
    if (need == 0) {
        DbgPrint("[执念-SIG] ZwQuerySystemInformation sizing failed\n");
        return FALSE;
    }

    ULONG alloc = need + 0x1000;
    P执念_SIG_MODULES mods = (P执念_SIG_MODULES)ExAllocatePoolWithTag(
        NonPagedPool, alloc, 执念_TAG);
    if (!mods)
        return FALSE;

    NTSTATUS st = ZwQuerySystemInformation(11, mods, alloc, &need);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[执念-SIG] module query failed 0x%08X\n", st);
        ExFreePoolWithTag(mods, 执念_TAG);
        return FALSE;
    }

    BOOLEAN found = FALSE;

    for (ULONG i = 0; i < mods->NumberOfModules; i++) {
        PVOID base = mods->Modules[i].ImageBase;
        ULONG size = mods->Modules[i].ImageSize;

        if (!base || !size)
            continue;

        if ((ULONG_PTR)fn >= (ULONG_PTR)base &&
            (ULONG_PTR)fn <  (ULONG_PTR)base + size) {
            if (OutBase) *OutBase = base;
            if (OutSize) *OutSize = size;
            DbgPrint("[执念-SIG] ntoskrnl module #%u base=%p size=0x%X name=%s\n",
                     i, base, size,
                     mods->Modules[i].FullPathName +
                     mods->Modules[i].OffsetToFileName);
            found = TRUE;
            break;
        }
    }

    ExFreePoolWithTag(mods, 执念_TAG);
    return found;
}
BOOLEAN 执念GetNtoskrnlRange(PVOID* OutBase, PULONG OutSize)
{
    return 执念GetNtoskrnlRangeImpl(OutBase, OutSize);
}

static PFN_MiGetPteAddress 执念FindMiGetPteAddressBySig(VOID)
{
    PVOID  kbase = NULL;
    ULONG  ksize = 0;

    if (!执念GetNtoskrnlRangeImpl(&kbase, &ksize)) {
        DbgPrint("[执念-SIG] cannot determine ntoskrnl range\n");
        return NULL;
    }

    DbgPrint("[执念-SIG] searching MiGetPteAddress in %p (0x%X bytes)...\n",
             kbase, ksize);

    PUCHAR start = (PUCHAR)kbase;
    ULONG  limit = ksize - (ULONG)执念_PTE_SIG_LEN;
    ULONG  hits  = 0;
    PVOID  first = NULL;

    for (ULONG off = 0; off < limit; off++) {
        if (!MmIsAddressValid(start + off))
            continue;

        BOOLEAN match = TRUE;
        for (ULONG k = 0; k < 执念_PTE_SIG_LEN; k++) {
            if (start[off + k] != g_PteSig[k]) { match = FALSE; break; }
        }

        if (match) {
            hits++;
            if (!first) {
                first = start + off;
                DbgPrint("[执念-SIG] hit #1 at RVA 0x%X -> %p\n",
                         off, start + off);
            } else if (hits <= 4) {
                DbgPrint("[执念-SIG] hit #%u at RVA 0x%X -> %p\n",
                         hits, off, start + off);
            }
        }
    }

    DbgPrint("[执念-SIG] total hits = %u\n", hits);

    if (!first) {
        DbgPrint("[执念-SIG] !! signature not found\n");
        return NULL;
    }

    return (PFN_MiGetPteAddress)first;
}

static PFN_MiGetPteAddress 执念GetMiGetPteAddress(VOID)
{
    if (g_MiLookupDone)
        return g_MiGetPteAddress;

    g_MiLookupDone = TRUE;
    PVOID fn = 执念LookupKernelSymbol("MiGetPteAddress");
    if (fn) {
        DbgPrint("[执念-PTE] MiGetPteAddress from symbol table: %p\n", fn);
        g_MiGetPteAddress = (PFN_MiGetPteAddress)fn;
        return g_MiGetPteAddress;
    }
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"MiGetPteAddress");
    fn = MmGetSystemRoutineAddress(&name);
    if (fn) {
        DbgPrint("[执念-PTE] MiGetPteAddress via MmGetSystemRoutineAddress: %p\n", fn);
        g_MiGetPteAddress = (PFN_MiGetPteAddress)fn;
        return g_MiGetPteAddress;
    }
    DbgPrint("[执念-PTE] symbol table miss, trying signature scan...\n");
    fn = 执念FindMiGetPteAddressBySig();
    if (fn) {
        DbgPrint("[执念-PTE] MiGetPteAddress via signature: %p\n", fn);
        g_MiGetPteAddress = (PFN_MiGetPteAddress)fn;
        return g_MiGetPteAddress;
    }

    DbgPrint("[执念-PTE] !! MiGetPteAddress NOT found by any method\n");
    DbgPrint("[执念-PTE] !! refusing to fall back to hand-computed math\n");
    return NULL;
}

#define 执念_PTE_RW      0x002ULL
#define 执念_PTE_DIRTY   0x040ULL
#define 执念_PTE_PRESENT 0x001ULL
#define 执念_PTE_LARGE   0x080ULL
VOID 执念ProbePage(PVOID Addr)
{
    DbgPrint("[执念-PROBE] target %p\n", Addr);
    if (!Addr) return;

    BOOLEAN valid = FALSE;
    __try { valid = MmIsAddressValid(Addr); }
    __except (EXCEPTION_EXECUTE_HANDLER) { valid = FALSE; }

    DbgPrint("[执念-PROBE]   MmIsAddressValid = %u\n", (ULONG)valid);
    if (!valid) { DbgPrint("[执念-PROBE]   -> NOT MAPPED\n"); return; }

    UCHAR bytes[8] = { 0 };
    __try {
        for (ULONG i = 0; i < 8; i++) bytes[i] = ((PUCHAR)Addr)[i];
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[执念-PROBE]   -> READ FAULT\n");
        return;
    }

    DbgPrint("[执念-PROBE]   bytes: %02X %02X %02X %02X %02X %02X %02X %02X\n",
             bytes[0], bytes[1], bytes[2], bytes[3],
             bytes[4], bytes[5], bytes[6], bytes[7]);
    DbgPrint("[执念-PROBE]   page offset = 0x%03X\n",
             (ULONG)((ULONG_PTR)Addr & 0xFFF));

    // 用 MiGetPteAddress 报告 PTE
    PFN_MiGetPteAddress getPte = 执念GetMiGetPteAddress();
    if (!getPte) {
        DbgPrint("[执念-PROBE]   PTE info unavailable (MiGetPteAddress missing)\n");
        return;
    }

    __try {
        PULONG64 pte = (PULONG64)getPte(Addr);
        if (!pte) {
            DbgPrint("[执念-PROBE]   MiGetPteAddress returned NULL\n");
            return;
        }
        DbgPrint("[执念-PROBE]   PTE @ %p = %016llX (P=%u RW=%u D=%u PS=%u)\n",
                 pte, *pte,
                 (ULONG)((*pte & 执念_PTE_PRESENT) ? 1 : 0),
                 (ULONG)((*pte & 执念_PTE_RW) ? 1 : 0),
                 (ULONG)((*pte & 执念_PTE_DIRTY) ? 1 : 0),
                 (ULONG)((*pte & 执念_PTE_LARGE) ? 1 : 0));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[执念-PROBE]   PTE read EXCEPTION 0x%08X\n", GetExceptionCode());
    }
}

// 改 PTE 的 RW 位 -> 写字节 -> 还原 PTE
BOOLEAN 执念WriteCodeViaPte(PVOID Addr, const UCHAR* Bytes, ULONG Len)
{
    PFN_MiGetPteAddress getPte = 执念GetMiGetPteAddress();
    if (!getPte) {
        DbgPrint("[执念-PTE] unavailable (MiGetPteAddress not resolved)\n");
        return FALSE;
    }

    PULONG64 pte = NULL;
    ULONG64  saved = 0;
    BOOLEAN  ok = FALSE;

    __try {
        pte = (PULONG64)getPte(Addr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[执念-PTE] MiGetPteAddress(%p) EXCEPTION 0x%08X\n",
                 Addr, GetExceptionCode());
        return FALSE;
    }

    if (!pte) {
        DbgPrint("[执念-PTE] MiGetPteAddress returned NULL for %p\n", Addr);
        return FALSE;
    }

    DbgPrint("[执念-PTE] pte @ %p = %016llX\n", pte, *pte);

    __try {
        saved = *pte;

        if (!(saved & 执念_PTE_PRESENT)) {
            DbgPrint("[执念-PTE] !! PTE not present, abort\n");
            return FALSE;
        }

        // 置 RW + Dirty
        *pte = saved | 执念_PTE_RW | 执念_PTE_DIRTY;
        DbgPrint("[执念-PTE]   -> set RW, now %016llX\n", *pte);

        // 写字节
        for (ULONG i = 0; i < Len; i++) {
            ((PUCHAR)Addr)[i] = Bytes[i];
            DbgPrint("[执念-PTE]   [%u] %p <- %02X (readback %02X)\n",
                     i, (PUCHAR)Addr + i, Bytes[i], ((PUCHAR)Addr)[i]);
        }

        // 还原 PTE
        *pte = saved;
        DbgPrint("[执念-PTE]   -> PTE restored to %016llX\n", saved);

        __invlpg(Addr);
        ok = TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[执念-PTE] !! EXCEPTION 0x%08X\n", GetExceptionCode());
        __try { *pte = saved; } __except (EXCEPTION_EXECUTE_HANDLER) { }
        ok = FALSE;
    }

    return ok;
}
