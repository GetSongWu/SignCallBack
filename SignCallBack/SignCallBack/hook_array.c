//本项目是开源的！如果你是被收费的骗了，请申请退款！
//开源_执念
//QQ:2693529153
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途
#include "SignCallBack.h"
#include "SignCallBackConfig.h"
extern PVOID      执念LookupKernelSymbol(_In_ PCSTR SymbolName);
extern BOOLEAN    执念IsAceAddress(PVOID Addr);
extern BOOLEAN    执念CallbackBelongsToAce(_In_ PVOID BlockOrFunc);
NTSTATUS 执念ScrubSpecialized(_In_ 执念_TARGET Target, _In_ BOOLEAN Remove);
PVOID    执念GetStubForTarget(_In_ 执念_TARGET Target);
static KIRQL 执念WpOff(VOID)
{
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    ULONG_PTR cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000ULL);   // 清除WP  16位
    return irql;
}

static VOID 执念WpOn(KIRQL irql, ULONG_PTR savedCr0)
{
    __writecr0(savedCr0);
    KeLowerIrql(irql);
}
static ULONG_PTR g_SavedCr0 = 0;

static VOID 执念WriteKernelPtr(PVOID* Where, PVOID Value)
{
    KIRQL irql = KeRaiseIrqlToDpcLevel();
    ULONG_PTR cr0 = __readcr0();
    __writecr0(cr0 & ~0x10000ULL);

    InterlockedExchangePointer(Where, Value);

    __writecr0(cr0);
    KeLowerIrql(irql);
}

//替换回调函数
typedef struct _执念_CALLBACK_BLOCK {
    ULONG_PTR RundownProtect;   // +0x00
    PVOID     Function;         // +0x08
    PVOID     Context;          // +0x10
} 执念_CALLBACK_BLOCK, *P执念_CALLBACK_BLOCK;

NTSTATUS 执念ScrubCallbackArray(_In_ 执念_TARGET Target, _In_ BOOLEAN Remove)
{
    if (Target >= 执念_TARGET_COUNT)
        return STATUS_INVALID_PARAMETER;

    P执念_SLOT slot = &g_执念Slots[Target];
    if (!slot->EntryAddress) {
        DbgPrint("[执念] scrub: target %u has no entry resolved\n", Target);
        return STATUS_NOT_FOUND;
    }

    PVOID entry = slot->EntryAddress;
    if (!MmIsAddressValid(entry))
        return STATUS_INVALID_ADDRESS;

    P执念_CALLBACK_BLOCK blk = (P执念_CALLBACK_BLOCK)entry;
    if (blk->Function != slot->OriginalEntry) {
        DbgPrint("[执念] scrub: entry %p not a Ps block, using specialized path\n", entry);
        return 执念ScrubSpecialized(Target, Remove);
    }

    if (Remove) {
        执念WriteKernelPtr(&blk->Function, slot->OriginalEntry);
        slot->Hooked = FALSE;
        DbgPrint("[执念] restored target %u fn=%p\n", Target, slot->OriginalEntry);
    } else {
#if 执念_ARRAY_USE_STUB_INSTEAD_OF_NULL
        PVOID stub = 执念GetStubForTarget(Target);
        if (!stub) return STATUS_NOT_SUPPORTED;
        执念WriteKernelPtr(&blk->Function, stub);
        DbgPrint("[执念] scrubbed target %u: %p -> stub %p\n", Target, slot->OriginalEntry, stub);
#else
        执念WriteKernelPtr(&blk->Function, NULL);
        DbgPrint("[执念] nulled target %u\n", Target);
#endif
        slot->Hooked = TRUE;
        slot->ViaEpt = FALSE;
    }

    return STATUS_SUCCESS;
}
static NTSTATUS 执念ScrubRegistryNode(_In_ P执念_SLOT slot, _In_ BOOLEAN Remove)
{
    PVOID node = slot->EntryAddress;
    if (!MmIsAddressValid(node)) return STATUS_INVALID_ADDRESS;
    PVOID* p = (PVOID*)node;
    for (ULONG k = 0; k < 16; k++) {
        if (!MmIsAddressValid(&p[k])) break;
        if (p[k] == slot->OriginalEntry) {
            PVOID newVal = Remove ? slot->OriginalEntry
                                  : 执念GetStubForTarget(执念_TARGET_REGISTRY);
            执念WriteKernelPtr(&p[k], newVal);
            slot->Hooked = !Remove;
            DbgPrint("[执念] registry node %p slot[%u] %p -> %p\n",
                     node, k, slot->OriginalEntry, newVal);
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

static NTSTATUS 执念ScrubShutdownNode(_In_ P执念_SLOT slot, _In_ BOOLEAN Remove)
{
    PVOID node = slot->EntryAddress;
    if (!MmIsAddressValid(node)) return STATUS_INVALID_ADDRESS;
    PVOID* fnField = (PVOID*)((PUCHAR)node + 0x18);
    if (!MmIsAddressValid(fnField)) return STATUS_INVALID_ADDRESS;
    if (*fnField != slot->OriginalEntry) {
        return 执念ScrubRegistryNode(slot, Remove);
    }

    PVOID newVal = Remove ? slot->OriginalEntry
                          : 执念GetStubForTarget(执念_TARGET_SHUTDOWN);
    执念WriteKernelPtr(fnField, newVal);
    slot->Hooked = !Remove;
    DbgPrint("[执念] shutdown node %p fn %p -> %p\n",
             node, slot->OriginalEntry, newVal);
    return STATUS_SUCCESS;
}
static NTSTATUS 执念ScrubObNode(_In_ P执念_SLOT slot, _In_ BOOLEAN Remove)
{
    PVOID node = slot->EntryAddress;
    if (!MmIsAddressValid(node)) return STATUS_INVALID_ADDRESS;
    PVOID* p = (PVOID*)node;
    for (ULONG k = 0; k < 32; k++) {
        if (!MmIsAddressValid(&p[k])) break;
        if (p[k] == slot->OriginalEntry) {
            PVOID newVal = Remove ? slot->OriginalEntry
                                  : 执念GetStubForTarget(执念_TARGET_PROCESS_OB);
            执念WriteKernelPtr(&p[k], newVal);
            slot->Hooked = !Remove;
            DbgPrint("[执念] ob node %p slot[%u] %p -> %p\n",
                     node, k, slot->OriginalEntry, newVal);
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

NTSTATUS 执念ScrubSpecialized(_In_ 执念_TARGET Target, _In_ BOOLEAN Remove)
{
    P执念_SLOT slot = &g_执念Slots[Target];
    switch (Target) {
    case 执念_TARGET_REGISTRY:   return 执念ScrubRegistryNode(slot, Remove);
    case 执念_TARGET_SHUTDOWN:   return 执念ScrubShutdownNode(slot, Remove);
    case 执念_TARGET_PROCESS_OB: return 执念ScrubObNode(slot, Remove);
    default:                    return STATUS_NOT_SUPPORTED;
    }
}
NTSTATUS 执念ScrubAllAceArrayEntries(VOID)
{
    NTSTATUS last = STATUS_SUCCESS;
    for (ULONG t = 0; t < 执念_TARGET_COUNT; t++) {
        if (!g_执念Slots[t].EntryAddress) continue;
        NTSTATUS st = 执念ScrubCallbackArray((执念_TARGET)t, FALSE);
        if (!NT_SUCCESS(st))
            last = st;
    }
    return last;
}
extern VOID     执念StubLoadImage(PUNICODE_STRING, HANDLE, PIMAGE_INFO);
extern NTSTATUS 执念StubCreateProcessEx(PEPROCESS, HANDLE, PPS_CREATE_NOTIFY_INFO);
extern NTSTATUS 执念StubRegistry(PVOID, PVOID, PVOID);
extern VOID     执念StubShutdown(PVOID);
extern NTSTATUS 执念StubObPre(PVOID, PVOID, PVOID, PVOID, PVOID);

PVOID 执念GetStubForTarget(_In_ 执念_TARGET Target)
{
    P执念_SLOT s = &g_执念Slots[Target];
    if (s->StubRoutine)
        return s->StubRoutine;

    PVOID stub = NULL;
    switch (Target) {
    case 执念_TARGET_LOAD_IMAGE:   stub = (PVOID)执念StubLoadImage;        break;
    case 执念_TARGET_CREATE_PROC:  stub = (PVOID)执念StubCreateProcessEx;  break;
    case 执念_TARGET_REGISTRY:     stub = (PVOID)执念StubRegistry;         break;
    case 执念_TARGET_SHUTDOWN:     stub = (PVOID)执念StubShutdown;         break;
    case 执念_TARGET_PROCESS_OB:   stub = (PVOID)执念StubObPre;            break;
    default: break;
    }
    s->StubRoutine = stub;
    return stub;
}
