//本页负责对ACE重新加载后的回调进行拦截，防止ACE重新注册回调
#include "SignCallBack.h"
#include "SignCallBackConfig.h"

extern PVOID 执念LookupKernelSymbol(_In_ PCSTR SymbolName);
extern BOOLEAN 执念IsAceAddress(PVOID Addr);
extern NTSTATUS 执念DisableAll(VOID);
extern PVOID 执念GetStubForTarget(_In_ 执念_TARGET Target);
static VOID 执念AceLoadNotify(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    if (ProcessId != NULL)   
        return;
    if (!FullImageName || !FullImageName->Buffer)
        return;

    // 判断是不是 ACE-BOOT.sys
    UNICODE_STRING suffix;
    RtlInitUnicodeString(&suffix, 执念_ACE_MODULE_NAME);

    if (FullImageName->Length < suffix.Length)
        return;

    UNICODE_STRING tail;
    tail.Buffer = (PWCHAR)((PUCHAR)FullImageName->Buffer +
                           (FullImageName->Length - suffix.Length));
    tail.Length = suffix.Length;
    tail.MaximumLength = suffix.Length;

    if (!RtlEqualUnicodeString(&tail, &suffix, TRUE))
        return;

    DbgPrint("[执念-WATCH] ACE-BOOT.sys loaded, re-applying disable (pid=%p)\n", ProcessId);
    执念DisableAll();//再来一次禁用
}

static BOOLEAN g_WatchRegistered = FALSE;

NTSTATUS 执念RegisterReloadWatch(VOID)
{
    if (g_WatchRegistered)
        return STATUS_SUCCESS;

#if 执念_ENABLE_PATH_C_REG_BLOCK
    NTSTATUS st = PsSetLoadImageNotifyRoutine(执念AceLoadNotify);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[执念-WATCH] PsSetLoadImageNotifyRoutine failed 0x%08X\n", st);
        return st;
    }
    g_WatchRegistered = TRUE;
    DbgPrint("[执念-WATCH] reload watch registered\n");
#endif
    return STATUS_SUCCESS;
}

VOID 执念UnregisterReloadWatch(VOID)
{
    if (g_WatchRegistered) {
        PsRemoveLoadImageNotifyRoutine(执念AceLoadNotify);
        g_WatchRegistered = FALSE;
        DbgPrint("[执念-WATCH] reload watch unregistered\n");
    }
}
//底下用EPT
static PVOID g_OrigPsSetLoadImageNotify = NULL;
static PVOID g_OrigPsSetCreateProcessNotifyEx = NULL;
static PVOID g_OrigCmRegisterCallbackEx = NULL;
static PVOID g_OrigObRegisterCallbacks = NULL;

typedef NTSTATUS (NTAPI *PFN_PsSetLoadImageNotifyRoutine)(
    PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);

typedef NTSTATUS (NTAPI *PFN_PsSetCreateProcessNotifyRoutineEx)(
    PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine, BOOLEAN Remove);

typedef NTSTATUS (NTAPI *PFN_CmRegisterCallbackEx)(
    PEX_CALLBACK_FUNCTION Function, PCUNICODE_STRING Altitude,
    PVOID Driver, PVOID Context, PLARGE_INTEGER Cookie, PVOID Reserved);

typedef NTSTATUS (NTAPI *PFN_ObRegisterCallbacks)(
    POB_CALLBACK_REGISTRATION Registration, PVOID* RegistrationHandle);
static NTSTATUS NTAPI 执念HookPsSetLoadImageNotify(
    PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine)
{
    if (执念IsAceAddress((PVOID)NotifyRoutine)) {
        DbgPrint("[执念-BLOCK] ACE registration blocked: PsSetLoadImageNotifyRoutine(%p)\n",
                 NotifyRoutine);
        g_执念Slots[执念_TARGET_LOAD_IMAGE].OriginalEntry = (PVOID)NotifyRoutine;
        return STATUS_SUCCESS;
    }
    PFN_PsSetLoadImageNotifyRoutine orig = (PFN_PsSetLoadImageNotifyRoutine)g_OrigPsSetLoadImageNotify;
    return orig ? orig(NotifyRoutine) : STATUS_UNSUCCESSFUL;
}

static NTSTATUS NTAPI 执念HookPsSetCreateProcessNotifyEx(
    PCREATE_PROCESS_NOTIFY_ROUTINE_EX NotifyRoutine, BOOLEAN Remove)
{
    if (执念IsAceAddress((PVOID)NotifyRoutine)) {
        DbgPrint("[执念-BLOCK] ACE registration blocked: PsSetCreateProcessNotifyRoutineEx(%p, rm=%u)\n",
                 NotifyRoutine, Remove);
        g_执念Slots[执念_TARGET_CREATE_PROC].OriginalEntry = (PVOID)NotifyRoutine;
        return STATUS_SUCCESS;
    }
    PFN_PsSetCreateProcessNotifyRoutineEx orig =
        (PFN_PsSetCreateProcessNotifyRoutineEx)g_OrigPsSetCreateProcessNotifyEx;
    return orig ? orig(NotifyRoutine, Remove) : STATUS_UNSUCCESSFUL;
}

static NTSTATUS NTAPI 执念HookCmRegisterCallbackEx(
    PEX_CALLBACK_FUNCTION Function, PCUNICODE_STRING Altitude,
    PVOID Driver, PVOID Context, PLARGE_INTEGER Cookie, PVOID Reserved)
{
    if (执念IsAceAddress((PVOID)Function)) {
        DbgPrint("[执念-BLOCK] ACE registration blocked: CmRegisterCallbackEx(%p, %wZ)\n",
                 Function, Altitude);
        g_执念Slots[执念_TARGET_REGISTRY].OriginalEntry = (PVOID)Function;
        if (Cookie) Cookie->QuadPart = 0;
        return STATUS_SUCCESS;
    }
    PFN_CmRegisterCallbackEx orig = (PFN_CmRegisterCallbackEx)g_OrigCmRegisterCallbackEx;
    return orig ? orig(Function, Altitude, Driver, Context, Cookie, Reserved)
                : STATUS_UNSUCCESSFUL;
}

static NTSTATUS NTAPI 执念HookObRegisterCallbacks(
    POB_CALLBACK_REGISTRATION Registration, PVOID* RegistrationHandle)
{
    if (Registration && Registration->OperationRegistration &&
        Registration->OperationRegistrationCount > 0) {

        POB_OPERATION_REGISTRATION reg = Registration->OperationRegistration;
        for (ULONG i = 0; i < Registration->OperationRegistrationCount; i++) {
            if (执念IsAceAddress(reg[i].PreOperation)) {
                DbgPrint("[执念-BLOCK] ACE registration blocked: ObRegisterCallbacks pre=%p\n",
                         reg[i].PreOperation);
                g_执念Slots[执念_TARGET_PROCESS_OB].OriginalEntry = reg[i].PreOperation;
                if (RegistrationHandle) *RegistrationHandle = NULL;
                return STATUS_SUCCESS;
            }
        }
    }
    PFN_ObRegisterCallbacks orig = (PFN_ObRegisterCallbacks)g_OrigObRegisterCallbacks;
    return orig ? orig(Registration, RegistrationHandle) : STATUS_UNSUCCESSFUL;
}

//安装拦截
NTSTATUS 执念InstallRegistrationBlocks(VOID)
{
    struct {
        PCSTR Sym;
        PVOID Hook;
        PVOID* Orig;
        P执念_SLOT Slot;
    } items[] = {
        { "PsSetLoadImageNotifyRoutine",              (PVOID)执念HookPsSetLoadImageNotify,
          &g_OrigPsSetLoadImageNotify,     &g_执念Slots[执念_TARGET_LOAD_IMAGE] },
        { "PsSetCreateProcessNotifyRoutineEx",        (PVOID)执念HookPsSetCreateProcessNotifyEx,
          &g_OrigPsSetCreateProcessNotifyEx, &g_执念Slots[执念_TARGET_CREATE_PROC] },
        { "CmRegisterCallbackEx",                     (PVOID)执念HookCmRegisterCallbackEx,
          &g_OrigCmRegisterCallbackEx,     &g_执念Slots[执念_TARGET_REGISTRY] },
        { "ObRegisterCallbacks",                      (PVOID)执念HookObRegisterCallbacks,
          &g_OrigObRegisterCallbacks,      &g_执念Slots[执念_TARGET_PROCESS_OB] },
    };

    for (ULONG i = 0; i < ARRAYSIZE(items); i++) {
        PVOID target = 执念LookupKernelSymbol(items[i].Sym);
        if (!target) {
            DbgPrint("[执念-BLOCK] symbol %s not found, skip\n", items[i].Sym);
            continue;
        }

        PVOID orig = NULL;
    }

    return STATUS_SUCCESS;
}
