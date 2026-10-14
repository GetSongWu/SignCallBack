//开源_执念
//QQ:2693529153
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途
//仅供学习交流使用，禁止用于商业用途
#include "SignCallBack.h"
#include "SignCallBackConfig.h"
执念_SLOT       g_执念Slots[执念_TARGET_COUNT] = { 0 };
PDRIVER_OBJECT g_执念SelfDriverObject = NULL;
PVOID          g_执念SelfDriverBase   = NULL;
ULONG          g_执念SelfDriverSize   = 0;
NTSTATUS 执念ApplyEptHooks(VOID);
NTSTATUS 执念ResolveProcessObCallbacksImpl(VOID);
NTSTATUS 执念ResolveShutdownCallbacksImpl(VOID);
PVOID    执念GetStubForTarget(_In_ 执念_TARGET Target);
NTSTATUS 执念ScrubSpecialized(_In_ 执念_TARGET Target, _In_ BOOLEAN Remove);
NTSTATUS 执念ScrubAllAceArrayEntries(VOID);
BOOLEAN  执念IsAceAddress(PVOID Addr);
NTSTATUS 执念RegisterReloadWatch(VOID);
VOID     执念UnregisterReloadWatch(VOID);
NTSTATUS 执念ScrubAceCallbacks(VOID);
NTSTATUS 执念UnscrubAll(VOID);
#define 执念_DEVICE_NAME   L"\\Device\\SignCallBack"
#define 执念_SYMLINK_NAME  L"\\DosDevices\\SignCallBack"
#define 执念_IOCTL_DISABLE_ALL   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define 执念_IOCTL_RESTORE_ALL   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define 执念_IOCTL_QUERY_STATUS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _执念_STATUS_OUT {
    ULONG Magic;            // '执念 ' 
    ULONG HookedMask;       // bit i = slot i hooked
    ULONG ViaEptMask;       // bit i = slot i via EPT 待选项
    ULONG ResolvedMask;     // bit i = slot i resolved
} 执念_STATUS_OUT, *P执念_STATUS_OUT;

static VOID 执念BuildStatus(_Out_ P执念_STATUS_OUT Out)
{
    Out->Magic = 0x20424353;  // '执念 '
    Out->HookedMask = 0;
    Out->ViaEptMask = 0;
    Out->ResolvedMask = 0;

    for (ULONG i = 0; i < 执念_TARGET_COUNT; i++) {
        if (g_执念Slots[i].Hooked)        Out->HookedMask   |= (1u << i);
        if (g_执念Slots[i].ViaEpt)        Out->ViaEptMask   |= (1u << i);
        if (g_执念Slots[i].EntryAddress)  Out->ResolvedMask |= (1u << i);
    }
}
//初始化
static VOID 执念InitSlots(VOID)
{
    g_执念Slots[执念_TARGET_PROCESS_OB].Target = 执念_TARGET_PROCESS_OB;
    g_执念Slots[执念_TARGET_PROCESS_OB].Name   = L"ProcessObCallback(PRE)";

    g_执念Slots[执念_TARGET_CREATE_PROC].Target = 执念_TARGET_CREATE_PROC;
    g_执念Slots[执念_TARGET_CREATE_PROC].Name   = L"CreateProcessEx";

    g_执念Slots[执念_TARGET_LOAD_IMAGE].Target = 执念_TARGET_LOAD_IMAGE;
    g_执念Slots[执念_TARGET_LOAD_IMAGE].Name   = L"LoadImage";

    g_执念Slots[执念_TARGET_REGISTRY].Target = 执念_TARGET_REGISTRY;
    g_执念Slots[执念_TARGET_REGISTRY].Name   = L"CmpCallback";

    g_执念Slots[执念_TARGET_SHUTDOWN].Target = 执念_TARGET_SHUTDOWN;
    g_执念Slots[执念_TARGET_SHUTDOWN].Name   = L"Shutdown";

    g_执念Slots[执念_TARGET_CREATE_THREAD].Target = 执念_TARGET_CREATE_THREAD;
    g_执念Slots[执念_TARGET_CREATE_THREAD].Name   = L"CreateThread";
}
NTSTATUS 执念DisableAll(VOID)
{
    DbgPrint("[执念] 禁用ACE回调\n");

    //计算ACE回调的RVA
    NTSTATUS st = 执念ResolveByRva();
    DbgPrint("[执念] resolve-by-rva -> 0x%08X\n", st);

    if (!NT_SUCCESS(st)) {
        DbgPrint("[执念] !! cannot resolve ACE callbacks, abort\n");
        执念DumpStatus();
        return st;
    }

    // 2. ★ 主操作: ARK 式摘回调
    st = 执念ScrubAceCallbacks();
    DbgPrint("[执念] scrub-ace-callbacks -> 0x%08X\n", st);

#if 执念_WATCH_ACE_RELOAD
    执念RegisterReloadWatch();
#endif

    执念DumpStatus();
    return st;
}

NTSTATUS 执念RestoreAll(VOID)
{
    DbgPrint("[执念] ===== restore all =====\n");

    执念UnscrubAll();

#if 执念_WATCH_ACE_RELOAD
    执念UnregisterReloadWatch();
#endif
    return STATUS_SUCCESS;
}

VOID 执念DumpStatus(VOID)
{
    DbgPrint("[执念] ---- status ----\n");
    for (ULONG i = 0; i < 执念_TARGET_COUNT; i++) {
        P执念_SLOT s = &g_执念Slots[i];
        DbgPrint("[执念] [%u] %-24ws entry=%p orig=%p hooked=%u ept=%u\n",
                 i, s->Name, s->EntryAddress, s->OriginalEntry,
                 s->Hooked, s->ViaEpt);
    }

}
NTSTATUS 执念DisableTarget(_In_ 执念_TARGET Target)
{
    if (Target >= 执念_TARGET_COUNT) return STATUS_INVALID_PARAMETER;
    P执念_SLOT s = &g_执念Slots[Target];
    if (!s->EntryAddress) return STATUS_NOT_FOUND;
    UNREFERENCED_PARAMETER(s);
    return 执念ScrubAceCallbacks();
}

NTSTATUS 执念RestoreTarget(_In_ 执念_TARGET Target)
{
    UNREFERENCED_PARAMETER(Target);
    return 执念UnscrubAll();
}
static NTSTATUS 执念Dispatch(PDEVICE_OBJECT DevObj, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);

    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    ULONG info = 0;

    switch (sp->Parameters.DeviceIoControl.IoControlCode) {

    case 执念_IOCTL_DISABLE_ALL:
        status = 执念DisableAll();
        break;

    case 执念_IOCTL_RESTORE_ALL:
        status = 执念RestoreAll();
        break;

    case 执念_IOCTL_QUERY_STATUS:
        if (sp->Parameters.DeviceIoControl.OutputBufferLength >= sizeof(执念_STATUS_OUT)) {
            P执念_STATUS_OUT out = (P执念_STATUS_OUT)Irp->AssociatedIrp.SystemBuffer;
            执念BuildStatus(out);
            info = sizeof(执念_STATUS_OUT);
            status = STATUS_SUCCESS;
        } else {
            status = STATUS_BUFFER_TOO_SMALL;
        }
        break;

    default:
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}
static PDEVICE_OBJECT g_执念DeviceObject = NULL;

VOID 执念DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    //卸载驱动
    UNREFERENCED_PARAMETER(DriverObject);
    执念RestoreAll();
    执念UnregisterReloadWatch();
    执念FreeSymbolTable();
    UNICODE_STRING symName;
    RtlInitUnicodeString(&symName, 执念_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symName);

    if (g_执念DeviceObject) {
        IoDeleteDevice(g_执念DeviceObject);
        g_执念DeviceObject = NULL;
    }

}
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    g_执念SelfDriverObject = DriverObject;
    执念InitSlots();
    g_执念SelfDriverBase = DriverObject->DriverStart;
    g_执念SelfDriverSize = DriverObject->DriverSize;
    UNICODE_STRING devName, symName;
    RtlInitUnicodeString(&devName, 执念_DEVICE_NAME);
    RtlInitUnicodeString(&symName, 执念_SYMLINK_NAME);

    NTSTATUS st = IoCreateDevice(
        DriverObject, 0, &devName,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_执念DeviceObject);
    if (!NT_SUCCESS(st)) {
        DbgPrint("[执念] IoCreateDevice failed 0x%08X\n", st);
    } else {
        IoCreateSymbolicLink(&symName, &devName);
        DriverObject->MajorFunction[IRP_MJ_CREATE]         = 执念Dispatch;
        DriverObject->MajorFunction[IRP_MJ_CLOSE]          = 执念Dispatch;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = 执念Dispatch;
        DbgPrint("[执念] device created: %ws\n", 执念_SYMLINK_NAME);
    }

   //卸载回调
    DriverObject->DriverUnload = 执念DriverUnload;
    执念Diagnose();

    // 立即执行一次禁用
    执念DisableAll();

    return STATUS_SUCCESS;
}
