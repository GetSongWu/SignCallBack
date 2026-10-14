//此页为最核心的stub实现！
#include "SignCallBack.h"
#include "SignCallBackConfig.h"

#if 执念_TRACE_CALLBACK_FIRE
#define 执念_FIRE_LOG(fmt, ...) DbgPrint("[执念-FIRE] " fmt, __VA_ARGS__)
#else
#define 执念_FIRE_LOG(fmt, ...) ((void)0)
#endif
// LoadImage
VOID 执念StubLoadImage(
    _In_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(FullImageName);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ImageInfo);
    执念_FIRE_LOG("LoadImage swallowed pid=%p\n", ProcessId);
}

// CreateProcessEx (Pre-create)
NTSTATUS 执念StubCreateProcessEx(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(CreateInfo);
    执念_FIRE_LOG("CreateProc swallowed pid=%p\n", ProcessId);
    return STATUS_SUCCESS;
}

//  CmRegisterCallbackEx
NTSTATUS 执念StubRegistry(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);
    执念_FIRE_LOG("Registry swallowed\n");
    return STATUS_SUCCESS;
}

// Shutdown
VOID 执念StubShutdown(_In_ PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);
    执念_FIRE_LOG("Shutdown swallowed\n");
}

// ObRegisterCallbacks PRE
typedef struct _执念_OB_PRE_OP_INFO {
    ULONG  Operation;           // +0x00  OB_OPERATION_HANDLE_CREATE=1 / DUPLICATE=2
    ULONG  Flags;               // +0x04
    PVOID  Parameters;          // +0x08
    PVOID  Object;              // +0x10
    PVOID  ObjectType;          // +0x18
    PVOID  CallContext;         // +0x20
} 执念_OB_PRE_OP_INFO, *P执念_OB_PRE_OP_INFO;

NTSTATUS 执念StubObPre(
    _In_ PVOID RegistrationContext,
    _In_ PVOID OperationInformation,
    _In_ PVOID Unused1,
    _In_ PVOID Unused2,
    _In_ PVOID Unused3)
{
    UNREFERENCED_PARAMETER(RegistrationContext);
    UNREFERENCED_PARAMETER(OperationInformation);
    UNREFERENCED_PARAMETER(Unused1);
    UNREFERENCED_PARAMETER(Unused2);
    UNREFERENCED_PARAMETER(Unused3);
    执念_FIRE_LOG("ObPre swallowed\n");
    return STATUS_SUCCESS;
}
