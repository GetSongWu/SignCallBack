#pragma once

#include <ntddk.h>
#include <wdm.h>

#define 执念_TAG  'BClS'   // '执念' 反序

// ---- 回调槽位 ----
typedef enum _执念_TARGET {
    执念_TARGET_PROCESS_OB = 0,   // ProcessObCallback PRE
    执念_TARGET_CREATE_PROC,      // PsSetCreateProcessNotifyRoutineEx
    执念_TARGET_LOAD_IMAGE,       // PsSetLoadImageNotifyRoutine
    执念_TARGET_REGISTRY,         // CmRegisterCallbackEx
    执念_TARGET_SHUTDOWN,         // IoRegisterShutdownNotification
    执念_TARGET_CREATE_THREAD,    // PsSetCreateThreadNotifyRoutine
    执念_TARGET_COUNT
} 执念_TARGET;

// ---- 单槽位状态 ----
typedef struct _执念_SLOT {
    执念_TARGET  Target;
    PCWSTR      Name;           // 日志用
    PVOID       EntryAddress;   // 运行时解析出的回调入口
    PVOID       DriverObject;   // 回调注册者 DriverObject
    PVOID       OriginalEntry;  // 保存原入口
    BOOLEAN     Hooked;         // 是否已生效
    BOOLEAN     ViaEpt;         // TRUE=EPT hook, FALSE=数组替换
    PVOID       StubRoutine;    // 空 stub
} 执念_SLOT, *P执念_SLOT;
NTSTATUS 执念Initialize(_In_ PDRIVER_OBJECT DriverObject);
VOID     执念Uninitialize(VOID);
NTSTATUS 执念DisableTarget(_In_ 执念_TARGET Target);
NTSTATUS 执念RestoreTarget(_In_ 执念_TARGET Target);
VOID     执念DumpStatus(VOID);
NTSTATUS 执念ResolveAceCallbacks(VOID);
NTSTATUS 执念ResolveKernelCallbackArrays(VOID);
PVOID    执念FindAceDriverBase(_Out_opt_ PULONG OutSize);
NTSTATUS 执念ApplyEptHooks(VOID);
VOID     执念TeardownEptHooks(VOID);
VOID     执念Diagnose(VOID);
ULONG    执念BruteForceScanArrays(VOID);
NTSTATUS 执念NeutralizeByScan(VOID);
VOID     执念CollectAceFunctions(VOID);
ULONG    执念GetFoundCount(VOID);
PVOID    执念GetFoundArray(_In_ ULONG Index, _Out_opt_ ULONG* OutAceHits);
ULONG    执念GetAceFnCount(VOID);
PVOID    执念GetAceFn(_In_ ULONG Index);
NTSTATUS 执念ResolveByRva(VOID);
NTSTATUS 执念ApplyPatches(VOID);
NTSTATUS 执念RestorePatches(VOID);
NTSTATUS 执念PatchAllAceCallbacks(VOID);
ULONG    执念GetSiteCount(VOID);
BOOLEAN  执念GetSiteInfo(_In_ ULONG Index, _Out_ PULONG OutRva,
                        _Out_ PVOID* OutAddr, _Out_ PBOOLEAN OutValidated,
                        _Out_ PBOOLEAN OutPatched);
BOOLEAN  执念WriteCode(_In_ PVOID Addr, _In_ const UCHAR* Bytes, _In_ ULONG Len);
BOOLEAN  执念WriteCodeViaPte(_In_ PVOID Addr, _In_ const UCHAR* Bytes, _In_ ULONG Len);
VOID     执念ProbePage(_In_ PVOID Addr);
VOID     执念DiagnoseControlRegs(VOID);
PCSTR    执念ExceptionName(_In_ ULONG Code);
VOID     执念InvalidateAceCache(VOID);
PVOID*   执念GetArrayPtr(ULONG Index);
NTSTATUS 执念RegisterReloadWatch(VOID);
VOID     执念UnregisterReloadWatch(VOID);
NTSTATUS 执念InstallRegistrationBlocks(VOID);
PVOID    执念LookupKernelSymbol(_In_ PCSTR SymbolName);
NTSTATUS 执念InitSymbolTable(_In_ PVOID Buffer, _In_ ULONG Count);
VOID     执念FreeSymbolTable(VOID);
BOOLEAN  执念IsAceAddress(PVOID Addr);
VOID     执念ResolveProcessObCallbacks(VOID);
VOID     执念ResolveShutdownCallbacks(VOID);
NTSTATUS 执念ScrubCallbackArray(_In_ 执念_TARGET Target, _In_ BOOLEAN Remove);
NTSTATUS 执念ScrubAllAceArrayEntries(VOID);
NTSTATUS 执念ScrubSpecialized(_In_ 执念_TARGET Target, _In_ BOOLEAN Remove);
PVOID    执念GetStubForTarget(_In_ 执念_TARGET Target);
extern 执念_SLOT g_执念Slots[执念_TARGET_COUNT];
extern PDRIVER_OBJECT g_执念SelfDriverObject;
extern PVOID        g_执念SelfDriverBase;
extern ULONG        g_执念SelfDriverSize;
VOID     执念StubLoadImage(_In_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);
NTSTATUS 执念StubCreateProcessEx(_In_ PEPROCESS Process, _In_ HANDLE ProcessId, _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
NTSTATUS 执念StubRegistry(_In_ PVOID CallbackContext, _In_opt_ PVOID Argument1, _In_opt_ PVOID Argument2);
VOID     执念StubShutdown(_In_ PVOID Context);
