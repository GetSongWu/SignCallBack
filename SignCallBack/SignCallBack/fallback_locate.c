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

// ---------------------------------------------------------------------------
// 方法二: 直接按名字打开 Driver 对象 (最可靠)
// ---------------------------------------------------------------------------

typedef NTSTATUS (NTAPI *PFN_ObReferenceObjectByName)(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext,
    PVOID* Object);

typedef VOID (NTAPI *PFN_ObfDereferenceObject)(PVOID Object);
extern POBJECT_TYPE IoDriverObjectType;
PVOID 执念FindDriverObjectByName(_In_ PCWSTR DriverName)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, DriverName);

    //从ntoskrnl找
    extern PVOID 执念LookupKernelSymbol(_In_ PCSTR SymbolName);
    PFN_ObReferenceObjectByName pObRef =
        (PFN_ObReferenceObjectByName)执念LookupKernelSymbol("ObReferenceObjectByName");

    if (!pObRef) {
        DbgPrint("[执念-FB] ObReferenceObjectByName not resolved\n");
        return NULL;
    }

    PVOID drvObj = NULL;
    NTSTATUS st = pObRef(&name,
                         OBJ_CASE_INSENSITIVE,
                         NULL,
                         FILE_ANY_ACCESS,
                         IoDriverObjectType,
                         KernelMode,
                         NULL,
                         &drvObj);

    if (!NT_SUCCESS(st)) {
        DbgPrint("[执念-FB] ObReferenceObjectByName(%ws) -> 0x%08X\n", DriverName, st);
        return NULL;
    }

    DbgPrint("[执念-FB] driver object for %ws = %p\n", DriverName, drvObj);
    return drvObj;
}

// 从 DRIVER_OBJECT 拿 base/size
// _DRIVER_OBJECT 布局:
//   +0x00 CSHORT Type
//   +0x02 CSHORT Size
//   +0x08 PDEVICE_OBJECT DeviceObject
//   +0x10 ULONG Flags
//   +0x18 PVOID DriverStart      ← 基址
//   +0x20 ULONG DriverSize       ← 大小
//   +0x28 PVOID DriverSection
//   +0x30 PVOID DriverExtension
//   +0x38 UNICODE_STRING DriverName
BOOLEAN 执念GetDriverRangeFromObject(
    _In_ PVOID DriverObject,
    _Out_ PVOID* OutBase,
    _Out_ PULONG OutSize)
{
    *OutBase = NULL;
    *OutSize = 0;

    if (!DriverObject || !MmIsAddressValid(DriverObject))
        return FALSE;

    __try {
        PVOID start = *(PVOID*)((PUCHAR)DriverObject + 0x18);
        ULONG size  = *(ULONG*)((PUCHAR)DriverObject + 0x20);

        if (!start || size == 0 || size > 0x10000000)
            return FALSE;

        *OutBase = start;
        *OutSize = size;
        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}
static PVOID g_FbAceBase = NULL;
static ULONG g_FbAceSize = 0;
static BOOLEAN g_FbResolved = FALSE;

BOOLEAN 执念FallbackResolveAceRange(VOID)
{
    if (g_FbResolved)
        return g_FbAceBase != NULL;

    g_FbResolved = TRUE;
    //匹配ACE对象
    PCWSTR names[] = {
        L"\\Driver\\ACE-BOOT",
        L"\\Driver\\ACE-BASE",
        L"\\Driver\\ACE-CORE",
        L"\\Driver\\ACE-BOOT64",
    };

    for (ULONG i = 0; i < ARRAYSIZE(names); i++) {
        PVOID drvObj = 执念FindDriverObjectByName(names[i]);
        if (!drvObj)
            continue;

        PVOID base = NULL;
        ULONG size = 0;
        if (执念GetDriverRangeFromObject(drvObj, &base, &size)) {
            g_FbAceBase = base;
            g_FbAceSize = size;
            DbgPrint("[执念-FB] ACE range from driver object: base=%p size=0x%X\n",
                     base, size);
            ObDereferenceObject(drvObj);
            return TRUE;
        }
        ObDereferenceObject(drvObj);
    }

    DbgPrint("[执念-FB] fallback resolve failed for all ACE names\n");
    return FALSE;
}

PVOID 执念FallbackAceBase(_Out_opt_ PULONG OutSize)
{
    if (!g_FbResolved)
        执念FallbackResolveAceRange();
    if (OutSize) *OutSize = g_FbAceSize;
    return g_FbAceBase;
}

BOOLEAN 执念IsAceAddressEx(PVOID Addr)
{
    if (!Addr) return FALSE;
    extern BOOLEAN 执念IsAceAddress(PVOID Addr);
    if (执念IsAceAddress(Addr))
        return TRUE;
    ULONG size = 0;
    PVOID base = 执念FallbackAceBase(&size);
    if (!base || !size)
        return FALSE;

    ULONG_PTR a = (ULONG_PTR)Addr;
    ULONG_PTR b = (ULONG_PTR)base;
    return (a >= b && a < b + size);
}
BOOLEAN 执念TryContextAsDriverObject(
    _In_ PVOID Context,
    _Out_ PVOID* OutBase,
    _Out_ PULONG OutSize)
{
    *OutBase = NULL;
    *OutSize = 0;

    if (!Context || !MmIsAddressValid(Context))
        return FALSE;

    __try {
        // 检查 +0x38 是否为 UNICODE_STRING 的 DriverName
        PUNICODE_STRING pName = (PUNICODE_STRING)((PUCHAR)Context + 0x38);
        if (!MmIsAddressValid(pName) || !MmIsAddressValid(pName->Buffer))
            return FALSE;

        if (pName->Length < 2 || pName->Length > 0x100)
            return FALSE;
        if ((pName->Length & 1) != 0)
            return FALSE;

        //试着找ACE启动的驱动名字样
        if (pName->Length >= 24) {   // 至少 "\Driver\ACE" 
            WCHAR buf[64] = { 0 };
            ULONG n = pName->Length / sizeof(WCHAR);
            if (n > 63) n = 63;
            for (ULONG i = 0; i < n; i++)
                buf[i] = pName->Buffer[i];
            for (ULONG i = 0; i + 6 < n; i++) {
                WCHAR a = buf[i], b = buf[i+1], c = buf[i+2],
                      d = buf[i+3], e = buf[i+4], f = buf[i+5], g = buf[i+6];
                if (a=='\\' &&
                    (b=='D'||b=='d') && (c=='r'||c=='R') && (d=='i'||d=='I') &&
                    (e=='v'||e=='V') && (f=='e'||f=='E') && (g=='r'||g=='R')) {
                    if (i + 9 < n) {
                        WCHAR x1 = buf[i+8], x2 = buf[i+9], x3 = buf[i+10];
                        if ((x1=='A'||x1=='a') && (x2=='C'||x2=='c') && (x3=='E'||x3=='e')) {
                            PVOID base = NULL; ULONG size = 0;
                            if (执念GetDriverRangeFromObject(Context, &base, &size)) {
                                *OutBase = base;
                                *OutSize = size;
                                DbgPrint("[执念-FB] Context->DriverObject matched: base=%p size=0x%X\n",
                                         base, size);
                                return TRUE;
                            }
                        }
                    }
                }
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return FALSE;
}
