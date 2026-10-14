//本页主要负责符号解析
//主要分为导出和未导出符号的解析
#include "SignCallBack.h"
#include "SignCallBackConfig.h"

#define 执念_MAX_SYMBOLS 512
#define 执念_SYMBOL_NAME_MAX 64

typedef struct _执念_SYMBOL {
    CHAR  Name[执念_SYMBOL_NAME_MAX];
    PVOID Address;
} 执念_SYMBOL, *P执念_SYMBOL;

static 执念_SYMBOL* g_SymbolTable = NULL;
static ULONG       g_SymbolCount = 0;
//初始化符号表
NTSTATUS 执念InitSymbolTable(_In_ PVOID Buffer, _In_ ULONG Count)
{
    if (!Buffer || Count == 0 || Count > 执念_MAX_SYMBOLS)
        return STATUS_INVALID_PARAMETER;

    if (g_SymbolTable) {
        ExFreePoolWithTag(g_SymbolTable, 执念_TAG);
        g_SymbolTable = NULL;
        g_SymbolCount = 0;
    }

    ULONG size = Count * sizeof(执念_SYMBOL);
    g_SymbolTable = (P执念_SYMBOL)ExAllocatePoolWithTag(NonPagedPool, size, 执念_TAG);
    if (!g_SymbolTable)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(g_SymbolTable, Buffer, size);
    g_SymbolCount = Count;
    DbgPrint("[执念-SYM] loaded %u symbols\n", Count);

    return STATUS_SUCCESS;
}
// 符号解析
// 优先: 注入的符号表
// 降级: MmGetSystemRoutineAddress (只能导出不然取不到)
PVOID 执念LookupKernelSymbol(_In_ PCSTR SymbolName)
{
    if (!SymbolName)
        return NULL;

    // 1. 符号表
    if (g_SymbolTable) {
        for (ULONG i = 0; i < g_SymbolCount; i++) {
            if (_stricmp(g_SymbolTable[i].Name, SymbolName) == 0)
                return g_SymbolTable[i].Address;
        }
    }
    SIZE_T len = 0;
    while (SymbolName[len] && len < 256)
        len++;

    WCHAR wide[260] = { 0 };
    for (SIZE_T i = 0; i < len; i++)
        wide[i] = (WCHAR)(UCHAR)SymbolName[i];
    wide[len] = L'\0';

    UNICODE_STRING uni;
    RtlInitUnicodeString(&uni, wide);

    return MmGetSystemRoutineAddress(&uni);
}
VOID 执念FreeSymbolTable(VOID)
{
    if (g_SymbolTable) {
        ExFreePoolWithTag(g_SymbolTable, 执念_TAG);
        g_SymbolTable = NULL;
        g_SymbolCount = 0;
    }
}
