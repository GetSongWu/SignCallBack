//本页为补全
#include "SignCallBack.h"
#include "SignCallBackConfig.h"
extern PVOID 执念LookupKernelSymbol(_In_ PCSTR SymbolName);
extern BOOLEAN 执念IsAceAddress(PVOID Addr);

// _OBJECT_TYPE 里的 CallbackList 偏移
// Win10 20H1 ~ Win11 24H2 都在 0xC8 ~ 0xE0 之间，所以一般不用大改
#define 执念_OBTYPE_CALLBACKLIST_OFFSET  0x0C8
#define 执念_OBTYPE_CALLBACKLIST_OFFSET2 0x0E0

typedef struct _执念_OBJECT_TYPE {
    UCHAR Pad[0x200];
} 执念_OBJECT_TYPE, *P执念_OBJECT_TYPE;

typedef struct _执念_OT_CALLBACK {
    LIST_ENTRY CallbackList;        // +0x00
    ULONG      CallbackOperations;  // +0x10
    PVOID      Operations;          // +0x18  -> OB_OPERATION_REGISTRATION[]
} 执念_OT_CALLBACK, *P执念_OT_CALLBACK;

// OB_OPERATION_REGISTRATION
typedef struct _执念_OB_OP_REG {
    PVOID ObjectType;                       // +0x00
    PVOID PreOperation;                     // +0x08
    PVOID PostOperation;                    // +0x10
    ULONG Operations;                       // +0x18
} 执念_OB_OP_REG, *P执念_OB_OP_REG;

VOID 执念ResolveProcessObCallbacks(VOID)
{
    PVOID types[2] = { PsProcessType, PsThreadType };

    for (ULONG t = 0; t < 2; t++) {
        PVOID objType = types[t];
        if (!objType || !MmIsAddressValid(objType))
            continue;

        ULONG offsets[2] = { 执念_OBTYPE_CALLBACKLIST_OFFSET,
                             执念_OBTYPE_CALLBACKLIST_OFFSET2 };

        for (ULONG o = 0; o < 2; o++) {
            PLIST_ENTRY head = (PLIST_ENTRY)((PUCHAR)objType + offsets[o]);
            if (!MmIsAddressValid(head)) continue;
            if (!MmIsAddressValid(head->Flink)) continue;
            if (head->Flink == head) continue;   // 空链

            PLIST_ENTRY cur = head->Flink;
            ULONG guard = 0;
            while (cur && cur != head && guard++ < 64) {
                if (!MmIsAddressValid(cur)) break;

                P执念_OT_CALLBACK cb = (P执念_OT_CALLBACK)cur;
                PVOID ops = cb->Operations;

                if (ops && MmIsAddressValid(ops)) {
                    P执念_OB_OP_REG reg = (P执念_OB_OP_REG)ops;
                    for (ULONG r = 0; r < 4; r++) {
                        if (!MmIsAddressValid(&reg[r])) break;
                        PVOID pre = reg[r].PreOperation;
                        if (pre && 执念IsAceAddress(pre)) {
                            P执念_SLOT slot = &g_执念Slots[执念_TARGET_PROCESS_OB];
                            if (!slot->EntryAddress) {
                                slot->EntryAddress = cur;
                                slot->OriginalEntry = pre;
                                slot->DriverObject = objType;
                                DbgPrint("[执念] ProcessOb PRE ACE node=%p pre=%p\n",
                                         cur, pre);
                            }
                        }
                    }
                }
                cur = cur->Flink;
            }

            if (g_执念Slots[执念_TARGET_PROCESS_OB].EntryAddress)
                break;
        }

        if (g_执念Slots[执念_TARGET_PROCESS_OB].EntryAddress)
            break;
    }
}


// Shutdown
//
// struct _POP_SHUTDOWN_ENTRY {
//     LIST_ENTRY List;          // +0x00
//     PVOID      DeviceObject;  // +0x10
//     PVOID      NotifyRoutine;// +0x18  回调函数
//     PVOID      Context;       // +0x20
//     ULONG      Flags;         // +0x28
// };
//
// 链表头: nt!PopShutdownListHead

typedef struct _执念_SHUTDOWN_ENTRY {
    LIST_ENTRY List;            // +0x00
    PVOID      DeviceObject;    // +0x10
    PVOID      NotifyRoutine;   // +0x18
    PVOID      Context;         // +0x20
    ULONG      Flags;           // +0x28
} 执念_SHUTDOWN_ENTRY, *P执念_SHUTDOWN_ENTRY;

VOID 执念ResolveShutdownCallbacks(VOID)
{
    PVOID headAddr = 执念LookupKernelSymbol("PopShutdownListHead");
    if (!headAddr) {
        DbgPrint("[执念] PopShutdownListHead symbol not available\n");
        return;
    }

    PLIST_ENTRY head = (PLIST_ENTRY)headAddr;
    if (!MmIsAddressValid(head)) return;

    PLIST_ENTRY cur = head->Flink;
    ULONG guard = 0;

    while (cur && cur != head && guard++ < 64) {
        if (!MmIsAddressValid(cur)) break;

        P执念_SHUTDOWN_ENTRY e = (P执念_SHUTDOWN_ENTRY)cur;
        if (MmIsAddressValid(e->NotifyRoutine) && 执念IsAceAddress(e->NotifyRoutine)) {
            P执念_SLOT slot = &g_执念Slots[执念_TARGET_SHUTDOWN];
            if (!slot->EntryAddress) {
                slot->EntryAddress = cur;
                slot->OriginalEntry = e->NotifyRoutine;
                slot->DriverObject = e->DeviceObject;
                DbgPrint("[执念] Shutdown ACE entry=%p fn=%p\n", cur, e->NotifyRoutine);
            }
        }
        cur = cur->Flink;
    }
}
