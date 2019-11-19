#pragma once
#pragma warning(disable: 4201)
#pragma warning(disable: 4324)
#define NDIS_SUPPORT_NDIS6 1
#define OPEN_EXISTING      3
#define MAX_DATA_SIZE      255
#define NT_DEVICE_NAME L"\\Device\\EzFireWall"
#define DOS_DEVICE_NAME  L"\\DosDevices\\EzFireWall"
#define TAG_NAME_NOTIFY 'EzFw'
#define TAG_NAME_REPORT 'EzRP'
#define TAG_NAME_BUFFDATA 'EzBT'
#define TAG_NAME_BLACKLISTDATA 'EzBD'
#define DPRINT(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define INRANGE(x,a,b)    (x >= a && x <= b) 
#define getBits( x )    (INRANGE((x&(~0x20)),'A','F') ? ((x&(~0x20)) - 'A' + 0xa) : (INRANGE(x,'0','9') ? x - '0' : 0))
#define getByte( x )    (getBits(x[0]) << 4 | getBits(x[1]))
#include <ntifs.h>
#include <ntddk.h>
#include <ndis.h>
#include <fwpsk.h>
#include <fwpmk.h>
#include <wdm.h>
#define INITGUID
#include <guiddef.h>

#define IOCTL_ADD_BLACKLIST_DATA \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1337, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
// 
// Callout and sublayer GUIDs
//

// 76b743d4-1249-4614-a632-6f9c4d08d25a
DEFINE_GUID(
	SF_ALE_CONNECT_CALLOUT_V4,
	0x76b743d4,
	0x1249,
	0x4614,
	0xa6, 0x32, 0x6f, 0x9c, 0x4d, 0x08, 0xd2, 0x5a
);

// 7ec7f7f5-0c55-4121-adc5-5d07d2ac0cef
DEFINE_GUID(
	SF_ALE_RECV_ACCEPT_CALLOUT_V4,
	0x7ec7f7f5,
	0x0c55,
	0x4121,
	0xad, 0xc5, 0x5d, 0x07, 0xd2, 0xac, 0x0c, 0xef
);

// 2e207682-d95f-4525-b966-969f26587f03
DEFINE_GUID(
	SF_SUBLAYER,
	0x2e207682,
	0xd95f,
	0x4525,
	0xb9, 0x66, 0x96, 0x9f, 0x26, 0x58, 0x7f, 0x03
);
// cea0131a-6ed3-4ed6-b40c-8a8fe8434b0a
DEFINE_GUID(
	SF_STREAM_CALLOUT_V4,
	0xcea0131a,
	0x6ed3,
	0x4ed6,
	0xb4, 0x0c, 0x8a, 0x8f, 0xe8, 0x43, 0x4b, 0x0a
);
//一堆函数定义
void SFALEConnectClassify(__in const FWPS_INCOMING_VALUES0* inFixedValues, __in const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, __inout void* layerData, __in const FWPS_FILTER0* filter, __in UINT64 flowContext, __in FWPS_CLASSIFY_OUT0* classifyOut);
NTSTATUS SFALEConnectNotify(__in FWPS_CALLOUT_NOTIFY_TYPE notifyType, __in const GUID* filterKey, __in const FWPS_FILTER0* filter);
void SFALERecvAcceptClassify(__in const FWPS_INCOMING_VALUES0* inFixedValues, __in const FWPS_INCOMING_METADATA_VALUES0* inMetaValues, __inout void* layerData, __in const FWPS_FILTER0* filter, __in UINT64 flowContext, __inout FWPS_CLASSIFY_OUT0* classifyOut);
NTSTATUS SFALERecvAcceptNotify(__in FWPS_CALLOUT_NOTIFY_TYPE notifyType, __in const GUID* filterKey, __in const FWPS_FILTER0* filter);
VOID SFDeleteCDO(__in PDRIVER_OBJECT DriverObject);
void SFDeregistryCallouts(__in PDEVICE_OBJECT DeviceObject);
NTSTATUS SFRegisterALEClassifyCallouts(__in const GUID* layerKey,__in const GUID* calloutKey,__in void* DeviceObject,__out UINT32* calloutId);
void SFALERecvDataClassify(__in const FWPS_INCOMING_VALUES0* inFixedValues,__in const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,__inout void* layerData,__in const FWPS_FILTER0* filter,__in UINT64 flowContext,__inout FWPS_CLASSIFY_OUT0* classifyOut);
NTSTATUS SFRegistryCallouts(__in PDEVICE_OBJECT DeviceObject);
NTSTATUS
SFALERecvDataNotify(__in FWPS_CALLOUT_NOTIFY_TYPE notifyType,__in const GUID* filterKey,__in const FWPS_FILTER0* filter);
__kernel_entry NTSYSCALLAPI NTSTATUS ZwCreateFile(
	PHANDLE            FileHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK   IoStatusBlock,
	PLARGE_INTEGER     AllocationSize,
	ULONG              FileAttributes,
	ULONG              ShareAccess,
	ULONG              CreateDisposition,
	ULONG              CreateOptions,
	PVOID              EaBuffer,
	ULONG              EaLength
);
//一些结构
typedef struct _FLOW_DATA
{
	UINT64      flowHandle;
	UINT64      flowContext;
	UINT64      calloutId;
	ULONG       localAddressV4;
	USHORT      localPort;
	USHORT      ipProto;
	ULONG       remoteAddressV4;
	USHORT      remotePort;
	WCHAR* processPath;
	LIST_ENTRY  listEntry;
	BOOLEAN     deleting;
} FLOW_DATA;

typedef enum _ReportType
{
	r_income, //进来auth
	r_output, //出去auth
	r_stream_income,  //TCP流交互
	r_stream_output
}ReportType;
typedef struct _Networkreport {
	ReportType type;
	int Protocol;
	DWORD IPaddr;
	DWORD BuffDataLen;
	char BuffData[0];
} Networkreport;

typedef struct _PUSH_DATA {
	DWORD BlockIP;
	SIZE_T dataLen;
	char data[255];
}PUSH_DATA, * PPUSH_DATA;
typedef struct _BLACK_LIST_DATA {
	LIST_ENTRY	link;
	char data[255];
}BLACK_LIST_DATA, * PBLACK_LIST_DATA;