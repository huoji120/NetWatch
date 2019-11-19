#include "head.h"
NTSTATUS SFCreateCDO(__in PDRIVER_OBJECT DriverObject);
PDEVICE_OBJECT  gControlDeviceObject;
HANDLE          gInjectionHandle;
HANDLE          gEngineHandle;
UINT32          gAleConnectCalloutIdV4;
UINT32          gAleRecvAcceptCalloutIdV4;
UINT32          gAleRSFSTREAMCALLOUTV4V4;
DWORD           gBackListIPTable[MAX_DATA_SIZE]; //最多支持255个黑名单IP
EX_SPIN_LOCK    gBlockIpLock, gBlockDataLock;
BLACK_LIST_DATA gBackListDataTable;
BOOLEAN			g_StartFilter = FALSE;

/*
HANDLE			g_hClient;
IO_STATUS_BLOCK g_ioStatusBlock;
KEVENT			g_event;
VOID ReportToR3(Networkreport* m_parameter,int lent)
{
	if (!NT_SUCCESS(ZwWriteFile(g_hClient, NULL, NULL, NULL, &g_ioStatusBlock, (void*)m_parameter, lent, NULL, NULL)))
		DPRINT("[DebugMessage] Error Cannot Wirte Pipe! \n"),
		g_hClient = 0;
}
*/
BOOL FindPattern(char* pattern,void* data,SIZE_T data_len)
{
	const char* pat = pattern;
	DWORD firstMatch = 0;
	DWORD End = (DWORD)data + data_len;
	for (DWORD pCur = (DWORD)data; pCur < End; pCur++)
	{
		if (!*pat)
			return firstMatch;

		if (*(PBYTE)pat == '\?' || *(BYTE*)pCur == getByte(pat))
		{
			if (!firstMatch)
				firstMatch = pCur;

			if (!pat[2])
				return firstMatch;

			if (*(PWORD)pat == '\?\?' || *(PBYTE)pat != '\?')
				pat += 3;

			else
				pat += 2;    //one ?
		}
		else
		{
			pat = pattern;
			firstMatch = 0;
		}
	}

	return firstMatch != NULL;
}

//添加数据到 到黑名单数据列表
VOID AddBlackListData(char* data,DWORD blockip,SIZE_T len)
{
	if (blockip == 0x0)
	{
		DPRINT("[DebugMessage] BlackData :%s len: %d \n", data, len);
		PBLACK_LIST_DATA newLink = (PBLACK_LIST_DATA)ExAllocatePoolWithTag(PagedPool, sizeof(BLACK_LIST_DATA), TAG_NAME_BLACKLISTDATA);
		if (newLink == NULL)
			ASSERT(false);
		//RtlZeroMemory(newLink, sizeof(BLACK_LIST_DATA));
		memcpy(newLink->data, data, len);
		DPRINT("[DebugMessage] BlackData :%s \n", newLink->data);
		InsertTailList(&gBackListDataTable.link, (PLIST_ENTRY)newLink);
	}
	else
	{
		 for (int i = 0; i < MAX_DATA_SIZE; i++)
		 {
			if (gBackListIPTable[i] == 0)
			{
				gBackListIPTable[i] = blockip;
				DPRINT("[DebugMessage] BlackIP :0x%08X \n", gBackListIPTable[i]);
				break;
			}
		 }
	}
}
//黑名单IP匹配
BOOLEAN QueryBlackIP(DWORD ipaddr)
{
	KIRQL   Irql = ExAcquireSpinLockExclusive(&gBlockIpLock);
	BOOLEAN result = FALSE;
	for (int i = 0; i < MAX_DATA_SIZE; i++)
	{
		if (gBackListIPTable[i] == ipaddr)
		{
			result = TRUE;
			break;
		}
	}
	ExReleaseSpinLockExclusive(&gBlockIpLock, Irql);
	return result;
}
//黑名单数据匹配
BOOLEAN QueryBlackListData(char* data, SIZE_T len)
{
	KIRQL   Irql = ExAcquireSpinLockExclusive(&gBlockDataLock);
	BOOLEAN result = FALSE;
	PLIST_ENTRY	head = &gBackListDataTable.link;
	PBLACK_LIST_DATA next = (PBLACK_LIST_DATA)gBackListDataTable.link.Blink;
	while (head != (PLIST_ENTRY)next)
	{
		if(FindPattern(next->data, data, len))
		{
			result = TRUE;
			break;
		}
	}
	ExReleaseSpinLockExclusive(&gBlockDataLock, Irql);
	return result;
}

NTSTATUS DriverDefaultHandler(IN PDEVICE_OBJECT pDeviceObject, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return pIrp->IoStatus.Status;
}

NTSTATUS DriverControlHandler(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp)

{
	PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
	NTSTATUS            ntStatus = STATUS_UNSUCCESSFUL;// Assume success
	ULONG               inBufLength; // Input buffer length
	ULONG               outBufLength; // Output buffer length
	PUCHAR				inBuf, outBuf;
	UNREFERENCED_PARAMETER(DeviceObject);
	irpSp = IoGetCurrentIrpStackLocation(Irp);

	inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

	inBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
	outBuf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
	DPRINT("[DebugMessage] DriverControlHandler: inBufLength: %d outBufLength: %d \n", inBufLength, outBufLength);

	if (!inBufLength || !outBufLength)
	{
		ntStatus = STATUS_INVALID_PARAMETER;
		goto End;
	}

	switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_ADD_BLACKLIST_DATA:
	{
		DPRINT("[DebugMessage] Add BlackList Data! \n");
		PPUSH_DATA push_data = (PPUSH_DATA)ExAllocatePoolWithTag(PagedPool, sizeof(PUSH_DATA), "tM2d");
		if (push_data)
		{
			RtlZeroMemory(push_data, sizeof(PUSH_DATA));
			memcpy(push_data, inBuf, inBufLength);
			AddBlackListData(push_data->data, push_data->BlockIP, push_data->dataLen);
			DPRINT("[DebugMessage] BlockIP: 0x%08X data: %s len: %d \n",  push_data->BlockIP, push_data->data, push_data->dataLen);
			g_StartFilter = TRUE;
			ntStatus = STATUS_SUCCESS;
			ExFreePoolWithTag(push_data, "tM2d");
		}
		else
		{
			ntStatus = STATUS_INVALID_PARAMETER;
		}
	
		break;
	}
	default:
		break;
	}

End:
	Irp->IoStatus.Status = ntStatus;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return ntStatus;
}
NTSTATUS DriverEntry(__in PDRIVER_OBJECT DriverObject,__in PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	//初始化管道
	NTSTATUS		   Status;
	UNICODE_STRING     uniName;
	OBJECT_ATTRIBUTES  objAttr;
	/*
	RtlInitUnicodeString(&uniName, L"\\DosDevices\\Pipe\\EzFireWall");
	InitializeObjectAttributes(&objAttr, &uniName,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL, NULL);
	Status = ZwCreateFile(&g_hClient,
		GENERIC_READ | GENERIC_WRITE,
		&objAttr, &g_ioStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);
	if (!NT_SUCCESS(Status) || !g_hClient)
	{
		DPRINT("[DebugMessage] Cannot pipe Fail! 0x%08X \n", Status);
		return Status;
	}
	DPRINT("[DebugMessage] Connect pipe Success!\n");
	KeInitializeEvent(&g_event, SynchronizationEvent, TRUE);
	*/
	RtlZeroMemory(gBackListIPTable, sizeof(gBackListIPTable));
	gBlockIpLock = 0;
	InitializeListHead((PLIST_ENTRY)&gBackListDataTable);

	Status = SFCreateCDO(DriverObject);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	if (!NT_SUCCESS(Status))
	{
		SFDeleteCDO(DriverObject);
		return Status;
	}

	Status = SFRegistryCallouts(gControlDeviceObject);

	if (!NT_SUCCESS(Status))
	{
		SFDeleteCDO(DriverObject);
		return Status;
	}

	return STATUS_SUCCESS;
}
NTSTATUS
SFCreateClose(
	__in PDEVICE_OBJECT DeviceObject,
	__in PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PAGED_CODE();

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = FILE_OPENED;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS
SFDeviceControl(
	__in PDEVICE_OBJECT DeviceObject,
	__in PIRP Irp
)
{
	return DriverControlHandler(DeviceObject, Irp);
}

VOID
SFUnload(
	__in PDRIVER_OBJECT DriverObject
)
{
	DPRINT("[DebugMessage] Driver Unload!");
	SFDeregistryCallouts(gControlDeviceObject);
	SFDeleteCDO(DriverObject);
}

NTSTATUS
SFCreateCDO(
	__in PDRIVER_OBJECT DriverObject
)
{
	NTSTATUS        Status;
	UNICODE_STRING  DeviceName;
	UNICODE_STRING  LinkName;

	//
	//  Create control device object
	//

	RtlInitUnicodeString(&DeviceName, NT_DEVICE_NAME);

	Status = IoCreateDevice(DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&gControlDeviceObject);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	//
	// Initialize the driver object with this driver's entry points.
	//

	DriverObject->MajorFunction[IRP_MJ_CREATE] = SFCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = SFCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SFDeviceControl;

	DriverObject->DriverUnload = SFUnload;

	//
	//  Initialize symbolic name for our control device object
	//

	RtlInitUnicodeString(&LinkName, DOS_DEVICE_NAME);

	//
	// Create a symbolic link between our device name  and the Win32 name
	//

	Status = IoCreateSymbolicLink(&LinkName, &DeviceName);

	if (!NT_SUCCESS(Status))
	{
		IoDeleteDevice(gControlDeviceObject);

		return Status;
	}

	return Status;
}

VOID
SFDeleteCDO(
	__in PDRIVER_OBJECT DriverObject
)
{
	UNICODE_STRING LinkName;

	UNREFERENCED_PARAMETER(DriverObject);

	PAGED_CODE();

	//
	//  Delete symbolic link
	//

	RtlInitUnicodeString(&LinkName, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&LinkName);

	//
	//  Delete control device object
	//

	if (gControlDeviceObject != NULL)
	{
		IoDeleteDevice(gControlDeviceObject);
		gControlDeviceObject = NULL;
	}
}

NTSTATUS
SFRegistryCallouts(
	__in PDEVICE_OBJECT DeviceObject
)
{
	NTSTATUS        Status = STATUS_SUCCESS;
	BOOLEAN         EngineOpened = FALSE;
	BOOLEAN         InTransaction = FALSE;
	FWPM_SESSION0   Session = { 0 };
	FWPM_SUBLAYER0  FirewallSubLayer;

	Session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	Status = FwpmEngineOpen0(NULL,
		RPC_C_AUTHN_WINNT,
		NULL,
		&Session,
		&gEngineHandle);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	EngineOpened = TRUE;

	Status = FwpmTransactionBegin0(gEngineHandle, 0);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	InTransaction = TRUE;

	RtlZeroMemory(&FirewallSubLayer, sizeof(FWPM_SUBLAYER0));

	FirewallSubLayer.subLayerKey = SF_SUBLAYER;
	FirewallSubLayer.displayData.name = L"Transport SimpleFirewall Sub-Layer";
	FirewallSubLayer.displayData.description = L"Sub-Layer for use by Transport SimpleFirewall callouts";
	FirewallSubLayer.flags = 0;
	FirewallSubLayer.weight = 0;

	Status = FwpmSubLayerAdd0(gEngineHandle, &FirewallSubLayer, NULL);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	Status = SFRegisterALEClassifyCallouts(&FWPM_LAYER_ALE_AUTH_CONNECT_V4,
		&SF_ALE_CONNECT_CALLOUT_V4,
		DeviceObject,
		&gAleConnectCalloutIdV4);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	Status = SFRegisterALEClassifyCallouts(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
		&SF_ALE_RECV_ACCEPT_CALLOUT_V4,
		DeviceObject,
		&gAleRecvAcceptCalloutIdV4);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	Status = SFRegisterALEClassifyCallouts(&FWPM_LAYER_STREAM_V4,
		&SF_STREAM_CALLOUT_V4,
		DeviceObject,
		&gAleRSFSTREAMCALLOUTV4V4);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	Status = FwpmTransactionCommit0(gEngineHandle);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	InTransaction = FALSE;

Exit:

	if (!NT_SUCCESS(Status))
	{
		if (InTransaction)
		{
			FwpmTransactionAbort0(gEngineHandle);
		}

		if (EngineOpened)
		{
			FwpmEngineClose0(gEngineHandle);
			gEngineHandle = NULL;
		}
	}

	return Status;
}

void
SFDeregistryCallouts(
	__in PDEVICE_OBJECT DeviceObject
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	FwpmEngineClose0(gEngineHandle);
	gEngineHandle = NULL;

	FwpsCalloutUnregisterById0(gAleConnectCalloutIdV4);
	FwpsCalloutUnregisterById0(gAleRecvAcceptCalloutIdV4);
	FwpsCalloutUnregisterById0(gAleRSFSTREAMCALLOUTV4V4);
}

NTSTATUS
SFAddFilter(
	__in const wchar_t* filterName,
	__in const wchar_t* filterDesc,
	__in const GUID* layerKey,
	__in const GUID* calloutKey
)
{
	FWPM_FILTER0 Filter = { 0 };

	Filter.layerKey = *layerKey;
	Filter.displayData.name = (wchar_t*)filterName;
	Filter.displayData.description = (wchar_t*)filterDesc;

	Filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	Filter.action.calloutKey = *calloutKey;
	Filter.subLayerKey = SF_SUBLAYER;
	Filter.weight.type = FWP_EMPTY;
	Filter.rawContext = 0;

	return FwpmFilterAdd0(gEngineHandle, &Filter, NULL, NULL);
}
NTSTATUS
SFRegisterALEClassifyCallouts(
	__in const GUID* layerKey,
	__in const GUID* calloutKey,
	__in void* DeviceObject,
	__out UINT32* calloutId
)
{
	NTSTATUS Status = STATUS_SUCCESS;

	FWPS_CALLOUT0 sCallout = { 0 };
	FWPM_CALLOUT0 mCallout = { 0 };

	FWPM_DISPLAY_DATA0 DisplayData = { 0 };

	BOOLEAN calloutRegistered = FALSE;

	sCallout.calloutKey = *calloutKey;

	if (IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V4))
	{
		DPRINT("[DebugMessage] 挂载 FWPM_LAYER_ALE_AUTH_CONNECT_V4! \n");
		sCallout.classifyFn = SFALEConnectClassify;
		sCallout.notifyFn = SFALEConnectNotify;
	}
	else if (IsEqualGUID(layerKey, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4))
	{
		DPRINT("[DebugMessage] 挂载 FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4! \n");
		sCallout.classifyFn = SFALERecvAcceptClassify;
		sCallout.notifyFn = SFALERecvAcceptNotify;
	}
	else if (IsEqualGUID(layerKey, &FWPM_LAYER_STREAM_V4))
	{
		DPRINT("[DebugMessage] 挂载 FWPM_LAYER_STREAM_V4! \n");
		sCallout.classifyFn = SFALERecvDataClassify;
		sCallout.notifyFn = SFALERecvDataNotify;
	}
	Status = FwpsCalloutRegister0(DeviceObject,
		&sCallout,
		calloutId);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	calloutRegistered = TRUE;

	DisplayData.name = L"Transport SimpleFirewall ALE Classify Callout";
	DisplayData.description = L"Intercepts inbound or outbound connect attempts";

	mCallout.calloutKey = *calloutKey;
	mCallout.displayData = DisplayData;
	mCallout.applicableLayer = *layerKey;

	Status = FwpmCalloutAdd0(gEngineHandle,
		&mCallout,
		NULL,
		NULL);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

	Status = SFAddFilter(L"Transport SimpleFirewall ALE Classify",
		L"Intercepts inbound or outbound connect attempts",
		layerKey,
		calloutKey);

	if (!NT_SUCCESS(Status))
	{
		goto Exit;
	}

Exit:

	if (!NT_SUCCESS(Status))
	{
		if (calloutRegistered)
		{
			FwpsCalloutUnregisterById0(*calloutId);
			*calloutId = 0;
		}
	}

	return Status;
}
NTSTATUS
SFALERecvDataNotify(
	__in FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	__in const GUID* filterKey,
	__in const FWPS_FILTER0* filter
)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	return STATUS_SUCCESS;
}

NTSTATUS
SFALERecvAcceptNotify(
	__in FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	__in const GUID* filterKey,
	__in const FWPS_FILTER0* filter
)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	return STATUS_SUCCESS;
}

NTSTATUS
SFALEConnectNotify(
	__in FWPS_CALLOUT_NOTIFY_TYPE notifyType,
	__in const GUID* filterKey,
	__in const FWPS_FILTER0* filter
)
{
	UNREFERENCED_PARAMETER(notifyType);
	UNREFERENCED_PARAMETER(filterKey);
	UNREFERENCED_PARAMETER(filter);

	return STATUS_SUCCESS;
}

VOID
PerformBasicAction(
	_In_ const FWPS_INCOMING_VALUES* pClassifyValues,
	_In_ const FWPS_INCOMING_METADATA_VALUES* pMetadata,
	_Inout_opt_ VOID* pLayerData,
	_In_ const FWPS_FILTER0* pFilter,
	_In_ UINT64 flowContext,
	_Inout_ FWPS_CLASSIFY_OUT* pClassifyOut,
	_In_ FWP_ACTION_TYPE basicAction
)
{
	UNREFERENCED_PARAMETER(pClassifyValues);
	UNREFERENCED_PARAMETER(pMetadata);
	UNREFERENCED_PARAMETER(flowContext);
	UNREFERENCED_PARAMETER(pLayerData);

	if (pClassifyOut)
	{
		pClassifyOut->actionType = basicAction;

		// Clear the right to mark as the definitive answer.

		if ((basicAction == FWP_ACTION_BLOCK) ||
			(basicAction == FWP_ACTION_PERMIT && pFilter->flags & FWPS_FILTER_FLAG_CLEAR_ACTION_RIGHT))
		{
			pClassifyOut->rights ^= FWPS_RIGHT_ACTION_WRITE;
		}
	}
}

//协议代码转为名称
char* ProtocolIdToName(UINT16 id)
{
	char* ProtocolName = ExAllocatePoolWithTag(NonPagedPool, 16, 'PWtn');
	if (ProtocolName)
	{
		switch (id)	//http://www.ietf.org/rfc/rfc1700.txt
		{
		case 1:
			strcpy_s(ProtocolName, 4 + 1, "ICMP");
			break;
		case 2:
			strcpy_s(ProtocolName, 4 + 1, "IGMP");
			break;
		case 6:
			strcpy_s(ProtocolName, 3 + 1, "TCP");
			break;
		case 17:
			strcpy_s(ProtocolName, 3 + 1, "UDP");
			break;
		case 27:
			strcpy_s(ProtocolName, 3 + 1, "RDP");
			break;
		default:
			strcpy_s(ProtocolName, 7 + 1, "UNKNOWN");
			break;
		}
	}
	return ProtocolName;
}
BOOLEAN CanIFilterThisRequest(
	__in const FWPS_INCOMING_VALUES0* inFixedValues,
	__in const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	__in void* packet,
	_In_ UINT64 flowContext
)
{
	UNREFERENCED_PARAMETER(inMetaValues);
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
	{
		DPRINT("[DebugMessage] Erro in PassIve: %d \n", KeGetCurrentIrql());
		return FALSE;
	}
	if (g_StartFilter)
	{
		DWORD LocalIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
		DWORD RemoteIP = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
		if (LocalIp != RemoteIP)
		{
			if (QueryBlackIP(RemoteIP))
			{
				DPRINT("[DebugMessage] Found BlackList IP! \n");
				return TRUE;
			}
		}

	}

	//这边可以阻止黑名单IP进入.
	/*
	char* ProtocolName = ProtocolIdToName(inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint16);
	DWORD LocalIp = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
	DWORD RemoteIP = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
	DPRINT("[DebugMessage] Out: ProtocolName: %s Local: %u.%u.%u.%u:%d Remote:%u.%u.%u.%u:%d Protocol: %s \n",
		(LocalIp >> 24) & 0xFF, (LocalIp >> 16) & 0xFF, (LocalIp >> 8) & 0xFF, LocalIp & 0xFF,
		inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_PORT].value.uint16,
		(RemoteIP >> 24) & 0xFF, (RemoteIP >> 16) & 0xFF, (RemoteIP >> 8) & 0xFF, RemoteIP & 0xFF,
		inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_PORT].value.uint16,
		ProtocolName);
	ExFreePool(ProtocolName);
	*/
	return FALSE;
}

//本地连别人的IP的连接
void SFALEConnectClassify(
	__in const FWPS_INCOMING_VALUES0* inFixedValues,
	__in const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	__inout void* layerData,
	__in const FWPS_FILTER0* filter,
	__in UINT64 flowContext,
	__in FWPS_CLASSIFY_OUT0* classifyOut
)
{
	if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)
	{
		FWP_ACTION_TYPE Action = (CanIFilterThisRequest(inFixedValues,inMetaValues, layerData,flowContext) ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT);

		PerformBasicAction(inFixedValues,
			inMetaValues,
			layerData,
			filter,
			flowContext,
			classifyOut,
			Action);
	}
}
//接收远程IP的连接
void SFALERecvAcceptClassify(
	__in const FWPS_INCOMING_VALUES0* inFixedValues,
	__in const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	__inout void* layerData,
	__in const FWPS_FILTER0* filter,
	__in UINT64 flowContext,
	__inout FWPS_CLASSIFY_OUT0* classifyOut
)
{
	if (classifyOut->rights & FWPS_RIGHT_ACTION_WRITE)
	{
		FWP_ACTION_TYPE Action = (CanIFilterThisRequest(inFixedValues,inMetaValues, layerData, flowContext) ? FWP_ACTION_BLOCK : FWP_ACTION_PERMIT);

		PerformBasicAction(inFixedValues,
			inMetaValues,
			layerData,
			filter,
			flowContext,
			classifyOut,
			Action);
	}
}


void SFALERecvDataClassify(
	__in const FWPS_INCOMING_VALUES0* inFixedValues,
	__in const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
	__inout void* layerData,//这玩意是数据指针
	__in const FWPS_FILTER0* filter,
	__in UINT64 flowContext,
	__inout FWPS_CLASSIFY_OUT0* classifyOut
)
{
	if (KeGetCurrentIrql() > DISPATCH_LEVEL)
	{
		DPRINT("[DebugMessage] Erro in PassIve: %d \n", KeGetCurrentIrql());
		return FALSE;
	}
	
	FWPS_STREAM_CALLOUT_IO_PACKET* streamPacket = (FWPS_STREAM_CALLOUT_IO_PACKET*)layerData;
	DWORD RemoteIP = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS].value.uint32;
	DWORD LocalIP = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_LOCAL_ADDRESS].value.uint32;
	if (streamPacket && streamPacket->streamData != NULL && streamPacket->streamData->dataLength != 0  && RemoteIP != LocalIP && g_StartFilter)
	{
		SIZE_T streamLength = streamPacket->streamData->dataLength;
		BOOLEAN inbound = (BOOLEAN)((streamPacket->streamData->flags & FWPS_STREAM_FLAG_RECEIVE) == FWPS_STREAM_FLAG_RECEIVE);
		BYTE* stream = ExAllocatePoolWithTag(NonPagedPool, streamLength, TAG_NAME_NOTIFY);
		SIZE_T byte_copied = 0;
		if (stream)
		{
			RtlZeroMemory(stream, streamLength);
			FwpsCopyStreamDataToBuffer(
				streamPacket->streamData,
				stream,
				streamLength,
				&byte_copied);
			NT_ASSERT(bytesCopied == streamLength);
			if (QueryBlackListData(stream, streamLength))
			{
				DPRINT("[DebugMessage] Found BlackList Data! \n");
				classifyOut->actionType = FWP_ACTION_BLOCK;
				ExFreePool(stream);
				return;
			}
			/*
			//抓包与截包,如果你发现这里蓝屏请自己加锁,但是会极大的影响系统运行效率(网络吞吐量太大,pipe管道有20MS的延迟,而且还是单线程.伤不起
			DPRINT("[DebugMessage] inbound: %d streamBuffer: %s ", inbound, stream);
			SIZE_T buffsize = streamLength + sizeof(Networkreport);
			inbound = (BOOLEAN)((streamPacket->streamData->flags & FWPS_STREAM_FLAG_RECEIVE) == FWPS_STREAM_FLAG_RECEIVE);
			Networkreport* report = (Networkreport*)ExAllocatePoolWithTag(NonPagedPool, buffsize, TAG_NAME_REPORT);
			if (report)
			{
				RtlZeroMemory(report, buffsize);
				report->type = inbound ? r_stream_income : r_stream_output;
				report->Protocol = inFixedValues->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_PROTOCOL].value.uint16;
				report->IPaddr = RemoteIP;
				report->BuffDataLen = streamLength;
				//定位到buffer的sizeof(Networkreport)位置
				BYTE* tmp = (BYTE*)report + sizeof(Networkreport);
				memcpy(tmp, stream, streamLength);
				ReportToR3(report, buffsize);
				ExFreePool(report);
			}*/

			ExFreePool(stream);
		}
	}
	classifyOut->actionType = FWP_ACTION_CONTINUE;

}
