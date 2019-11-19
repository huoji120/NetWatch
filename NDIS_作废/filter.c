#include "precomp.h"

#define __FILENUMBER    'PNPF'

/**
 * 驱动入口
 *
 * @Author Yue
 */

#pragma NDIS_INIT_FUNCTION(DriverEntry)

NDIS_HANDLE         FilterDriverHandle; // 过滤驱动的NDIS句柄
NDIS_HANDLE         FilterDriverObject; // DriverObject驱动对象

FILTER_LOCK         FilterListLock;		//插入ModuleList需要的Lock
LIST_ENTRY          FilterModuleList;	//ModulelList链表头

NDIS_FILTER_PARTIAL_CHARACTERISTICS DefaultChars = {
	{ 0, 0, 0 },
	0,
	FilterSendNetBufferLists,
	FilterSendNetBufferListsComplete,
	NULL,
	FilterReceiveNetBufferLists,
	FilterReturnNetBufferLists
};

//驱动入口
_Use_decl_annotations_
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
	KdPrint(("===>DriverEntry...\n"));

	NDIS_STATUS Status;

	NDIS_FILTER_DRIVER_CHARACTERISTICS      FChars;

	NDIS_STRING ServiceName = RTL_CONSTANT_STRING(FILTER_SERVICE_NAME);
	NDIS_STRING UniqueName = RTL_CONSTANT_STRING(FILTER_UNIQUE_NAME);
	NDIS_STRING FriendlyName = RTL_CONSTANT_STRING(FILTER_FRIENDLY_NAME);
	BOOLEAN bFalse = FALSE;

	UNREFERENCED_PARAMETER(RegistryPath);

	FilterDriverObject = DriverObject;

	do
	{
		NdisZeroMemory(&FChars, sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS));
		FChars.Header.Type = NDIS_OBJECT_TYPE_FILTER_DRIVER_CHARACTERISTICS;
		FChars.Header.Size = sizeof(NDIS_FILTER_DRIVER_CHARACTERISTICS);
#if NDIS_SUPPORT_NDIS61
		FChars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_2;
#else
		FChars.Header.Revision = NDIS_FILTER_CHARACTERISTICS_REVISION_1;
#endif
		FChars.MajorNdisVersion = FILTER_MAJOR_NDIS_VERSION;
		FChars.MinorNdisVersion = FILTER_MINOR_NDIS_VERSION;
		FChars.MajorDriverVersion = 1;
		FChars.MinorDriverVersion = 0;
		FChars.Flags = 0;

		FChars.FriendlyName = FriendlyName;
		FChars.UniqueName = UniqueName;
		FChars.ServiceName = ServiceName;
		FChars.SetOptionsHandler = FilterRegisterOptions;
		FChars.AttachHandler = FilterAttach;
		FChars.DetachHandler = FilterDetach;
		FChars.RestartHandler = FilterRestart;
		FChars.PauseHandler = FilterPause;
		FChars.SetFilterModuleOptionsHandler = FilterSetModuleOptions;
		FChars.OidRequestHandler = FilterOidRequest;
		FChars.OidRequestCompleteHandler = FilterOidRequestComplete;
		FChars.CancelOidRequestHandler = FilterCancelOidRequest;

		FChars.SendNetBufferListsHandler = FilterSendNetBufferLists;
		FChars.ReturnNetBufferListsHandler = FilterReturnNetBufferLists;
		FChars.SendNetBufferListsCompleteHandler = FilterSendNetBufferListsComplete;
		FChars.ReceiveNetBufferListsHandler = FilterReceiveNetBufferLists;
		FChars.DevicePnPEventNotifyHandler = FilterDevicePnPEventNotify;
		FChars.NetPnPEventHandler = FilterNetPnPEvent;
		FChars.StatusHandler = FilterStatus;
		FChars.CancelSendNetBufferListsHandler = FilterCancelSendNetBufferLists;

		DriverObject->DriverUnload = FilterUnload;

		FilterDriverHandle = NULL;

		//
		// Initialize spin locks
		//
		FILTER_INIT_LOCK(&FilterListLock);

		InitializeListHead(&FilterModuleList);
		//注册FilterDriver
		Status = NdisFRegisterFilterDriver(DriverObject,
			(NDIS_HANDLE)FilterDriverObject,
			&FChars,
			&FilterDriverHandle);
		if (Status != NDIS_STATUS_SUCCESS)
		{
			KdPrint(("Register filter driver failed.\n"));
			break;
		}
		//注册Device
		Status = NdisFilterRegisterDevice();

		if (Status != NDIS_STATUS_SUCCESS)
		{
			NdisFDeregisterFilterDriver(FilterDriverHandle);
			FILTER_FREE_LOCK(&FilterListLock);
			KdPrint(("Register device for the filter driver failed.\n"));
			break;
		}
	} while (bFalse);

	//////////////////////////////////////////////////////////////////////

	InitBlackDataList();

	////////////////////////////////////////////////////////////////////*/

	KdPrint(("<===DriverEntry, Status = %8x\n", Status));
	return Status;

}

//驱动注册设备
_IRQL_requires_max_(PASSIVE_LEVEL)
NDIS_STATUS NdisFilterRegisterDevice(VOID)
{
	NDIS_STATUS            Status = NDIS_STATUS_SUCCESS;
	UNICODE_STRING         DeviceName;
	UNICODE_STRING         DeviceLinkUnicodeString;
	PDRIVER_DISPATCH       DispatchTable[IRP_MJ_MAXIMUM_FUNCTION + 1];
	NDIS_DEVICE_OBJECT_ATTRIBUTES   DeviceAttribute;
	PFILTER_DEVICE_EXTENSION        FilterDeviceExtension;
	PDRIVER_OBJECT                  DriverObject;

	KdPrint(("==>NdisFilterRegisterDevice\n"));

	NdisZeroMemory(DispatchTable, (IRP_MJ_MAXIMUM_FUNCTION + 1) * sizeof(PDRIVER_DISPATCH));

	DispatchTable[IRP_MJ_CREATE] = NdisFilterDispatch;
	DispatchTable[IRP_MJ_CLOSE] = NdisFilterDispatch;
	DispatchTable[IRP_MJ_DEVICE_CONTROL] = NdisFilterDeviceIoControl;


	NdisInitUnicodeString(&DeviceName, NTDEVICE_STRING);
	NdisInitUnicodeString(&DeviceLinkUnicodeString, LINKNAME_STRING);

	//创建设备对象并且注册
	NdisZeroMemory(&DeviceAttribute, sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES));

	DeviceAttribute.Header.Type = NDIS_OBJECT_TYPE_DEVICE_OBJECT_ATTRIBUTES;
	DeviceAttribute.Header.Revision = NDIS_DEVICE_OBJECT_ATTRIBUTES_REVISION_1;
	DeviceAttribute.Header.Size = sizeof(NDIS_DEVICE_OBJECT_ATTRIBUTES);

	DeviceAttribute.DeviceName = &DeviceName;
	DeviceAttribute.SymbolicName = &DeviceLinkUnicodeString;
	DeviceAttribute.MajorFunctions = &DispatchTable[0];
	DeviceAttribute.ExtensionSize = sizeof(FILTER_DEVICE_EXTENSION);
	Status = NdisRegisterDeviceEx(
		FilterDriverHandle,
		&DeviceAttribute,
		&DeviceObject,
		&NdisFilterDeviceHandle
		);
	if (Status == NDIS_STATUS_SUCCESS)
	{
		FilterDeviceExtension = NdisGetDeviceReservedExtension(DeviceObject);

		FilterDeviceExtension->Signature = 'FTDR';
		FilterDeviceExtension->Handle = FilterDriverHandle;
		DriverObject = (PDRIVER_OBJECT)FilterDriverObject;
	}
	KdPrint(("<==NdisFilterRegisterDevice: %x\n", Status));
	return (Status);
}

//驱动注销设备
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID NdisFilterDeregisterDevice(VOID){
	if (NdisFilterDeviceHandle != NULL)
		NdisDeregisterDeviceEx(NdisFilterDeviceHandle);
	NdisFilterDeviceHandle = NULL;
}

//驱动注册选项
_Use_decl_annotations_
NDIS_STATUS FilterRegisterOptions(NDIS_HANDLE  NdisFilterDriverHandle,NDIS_HANDLE  FilterDriverContext)
{
	ASSERT(NdisFilterDriverHandle == FilterDriverHandle);
	ASSERT(FilterDriverContext == (NDIS_HANDLE)FilterDriverObject);

	if ((NdisFilterDriverHandle != (NDIS_HANDLE)FilterDriverHandle) ||
		(FilterDriverContext != (NDIS_HANDLE)FilterDriverObject))
		return NDIS_STATUS_INVALID_PARAMETER;
	return NDIS_STATUS_SUCCESS;
}

//驱动Attach底层的网卡设备
_Use_decl_annotations_
NDIS_STATUS FilterAttach(NDIS_HANDLE NdisFilterHandle,NDIS_HANDLE FilterDriverContext,PNDIS_FILTER_ATTACH_PARAMETERS  AttachParameters)
{
	PMS_FILTER              pFilter = NULL;
	NDIS_STATUS             Status = NDIS_STATUS_SUCCESS;
	NDIS_FILTER_ATTRIBUTES  FilterAttributes;
	ULONG                   Size;
	BOOLEAN					bFalse = FALSE;

	NET_BUFFER_LIST_POOL_PARAMETERS  PoolParameters;
	NET_BUFFER_POOL_PARAMETERS		 PoolParameter;

	KdPrint(("===>FilterAttach: NdisFilterHandle %p\n", NdisFilterHandle));
	do
	{
		ASSERT(FilterDriverContext == (NDIS_HANDLE)FilterDriverObject);

		if (FilterDriverContext != (NDIS_HANDLE)FilterDriverObject)
		{
			Status = NDIS_STATUS_INVALID_PARAMETER;
			break;
		}
		if ((AttachParameters->MiniportMediaType != NdisMedium802_3)
			&& (AttachParameters->MiniportMediaType != NdisMediumWan)
			&& (AttachParameters->MiniportMediaType != NdisMediumWirelessWan))
		{
			KdPrint(("Unsupported media type.\n"));

			Status = NDIS_STATUS_INVALID_PARAMETER;
			break;
		}

		Size = sizeof(MS_FILTER)+
			AttachParameters->FilterModuleGuidName->Length +
			AttachParameters->BaseMiniportInstanceName->Length +
			AttachParameters->BaseMiniportName->Length;

		//为MS_FILTER结构体分配内存
		pFilter = (PMS_FILTER)FILTER_ALLOC_MEM(NdisFilterHandle, Size);
		if (pFilter == NULL){
			KdPrint(("Failed to allocate context structure.\n"));
			Status = NDIS_STATUS_RESOURCES;
			break;
		}
		NdisZeroMemory(pFilter, sizeof(MS_FILTER));

		//ModuleName
		pFilter->FilterModuleName.Length = pFilter->FilterModuleName.MaximumLength = AttachParameters->FilterModuleGuidName->Length;
		pFilter->FilterModuleName.Buffer = (PWSTR)((PUCHAR)pFilter + sizeof(MS_FILTER));
		NdisMoveMemory(pFilter->FilterModuleName.Buffer,
			AttachParameters->FilterModuleGuidName->Buffer,
			pFilter->FilterModuleName.Length);
		//KdPrint(("pFilter->FilterModuleName : %x\n", pFilter->FilterModuleName));

		//MiniportFriendlyName
		pFilter->MiniportFriendlyName.Length = pFilter->MiniportFriendlyName.MaximumLength = AttachParameters->BaseMiniportInstanceName->Length;
		pFilter->MiniportFriendlyName.Buffer = (PWSTR)((PUCHAR)pFilter->FilterModuleName.Buffer + pFilter->FilterModuleName.Length);
		NdisMoveMemory(pFilter->MiniportFriendlyName.Buffer,
			AttachParameters->BaseMiniportInstanceName->Buffer,
			pFilter->MiniportFriendlyName.Length);
		//KdPrint(("MiniportFriendlyName : %x\n", pFilter->MiniportFriendlyName));

		//MiniportName
		pFilter->MiniportName.Length = pFilter->MiniportName.MaximumLength = AttachParameters->BaseMiniportName->Length;
		pFilter->MiniportName.Buffer = (PWSTR)((PUCHAR)pFilter->MiniportFriendlyName.Buffer +
			pFilter->MiniportFriendlyName.Length);
		NdisMoveMemory(pFilter->MiniportName.Buffer,
			AttachParameters->BaseMiniportName->Buffer,
			pFilter->MiniportName.Length);
		//KdPrint(("pFilter->MiniportName : %x\n", pFilter->MiniportName));
		//其它参数值传递
		pFilter->MiniportIfIndex = AttachParameters->BaseMiniportIfIndex;
		pFilter->TrackReceives = TRUE;
		pFilter->TrackSends = TRUE;
		pFilter->FilterHandle = NdisFilterHandle;

		//NDIS NBL内存池参数
		//NDIS_HANDLE	SendNetBufferListPool;
		//Initial PoolParameters,为了之后(FilterReceiveNetBufferLists)从中创建新的NBL并过滤数据
		//NET_BUFFER_LIST_POOL
		NdisZeroMemory(&PoolParameters, sizeof(NET_BUFFER_LIST_POOL_PARAMETERS));
		PoolParameters.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
		PoolParameters.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
		PoolParameters.Header.Size = sizeof(PoolParameters);
		PoolParameters.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
		PoolParameters.ContextSize = 0;
		PoolParameters.fAllocateNetBuffer = TRUE;
		PoolParameters.PoolTag = FILTER_ALLOC_TAG;
		pFilter->SendNetBufferListPool = NdisAllocateNetBufferListPool(
			NdisFilterHandle,
			&PoolParameters);

		//NDIS NB内存池参数 NET_BUFFER_POOL 
		NdisZeroMemory(&PoolParameter, sizeof(NET_BUFFER_POOL_PARAMETERS));
		PoolParameter.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
		PoolParameter.Header.Revision = NET_BUFFER_POOL_PARAMETERS_REVISION_1;
		PoolParameter.Header.Size = NDIS_SIZEOF_NET_BUFFER_POOL_PARAMETERS_REVISION_1;
		PoolParameter.PoolTag = FILTER_ALLOC_TAG;
		pFilter->SendNetBufferPool = NdisAllocateNetBufferPool(
			NdisFilterHandle,
			&PoolParameter);

		//绑定的下层设备的内存参数 FILTER_ATTRIBUTE
		NdisZeroMemory(&FilterAttributes, sizeof(NDIS_FILTER_ATTRIBUTES));
		FilterAttributes.Header.Revision = NDIS_FILTER_ATTRIBUTES_REVISION_1;
		FilterAttributes.Header.Size = sizeof(NDIS_FILTER_ATTRIBUTES);
		FilterAttributes.Header.Type = NDIS_OBJECT_TYPE_FILTER_ATTRIBUTES;
		FilterAttributes.Flags = 0;
		NDIS_DECLARE_FILTER_MODULE_CONTEXT(MS_FILTER);
		Status = NdisFSetAttributes(NdisFilterHandle,
			pFilter,
			&FilterAttributes);
		if (Status != NDIS_STATUS_SUCCESS){
			KdPrint(("Failed to set attributes.\n"));
			break;
		}

		pFilter->State = FilterPaused;

		FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
		InsertHeadList(&FilterModuleList, &pFilter->FilterModuleLink);
		FILTER_RELEASE_LOCK(&FilterListLock, bFalse);

	} while (bFalse);

	if (Status != NDIS_STATUS_SUCCESS){
		if (pFilter != NULL){
			FILTER_FREE_MEM(pFilter);
		}
	}

	//KdPrint(("<===FilterAttach:    Status %x\n", Status));
	return Status;
}

//驱动状态设置为Paused
_Use_decl_annotations_
NDIS_STATUS FilterPause(NDIS_HANDLE FilterModuleContext,PNDIS_FILTER_PAUSE_PARAMETERS PauseParameters)
{
	PMS_FILTER          pFilter = (PMS_FILTER)(FilterModuleContext);
	NDIS_STATUS         Status;
	BOOLEAN               bFalse = FALSE;

	UNREFERENCED_PARAMETER(PauseParameters);
	FILTER_ASSERT(pFilter->State == FilterRunning);

	FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);
	pFilter->State = FilterPausing;
	FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);

	Status = NDIS_STATUS_SUCCESS;
	pFilter->State = FilterPaused;
	return Status;
}

//驱动重启
_Use_decl_annotations_
NDIS_STATUS FilterRestart(NDIS_HANDLE FilterModuleContext,PNDIS_FILTER_RESTART_PARAMETERS RestartParameters)
{
	NDIS_STATUS     Status;
	PMS_FILTER      pFilter = (PMS_FILTER)FilterModuleContext;
	NDIS_HANDLE     ConfigurationHandle = NULL;

	PNDIS_RESTART_GENERAL_ATTRIBUTES NdisGeneralAttributes;
	PNDIS_RESTART_ATTRIBUTES         NdisRestartAttributes;
	NDIS_CONFIGURATION_OBJECT        ConfigObject;

	//KdPrint(("===>FilterRestart:   FilterModuleContext %p\n", FilterModuleContext));

	FILTER_ASSERT(pFilter->State == FilterPaused);

	ConfigObject.Header.Type = NDIS_OBJECT_TYPE_CONFIGURATION_OBJECT;
	ConfigObject.Header.Revision = NDIS_CONFIGURATION_OBJECT_REVISION_1;
	ConfigObject.Header.Size = sizeof(NDIS_CONFIGURATION_OBJECT);
	ConfigObject.NdisHandle = FilterDriverHandle;
	ConfigObject.Flags = 0;

	Status = NdisOpenConfigurationEx(&ConfigObject, &ConfigurationHandle);
	if (Status != NDIS_STATUS_SUCCESS){
		//倘若无法打开ConfigObject，驱动可以退出重启状态
#if 0
		//这儿的代码只是列举如何调用NDIS给事件log写事件
		PWCHAR              ErrorString = L"ndislwf9";

		DEBUGP(DL_WARN, "FilterRestart: Cannot open configuration.\n");
		NdisWriteEventLogEntry(FilterDriverObject,
			EVENT_NDIS_DRIVER_FAILURE,
			0,
			1,
			&ErrorString,
			sizeof(Status),
			&Status);
#endif
	}

	if (Status == NDIS_STATUS_SUCCESS) NdisCloseConfiguration(ConfigurationHandle);

	NdisRestartAttributes = RestartParameters->RestartAttributes;

	if (NdisRestartAttributes != NULL)
	{
		PNDIS_RESTART_ATTRIBUTES   NextAttributes;
		ASSERT(NdisRestartAttributes->Oid == OID_GEN_MINIPORT_RESTART_ATTRIBUTES);
		NdisGeneralAttributes = (PNDIS_RESTART_GENERAL_ATTRIBUTES)NdisRestartAttributes->Data;
		NdisGeneralAttributes->LookaheadSize = 128;

		//检查每一个attribute去看是否filter需要修改
		NextAttributes = NdisRestartAttributes->Next;

		while (NextAttributes != NULL)
			NextAttributes = NextAttributes->Next;
	}
	pFilter->State = FilterRunning; // when successful
	Status = NDIS_STATUS_SUCCESS;
	if (Status != NDIS_STATUS_SUCCESS) pFilter->State = FilterPaused;
	//KdPrint(("<===FilterRestart:  FilterModuleContext %p, Status %x\n", FilterModuleContext, Status));
	return Status;
}

//驱动解除Attach
_Use_decl_annotations_
VOID FilterDetach(NDIS_HANDLE FilterModuleContext)
{
	PMS_FILTER                  pFilter = (PMS_FILTER)FilterModuleContext;
	BOOLEAN                      bFalse = FALSE;
	KdPrint(("===>FilterDetach:    FilterInstance %p\n", FilterModuleContext));
	FILTER_ASSERT(pFilter->State == FilterPaused);
	if (pFilter->FilterName.Buffer != NULL){
		FILTER_FREE_MEM(pFilter->FilterName.Buffer);
	}

	FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
	RemoveEntryList(&pFilter->FilterModuleLink);
	FILTER_RELEASE_LOCK(&FilterListLock, bFalse);

	//parameter is NDIS_HANDLE in this Function
	NdisFreeNetBufferListPool(pFilter->SendNetBufferListPool);
	NdisFreeNetBufferPool(pFilter->SendNetBufferPool);
	// Free the memory allocated
	FILTER_FREE_MEM(pFilter);

	KdPrint(("<===FilterDetach Successfully\n"));
	return;
}

//驱动卸载
_Use_decl_annotations_
VOID FilterUnload(PDRIVER_OBJECT DriverObject)
{
#if DBG
	BOOLEAN               bFalse = FALSE;
#endif

	UNREFERENCED_PARAMETER(DriverObject);

	KdPrint(("===>FilterUnload\n"));

	NdisFilterDeregisterDevice();
	NdisFDeregisterFilterDriver(FilterDriverHandle);
	UnInitBlackDataList();

#if DBG

	FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);
	ASSERT(IsListEmpty(&FilterModuleList));
	FILTER_RELEASE_LOCK(&FilterListLock, bFalse);

#endif

	FILTER_FREE_LOCK(&FilterListLock);
	KdPrint(("<===FilterUnload\n"));
	return;
}

//驱动状态
_Use_decl_annotations_
VOID FilterStatus(NDIS_HANDLE FilterModuleContext,PNDIS_STATUS_INDICATION StatusIndication)
{
	PMS_FILTER              pFilter = (PMS_FILTER)FilterModuleContext;
#if DBG
	BOOLEAN                  bFalse = FALSE;
#endif

	KdPrint(("===>FilterStatus, IndicateStatus = %8x.\n", StatusIndication->StatusCode));
#if DBG
	FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);
	ASSERT(pFilter->bIndicating == FALSE);
	pFilter->bIndicating = TRUE;
	FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);
#endif // DBG

	NdisFIndicateStatus(pFilter->FilterHandle, StatusIndication);

#if DBG
	FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);
	ASSERT(pFilter->bIndicating == TRUE);
	pFilter->bIndicating = FALSE;
	FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);
#endif // DBG
	KdPrint(("<===FilterStatus.\n"));
}

//驱动设备PNP事件通告
_Use_decl_annotations_
VOID FilterDevicePnPEventNotify(NDIS_HANDLE FilterModuleContext,PNET_DEVICE_PNP_EVENT NetDevicePnPEvent)
{
	PMS_FILTER             pFilter = (PMS_FILTER)FilterModuleContext;
	NDIS_DEVICE_PNP_EVENT  DevicePnPEvent = NetDevicePnPEvent->DevicePnPEvent;
#if DBG
	BOOLEAN                bFalse = FALSE;
#endif

	DEBUGP(DL_TRACE, "===>FilterDevicePnPEventNotify: NetPnPEvent = %p.\n", NetDevicePnPEvent);
	switch (DevicePnPEvent)
	{

	case NdisDevicePnPEventQueryRemoved:
	case NdisDevicePnPEventRemoved:
	case NdisDevicePnPEventSurpriseRemoved:
	case NdisDevicePnPEventQueryStopped:
	case NdisDevicePnPEventStopped:
	case NdisDevicePnPEventPowerProfileChanged:
	case NdisDevicePnPEventFilterListChanged:

		break;

	default:
		DEBUGP(DL_ERROR, "FilterDevicePnPEventNotify: Invalid event.\n");
		FILTER_ASSERT(bFalse);

		break;
	}

	NdisFDevicePnPEventNotify(pFilter->FilterHandle, NetDevicePnPEvent);

	DEBUGP(DL_TRACE, "<===FilterDevicePnPEventNotify\n");

}

//驱动网卡PNP事件启动
_Use_decl_annotations_
NDIS_STATUS FilterNetPnPEvent(NDIS_HANDLE FilterModuleContext,PNET_PNP_EVENT_NOTIFICATION NetPnPEventNotification)
{
	PMS_FILTER                pFilter = (PMS_FILTER)FilterModuleContext;
	NDIS_STATUS               Status = NDIS_STATUS_SUCCESS;

	Status = NdisFNetPnPEvent(pFilter->FilterHandle, NetPnPEventNotification);

	return Status;
}

//运行时设置Module句柄选项
_Use_decl_annotations_
NDIS_STATUS FilterSetModuleOptions(NDIS_HANDLE FilterModuleContext)
{
	PMS_FILTER                               pFilter = (PMS_FILTER)FilterModuleContext;
	NDIS_FILTER_PARTIAL_CHARACTERISTICS      OptionalHandlers;
	NDIS_STATUS                              Status = NDIS_STATUS_SUCCESS;
	BOOLEAN                                  bFalse = FALSE;

	if (bFalse)
	{
		UINT      i;

		pFilter->CallsRestart++;

		i = pFilter->CallsRestart % 8;

		pFilter->TrackReceives = TRUE;
		pFilter->TrackSends = TRUE;

		NdisMoveMemory(&OptionalHandlers, &DefaultChars, sizeof(OptionalHandlers));
		OptionalHandlers.Header.Type = NDIS_OBJECT_TYPE_FILTER_PARTIAL_CHARACTERISTICS;
		OptionalHandlers.Header.Size = sizeof(OptionalHandlers);
		switch (i)
		{

		case 0:
			OptionalHandlers.ReceiveNetBufferListsHandler = NULL;
			pFilter->TrackReceives = FALSE;
			break;

		case 1:

			OptionalHandlers.ReturnNetBufferListsHandler = NULL;
			pFilter->TrackReceives = FALSE;
			break;

		case 2:
			OptionalHandlers.SendNetBufferListsHandler = NULL;
			pFilter->TrackSends = FALSE;
			break;

		case 3:
			OptionalHandlers.SendNetBufferListsCompleteHandler = NULL;
			pFilter->TrackSends = FALSE;
			break;

		case 4:
			OptionalHandlers.ReceiveNetBufferListsHandler = NULL;
			OptionalHandlers.ReturnNetBufferListsHandler = NULL;
			break;

		case 5:
			OptionalHandlers.SendNetBufferListsHandler = NULL;
			OptionalHandlers.SendNetBufferListsCompleteHandler = NULL;
			break;

		case 6:

			OptionalHandlers.ReceiveNetBufferListsHandler = NULL;
			OptionalHandlers.ReturnNetBufferListsHandler = NULL;
			OptionalHandlers.SendNetBufferListsHandler = NULL;
			OptionalHandlers.SendNetBufferListsCompleteHandler = NULL;
			break;

		case 7:
			break;
		}
		Status = NdisSetOptionalHandlers(pFilter->FilterHandle, (PNDIS_DRIVER_OPTIONAL_HANDLERS)&OptionalHandlers);
	}
	return Status;
}

//取消发送NBL
_Use_decl_annotations_
VOID FilterCancelSendNetBufferLists(NDIS_HANDLE FilterModuleContext, PVOID CancelId)
{
	PMS_FILTER  pFilter = (PMS_FILTER)FilterModuleContext;
	NdisFCancelSendNetBufferLists(pFilter->FilterHandle, CancelId);
}

//发送NBL完成的回调
_Use_decl_annotations_
VOID FilterSendNetBufferListsComplete(NDIS_HANDLE FilterModuleContext,PNET_BUFFER_LIST NetBufferLists,ULONG SendCompleteFlags)
{
	PMS_FILTER         pFilter = (PMS_FILTER)FilterModuleContext;
	ULONG              NumOfSendCompletes = 0;
	BOOLEAN            DispatchLevel;
	PNET_BUFFER_LIST   CurrNbl;

	KdPrint(("===>SendNBLComplete, NetBufferList: %p.\n", NetBufferLists));

	PUCHAR	pMdl;
	PUCHAR	pData;
	ULONG	BufLength = 0;
	//DIY数据
	if (NetBufferLists->SourceHandle == pFilter->FilterHandle){
		pMdl = NET_BUFFER_FIRST_MDL(
			NET_BUFFER_LIST_FIRST_NB(NetBufferLists));
		FILTER_ASSERT(pMdl != NULL);
		
		NdisFreeMdl(pMdl);
		KdPrint(("Data Complete DIY\n"));
	}
	else{
		if (pFilter->TrackSends)
		{
			CurrNbl = NetBufferLists;
			while (CurrNbl)
			{
				NumOfSendCompletes++;
				CurrNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl);
			}
			DispatchLevel = NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendCompleteFlags);
			FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
			pFilter->OutstandingSends -= NumOfSendCompletes;
			FILTER_LOG_SEND_REF(2, pFilter, PrevNbl, pFilter->OutstandingSends);
			FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
		}
		NdisFSendNetBufferListsComplete(pFilter->FilterHandle, NetBufferLists, SendCompleteFlags);

	}
	KdPrint(("<===SendNBLComplete.\n"));
}

//发送NBL
_Use_decl_annotations_
VOID FilterSendNetBufferLists(NDIS_HANDLE FilterModuleContext,PNET_BUFFER_LIST NetBufferLists,NDIS_PORT_NUMBER PortNumber,ULONG SendFlags)
{
	PMS_FILTER          pFilter = (PMS_FILTER)FilterModuleContext;
	PNET_BUFFER_LIST    CurrNbl;
	BOOLEAN             DispatchLevel;
	BOOLEAN             bFalse = FALSE;

	KdPrint(("===>SendNetBufferList: NBL = %p.\n", NetBufferLists));

	do{
		DispatchLevel = NDIS_TEST_SEND_AT_DISPATCH_LEVEL(SendFlags);
#if DBG
		FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
		if (pFilter->State != FilterRunning)
		{
			FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);

			CurrNbl = NetBufferLists;
			while (CurrNbl)
			{
				NET_BUFFER_LIST_STATUS(CurrNbl) = NDIS_STATUS_PAUSED;
				CurrNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl);
			}
			NdisFSendNetBufferListsComplete(pFilter->FilterHandle,
				NetBufferLists,
				DispatchLevel ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);
			break;

		}
		FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
#endif
		/*///////////////////////////////////////////////////////////////////////////////
		//Drop the NBLs normally.
		KdPrint(("<----------------Send  Drop the NBLs------------>\n"));
		NdisFSendNetBufferListsComplete(pFilter->FilterHandle,NetBufferLists,DispatchLevel ? NDIS_SEND_COMPLETE_FLAGS_DISPATCH_LEVEL : 0);
		break;
		//////////////////////////////////////////////////////////////////////////////*/

		KdPrint(("-----------SendNBL    Modify   Start--------------\n"));
		if (filterScanSingleNBL(NetBufferLists, pFilter))//轮询NBLs中每个节点，并且解析其中每个NB,并匹配规则
			KdPrint(("-----------SendNBL Allow--------------\n"));
		else{
			KdPrint(("------------Drop the SendNBL-----------------\n"));
			// ReceiveFlags == NDIS_RECEIVE_FLAGS_RESOURCES 同步:需要获得回复
			if (NDIS_TEST_RECEIVE_CANNOT_PEND(SendFlags))
				NdisFReturnNetBufferLists(pFilter->FilterHandle,NetBufferLists,SendFlags);
			else{
				KdPrint(("######################Drop the SendNBL#############################\n"));
				break;
			}
		}
		KdPrint(("-----------SendNBL    Modify  end--------------\n"));

		//记录NBLs
		if (pFilter->TrackSends){
			FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
			CurrNbl = NetBufferLists;
			while (CurrNbl){
				pFilter->OutstandingSends++;
				FILTER_LOG_SEND_REF(1, pFilter, CurrNbl, pFilter->OutstandingSends);
				CurrNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl);
			}
			FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
		}
		NdisFSendNetBufferLists(pFilter->FilterHandle, NetBufferLists, PortNumber, SendFlags);
	} while (bFalse);
	KdPrint(("<===SendNetBufferList. \n"));
}

//接收NBL完成的回调
_Use_decl_annotations_ 
VOID FilterReturnNetBufferLists(NDIS_HANDLE FilterModuleContext,PNET_BUFFER_LIST NetBufferLists,ULONG ReturnFlags)
{
	PMS_FILTER          pFilter = (PMS_FILTER)FilterModuleContext;
	PNET_BUFFER_LIST    CurrNbl = NetBufferLists;
	UINT                NumOfNetBufferLists = 0;
	BOOLEAN             DispatchLevel;
	ULONG               Ref;

	KdPrint(("===>ReturnNetBufferLists, NetBufferLists is %p.\n", NetBufferLists));

	if (pFilter->TrackReceives)
	{
		while (CurrNbl)
		{
			NumOfNetBufferLists++;
			CurrNbl = NET_BUFFER_LIST_NEXT_NBL(CurrNbl);
		}
	}

	NdisFReturnNetBufferLists(pFilter->FilterHandle, NetBufferLists, ReturnFlags);

	if (pFilter->TrackReceives)
	{
		DispatchLevel = NDIS_TEST_RETURN_AT_DISPATCH_LEVEL(ReturnFlags);
		FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);

		pFilter->OutstandingRcvs -= NumOfNetBufferLists;
		Ref = pFilter->OutstandingRcvs;
		FILTER_LOG_RCV_REF(3, pFilter, NetBufferLists, Ref);
		FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
	}


	KdPrint(("<===ReturnNetBufferLists.\n"));


}

//接收NBL
_Use_decl_annotations_
VOID FilterReceiveNetBufferLists(NDIS_HANDLE FilterModuleContext,PNET_BUFFER_LIST NetBufferLists,NDIS_PORT_NUMBER PortNumber,ULONG NumberOfNetBufferLists,ULONG ReceiveFlags)
{

	PMS_FILTER          pFilter = (PMS_FILTER)FilterModuleContext;
	BOOLEAN             DispatchLevel;
	ULONG               Ref;
	BOOLEAN             bFalse = FALSE;
#if DBG
	ULONG               ReturnFlags;
#endif

	KdPrint(("===>ReceiveNetBufferList: NetBufferLists = %p.\n", NetBufferLists));

	do
	{

		DispatchLevel = NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags);
#if DBG
		FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);

		//非Running状态,抛包
		if (pFilter->State != FilterRunning)
		{
			FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
			//判断是否是异步
			if (NDIS_TEST_RECEIVE_CAN_PEND(ReceiveFlags))
			{
				ReturnFlags = 0;
				if (NDIS_TEST_RECEIVE_AT_DISPATCH_LEVEL(ReceiveFlags))
				{
					NDIS_SET_RETURN_FLAG(ReturnFlags, NDIS_RETURN_FLAGS_DISPATCH_LEVEL);
				}

				NdisFReturnNetBufferLists(pFilter->FilterHandle, NetBufferLists, ReturnFlags);
			}
			break;
		}
		FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
#endif

		ASSERT(NumberOfNetBufferLists >= 1);

		/////////////////////////////////////////////////////////////////

		KdPrint(("-----------ReceiveNBL    Scan   Start--------------\n"));

		if (filterScanSingleNBL(NetBufferLists, pFilter))//轮询NBLs中每个节点，并且解析其中每个NB,并匹配规则
			KdPrint(("-----------ReceiveNBL  Allow--------------\n"));
		else
		{
			KdPrint(("------------Drop the ReceiveNBL-----------------\n"));
			if (NDIS_TEST_RECEIVE_CANNOT_PEND(ReceiveFlags))// ReceiveFlags == NDIS_RECEIVE_FLAGS_RESOURCES 同步:需要获得回复
				NdisFReturnNetBufferLists(pFilter->FilterHandle,NetBufferLists,ReceiveFlags);
			else{ 
				KdPrint(("######################Drop the ReceiveNBL#############################\n"));
				break;
			}
		}
		KdPrint(("-----------ReceiveNBL    Modify  end--------------\n"));

		/*////////////////////////////////////////////////////////////////
		//<-----------------Drop the NetPacket----------------->

		KdPrint(("<-----------------Drop the NBLs--------------------------->"));

		if (NDIS_TEST_RECEIVE_CANNOT_PEND(ReceiveFlags)){// ReceiveFlags == NDIS_RECEIVE_FLAGS_RESOURCES 同步:需要获得回复

		NdisFReturnNetBufferLists(pFilter->FilterHandle,
									NetBufferLists,
									ReceiveFlags
									);
		}else break;

		////////////////////////////////////////////////////////////////*/

		if (pFilter->TrackReceives)
		{
			FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
			pFilter->OutstandingRcvs += NumberOfNetBufferLists;
			Ref = pFilter->OutstandingRcvs;

			FILTER_LOG_RCV_REF(1, pFilter, NetBufferLists, Ref);
			FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
		}

		//给上层发送NBLs
		NdisFIndicateReceiveNetBufferLists(
			pFilter->FilterHandle,
			NetBufferLists,
			PortNumber,
			NumberOfNetBufferLists,
			ReceiveFlags);

		//记录操作
		if (NDIS_TEST_RECEIVE_CANNOT_PEND(ReceiveFlags) &&
			pFilter->TrackReceives)
		{
			FILTER_ACQUIRE_LOCK(&pFilter->Lock, DispatchLevel);
			pFilter->OutstandingRcvs -= NumberOfNetBufferLists;
			Ref = pFilter->OutstandingRcvs;
			FILTER_LOG_RCV_REF(2, pFilter, NetBufferLists, Ref);
			FILTER_RELEASE_LOCK(&pFilter->Lock, DispatchLevel);
		}

	} while (bFalse);

	KdPrint(("<===ReceiveNetBufferList: Flags = %8x.\n", ReceiveFlags));
}

