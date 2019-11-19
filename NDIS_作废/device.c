#include "precomp.h"
#include <ndis.h>

/**
 * 设备驱动设置
 *
 * @Author Yue
 */

#pragma NDIS_INIT_FUNCTION(NdisFilterRegisterDevice)

extern	NDIS_HANDLE         FilterDriverHandle;
extern	NDIS_HANDLE         FilterDriverObject;

extern	FILTER_LOCK         FilterListLock;
extern	LIST_ENTRY          FilterModuleList;

NDIS_HANDLE			NdisFilterDeviceHandle = NULL;//驱动注册的设备句柄
PDEVICE_OBJECT      DeviceObject = NULL;//设备对象指针

//寻找过滤的Module
_IRQL_requires_max_(DISPATCH_LEVEL)
PMS_FILTER filterFindFilterModule(_In_reads_bytes_(BufferLength)PUCHAR  Buffer,_In_ ULONG BufferLength)
{

	PMS_FILTER              pFilter;
	PLIST_ENTRY             Link;
	BOOLEAN                  bFalse = FALSE;

	FILTER_ACQUIRE_LOCK(&FilterListLock, bFalse);

	Link = FilterModuleList.Flink;

	while (Link != &FilterModuleList)
	{
		pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

		if (BufferLength >= pFilter->FilterModuleName.Length)
		{
			if (NdisEqualMemory(Buffer, pFilter->FilterModuleName.Buffer, pFilter->FilterModuleName.Length))
			{
				FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
				return pFilter;
			}
		}

		Link = Link->Flink;
	}

	FILTER_RELEASE_LOCK(&FilterListLock, bFalse);
	return NULL;
}

//发送DIY数据包
NTSTATUS SendDIYNBL(PIRP Irp,PIO_STACK_LOCATION pIoStackIrp,UINT *sizeofWrite)
{
	KdPrint(("Send DIY NBL\n"));

	NTSTATUS    Status =  STATUS_UNSUCCESSFUL;

	/////////////////////////////////////////////////

	PVOID pInputBuffer, pOutputBuffer;
	ULONG  outputLength, inputLength;

	DbgPrint("COMM_BufferedIo\r\n");

	outputLength = pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength;
	inputLength = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
	pInputBuffer = Irp->AssociatedIrp.SystemBuffer;
	pOutputBuffer = Irp->AssociatedIrp.SystemBuffer;

	if (pInputBuffer && pOutputBuffer)
	{
		DbgPrint("COMM_BufferedIo UserModeMessage = '%s'", pInputBuffer);

		//RtlCopyMemory(pOutputBuffer, pInputBuffer, outputLength);

		CHAR  Buffer[1024] = { "DSFEREGRDHDRH" };

		RtlCopyMemory(pOutputBuffer, Buffer, sizeof(Buffer));

		*sizeofWrite = sizeof(Buffer);
		Status = STATUS_SUCCESS;
	}

	/////////////////////////////////////////////////A R P

	PMS_FILTER  pFilter;
	PLIST_ENTRY Link;

	ULONG		BufSize = 100;

	PETHeader	pEtheader = NULL;
	PARPHeader	pArpheader = NULL;

	PMDL		pMdl;
	PUCHAR		pEthFrame;

	PNET_BUFFER_LIST  pNewNBL;

	//获得MS_FILTER
	Link = FilterModuleList.Flink;
	pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);

	do{
		//封装自定义数据

		//创建 MDL & EthFrame
		pEthFrame = (PUCHAR)NdisAllocateMemoryWithTagPriority(
			pFilter->FilterHandle,
			BufSize,
			FILTER_ALLOC_TAG,
			LowPoolPriority
			);

		NdisZeroMemory(pEthFrame, BufSize);

		//ETHeader
		pEthFrame[0] = 0xff;
		pEthFrame[1] = 0xff;
		pEthFrame[2] = 0xff;
		pEthFrame[3] = 0xff;
		pEthFrame[4] = 0xff;
		pEthFrame[5] = 0xff;

		pEthFrame[6] = 0x08;
		pEthFrame[7] = 0x00;
		pEthFrame[8] = 0x27;
		pEthFrame[9] = 0x74;
		pEthFrame[10] = 0xc1;
		pEthFrame[11] = 0xa9;

		pEthFrame[12] = 0x08;
		pEthFrame[13] = 0x06;

		//ArpHeader
		pEthFrame[14] = 0x00;//hrd
		pEthFrame[15] = 0x01;

		pEthFrame[16] = 0x08;//eth_type
		pEthFrame[17] = 0x00;

		pEthFrame[18] = 0x06;//maclen

		pEthFrame[19] = 0x04;//iplen

		pEthFrame[20] = 0x00;//Arp request
		pEthFrame[21] = 0x01;

		pEthFrame[22] = 0x08;//Source Mac
		pEthFrame[23] = 0x00;
		pEthFrame[24] = 0x27;
		pEthFrame[25] = 0x74;
		pEthFrame[26] = 0xc1;
		pEthFrame[27] = 0xa9;

		pEthFrame[28] = 0xc0;//Source Ip
		pEthFrame[29] = 0xa8;
		pEthFrame[30] = 0x01;
		pEthFrame[31] = 0x6e;

		pEthFrame[32] = 0xff;//Destination Mac
		pEthFrame[33] = 0xff;
		pEthFrame[34] = 0xff;
		pEthFrame[35] = 0xff;
		pEthFrame[36] = 0xff;
		pEthFrame[37] = 0xff;

		pEthFrame[38] = 0xc0;//Destination Ip
		pEthFrame[39] = 0xa8;
		pEthFrame[40] = 0x01;
		pEthFrame[41] = 0x68;


		pMdl = NdisAllocateMdl(pFilter->FilterHandle,
			pEthFrame,
			BufSize
			);

		if (pMdl == NULL){
			KdPrint(("pMdl NULL\n"));
		}
		else{
			KdPrint(("pMDL SUccessful\n"));
		}

		//New NBL
		pNewNBL = NdisAllocateNetBufferAndNetBufferList(
					pFilter->SendNetBufferListPool,
					80,
					0,
					pMdl,
					0,
					BufSize
					);

		if (pNewNBL != NULL){
			KdPrint(("Create Memory Success.\n"));
			Status = STATUS_SUCCESS;
		}else{
			KdPrint(("pNewNBL Allocate Memory is NULL \n"));
			break;
		}

		KdPrint(("DataLength : %d\n",pNewNBL->FirstNetBuffer->DataLength));

		
		pNewNBL->SourceHandle = pFilter->FilterHandle;

		NdisFSendNetBufferLists(
					pFilter->FilterHandle,
					pNewNBL,
					NDIS_DEFAULT_PORT_NUMBER,
					NDIS_SEND_FLAGS_DISPATCH_LEVEL);
		KdPrint(("Send ARP Packet=====================\n"));

	} while (FALSE);

	KdPrint(("Send NBL End\n"));

	return Status;
}

//设置自己的IP
NTSTATUS SetSelfIP(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID pInputBuffer, pOutputBuffer;
	ULONG  outputLength, inputLength;

	DbgPrint("COMM_BufferedIo\r\n");

	outputLength = pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength;
	inputLength = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
	pInputBuffer = Irp->AssociatedIrp.SystemBuffer;
	pOutputBuffer = Irp->AssociatedIrp.SystemBuffer;

	if (pInputBuffer && pOutputBuffer)
	{
		DbgPrint("COMM_BufferedIo UserModeMessage = '%s'", pInputBuffer);

		//RtlCopyMemory(pOutputBuffer, pInputBuffer, outputLength);

		CHAR  Buffer[1024] = { "DSFEREGRDHDRH" };

		RtlCopyMemory(pOutputBuffer, Buffer, sizeof(Buffer));

		*sizeofWrite = sizeof(Buffer);
		status = STATUS_SUCCESS;
	}
	return status;
}

//应用设置黑名单列表
NTSTATUS SetBlackList(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite){
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PBLACK_DATA pInputBuffer;
	ULONG  outputLength, inputLength;

	KdPrint(("--NDIS---SetBlackList-----\r\n"));

	outputLength = pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength;
	inputLength = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
	pInputBuffer = (PBLACK_DATA)Irp->AssociatedIrp.SystemBuffer;

	if (pInputBuffer){

		NTSTATUS Status = STATUS_SUCCESS;

		//KdPrint(("ProtoType: %c\n", pInputBuffer->ProtoType));
		//KdPrint(("Ip : %d-%d-%d-%d\n", (ULONG)pInputBuffer->Ip[0],(ULONG)pInputBuffer->Ip[1],(ULONG)pInputBuffer->Ip[2],(ULONG)pInputBuffer->Ip[3]));
		//KdPrint(("Mac : %2x-%2x-%2x-%2x-%2x-%2x\n",pInputBuffer->Mac[0],pInputBuffer->Mac[1],pInputBuffer->Mac[2],
		//			pInputBuffer->Mac[3],pInputBuffer->Mac[4],pInputBuffer->Mac[5]));

		PBLACK_LIST p = ExAllocatePool(NonPagedPool, sizeof(BLACK_LIST));
		RtlZeroMemory(p, sizeof(BLACK_LIST));

		//Ip copy
		for (int i = 0; i < 4; i++){
			p->blackData.Ip[i] = pInputBuffer->Ip[i];
		}
		//Mac copy
		for (int j = 0; j < 6; j++){
			p->blackData.Mac[j] = pInputBuffer->Mac[j];
		}
		//协议
		p->blackData.ProtoType = pInputBuffer->ProtoType;
		//端口
		p->blackData.DestinationProt = pInputBuffer->DestinationProt;
		p->blackData.SourceProt = pInputBuffer->SourceProt;
		//网址
		int SizeURL = strlen(pInputBuffer->URL);
		for (int i = 0; i < SizeURL; i++){
			p->blackData.URL[i] = pInputBuffer->URL[i];
		}
		//KdPrint(("pInputBuffer->URL: %s\n",pInputBuffer->URL));
		//KdPrint(("p->blackData.URL: %s\n", p->blackData.URL));

		//KdPrint(("Copied Ip: %d-%d-%d-%d\n", (ULONG)p->blackData.Ip[0], (ULONG)p->blackData.Ip[1],
		//	(ULONG)p->blackData.Ip[2], (ULONG)p->blackData.Ip[3]));
		//KdPrint(("Copied Mac: %2x-%2x-%2x-%2x-%2x-%2x\n", p->blackData.Mac[0], p->blackData.Mac[1],p->blackData.Mac[2],
		//	p->blackData.Mac[3], p->blackData.Mac[4], p->blackData.Mac[5]));

		Status = InsertBlackList(p);
		if (Status == STATUS_UNSUCCESSFUL){
			KdPrint(("Insert Failed!\n"));
		}
		else{
			KdPrint(("Insert Success!\n"));
		}

		*sizeofWrite = 0;
		status = STATUS_SUCCESS;
	}
	return status;
}

//移除指定黑名单节点
NTSTATUS RemoveBlack(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite){
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PBLACK_DATA pInputBuffer;
	ULONG  outputLength, inputLength;
	KdPrint(("--NDIS---RemoveBlack-----\n"));
	outputLength = pIoStackIrp->Parameters.DeviceIoControl.OutputBufferLength;
	inputLength = pIoStackIrp->Parameters.DeviceIoControl.InputBufferLength;
	pInputBuffer = (PBLACK_DATA)Irp->AssociatedIrp.SystemBuffer;
	if (pInputBuffer){
		if (NT_SUCCESS(RemoveBlackList(pInputBuffer))){
			*sizeofWrite = 0;
			Status = STATUS_SUCCESS;
		}
	}
	return Status;
}

//设备控制函数
_Use_decl_annotations_ 
NTSTATUS NdisFilterDeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = STATUS_NOT_SUPPORTED;
	PIO_STACK_LOCATION pIrpStack = NULL;
	UINT sizeofWrite = 0;

	KdPrint(("--NDIS--IoControl\r\n"));

	pIrpStack = IoGetCurrentIrpStackLocation(pIrp);

	if (pIrpStack)
	{
		switch (pIrpStack->Parameters.DeviceIoControl.IoControlCode)
		{

		case IOCTL_COMM_SEND_NBL:
			status = SendDIYNBL(pIrp, pIrpStack, &sizeofWrite);
			break;
			
		case IOCTL_COMM_SET_SELFIP:
			status = SetSelfIP(pIrp, pIrpStack, &sizeofWrite);
			break;

		case IOCTL_SET_BLACK_LIST:
			status = SetBlackList(pIrp, pIrpStack, &sizeofWrite);
			break;

		case IOCTL_DELETE_BLACK_LIST:
			status = RemoveBlack(pIrp, pIrpStack, &sizeofWrite);
			break;
		case IOCTL_CLEAR_BLACK_LIST:
			UnInitBlackDataList();
			status = STATUS_SUCCESS;
			break;
		default:
			break;
		}
	}

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = sizeofWrite;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}

//基本操作设备派遣函数
_Use_decl_annotations_
NTSTATUS NdisFilterDispatch(PDEVICE_OBJECT DeviceObject,PIRP Irp)
{

	//KdPrint(("===>NdisFilterTESTDispatch##################################>.\n"));
	PIO_STACK_LOCATION       IrpStack;
	NTSTATUS                 Status = STATUS_SUCCESS;

	PCHAR buffer = NULL;
	ULONG inLen = 0;
	ULONG outLen = 0;

	CHAR outbuffer[1024] = { "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx" };

	UNREFERENCED_PARAMETER(DeviceObject);

	IrpStack = IoGetCurrentIrpStackLocation(Irp);

	switch (IrpStack->MajorFunction)
	{
	case IRP_MJ_CREATE:
		KdPrint(("IRP_MJ_CREATE*********************************\n"));
		break;

	case IRP_MJ_CLEANUP:
		KdPrint(("IRP_MJ_CLEANUP*********************************\n"));
		break;

	case IRP_MJ_CLOSE:
		KdPrint(("IRP_MJ_CLOSE*********************************\n"));
		break;
	default:
		KdPrint(("*********************************\n"));
		break;
	}


	Irp->IoStatus.Status = Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Status;
}

