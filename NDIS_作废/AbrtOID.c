#include "precomp.h"

/**
 * OID操作
 *
 * @Author Yue
 */

extern LIST_ENTRY          FilterModuleList;

//内部OID请求发送
NDIS_STATUS filterDoInternalRequest(IN PMS_FILTER FilterModuleContext,IN NDIS_REQUEST_TYPE RequestType,IN NDIS_OID Oid,IN PVOID InformationBuffer,IN ULONG InformationBufferLength,IN ULONG OutputBufferLength, OPTIONAL IN ULONG MethodId, OPTIONAL OUT PULONG pBytesProcessed){
	FILTER_REQUEST              FilterRequest;
	PNDIS_OID_REQUEST           NdisRequest = &FilterRequest.Request;
	NDIS_STATUS                 Status = NDIS_STATUS_SUCCESS;

	//KdPrint(("==>filterDoInternalRequest\n"));
	NdisZeroMemory(NdisRequest, sizeof(NDIS_OID_REQUEST));

	NdisInitializeEvent(&FilterRequest.ReqEvent);

	NdisRequest->Header.Type = NDIS_OBJECT_TYPE_OID_REQUEST;
	NdisRequest->Header.Revision = NDIS_OID_REQUEST_REVISION_1;
	NdisRequest->Header.Size = sizeof(NDIS_OID_REQUEST);
	NdisRequest->RequestType = RequestType;

	switch (RequestType)
	{
	case NdisRequestQueryInformation:
		NdisRequest->DATA.QUERY_INFORMATION.Oid = Oid;
		NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer =
			InformationBuffer;
		NdisRequest->DATA.QUERY_INFORMATION.InformationBufferLength =
			InformationBufferLength;
		break;

	case NdisRequestSetInformation:
		NdisRequest->DATA.SET_INFORMATION.Oid = Oid;
		NdisRequest->DATA.SET_INFORMATION.InformationBuffer =
			InformationBuffer;
		NdisRequest->DATA.SET_INFORMATION.InformationBufferLength =
			InformationBufferLength;
		break;

	case NdisRequestMethod:
		NdisRequest->DATA.METHOD_INFORMATION.Oid = Oid;
		NdisRequest->DATA.METHOD_INFORMATION.MethodId = MethodId;
		NdisRequest->DATA.METHOD_INFORMATION.InformationBuffer =
			InformationBuffer;
		NdisRequest->DATA.METHOD_INFORMATION.InputBufferLength =
			InformationBufferLength;
		NdisRequest->DATA.METHOD_INFORMATION.OutputBufferLength = OutputBufferLength;
		break;



	default:
		FILTER_ASSERT(FALSE);
		break;
	}

	NdisRequest->RequestId = (PVOID)FILTER_REQUEST_ID;
	Status = NdisFOidRequest(FilterModuleContext->FilterHandle,
		NdisRequest);

	if (Status == NDIS_STATUS_PENDING)
	{
		//NdisWaitEvent(&FilterRequest.ReqEvent, 0);
		//Status = FilterRequest.Status;
	}

	if (Status == NDIS_STATUS_SUCCESS)
	{
		if (RequestType == NdisRequestSetInformation)
		{
			*pBytesProcessed = NdisRequest->DATA.SET_INFORMATION.BytesRead;
		}

		if (RequestType == NdisRequestQueryInformation)
		{
			*pBytesProcessed = NdisRequest->DATA.QUERY_INFORMATION.BytesWritten;
			InformationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
		}

		if (RequestType == NdisRequestMethod)
		{
			*pBytesProcessed = NdisRequest->DATA.METHOD_INFORMATION.BytesWritten;
			InformationBuffer = NdisRequest->DATA.QUERY_INFORMATION.InformationBuffer;
		}


		// The driver below should set the correct value to BytesWritten 
		// or BytesRead. But now, we just truncate the value to InformationBufferLength


		if (RequestType == NdisRequestMethod)
		{
			if (*pBytesProcessed > OutputBufferLength)
			{
				*pBytesProcessed = OutputBufferLength;
			}
		}
		else
		{

			if (*pBytesProcessed > InformationBufferLength)
			{
				*pBytesProcessed = InformationBufferLength;
			}
		}
	}
	//add by leyond
	if (Status == NDIS_STATUS_INVALID_LENGTH || Status == NDIS_STATUS_BUFFER_TOO_SHORT)
	{
		KdPrint(("Still need more bytes = %u", NdisRequest->DATA.QUERY_INFORMATION.BytesNeeded));

	}

	if (Status == NDIS_STATUS_INVALID_OID)
	{
		KdPrint((" NDIS_STATUS_INVALID_OID--||--"));
	}

	return (Status);
}

//内部OID请求完成回调
VOID filterInternalRequestComplete(_In_ NDIS_HANDLE FilterModuleContext,_In_ PNDIS_OID_REQUEST NdisRequest,_In_ NDIS_STATUS Status){
	PFILTER_REQUEST              FilterRequest;

	UNREFERENCED_PARAMETER(FilterModuleContext);

	FilterRequest = CONTAINING_RECORD(NdisRequest, FILTER_REQUEST, Request);
	FilterRequest->Status = Status;
	NdisSetEvent(&FilterRequest->ReqEvent);
}

//驱动发送OID
_Use_decl_annotations_
NDIS_STATUS FilterOidRequest(NDIS_HANDLE FilterModuleContext,PNDIS_OID_REQUEST Request){

	PMS_FILTER              pFilter = (PMS_FILTER)FilterModuleContext;
	NDIS_STATUS             Status;
	PNDIS_OID_REQUEST       ClonedRequest = NULL;
	BOOLEAN                 bSubmitted = FALSE;
	PFILTER_REQUEST_CONTEXT Context;
	BOOLEAN                 bFalse = FALSE;

	//DEBUGP(DL_TRACE, "===>FilterOidRequest: Request %p.\n", Request);
	do
	{
		Status = NdisAllocateCloneOidRequest(pFilter->FilterHandle,
											Request,
											FILTER_TAG,
											&ClonedRequest);
		if (Status != NDIS_STATUS_SUCCESS)
		{
			DEBUGP(DL_WARN, "FilerOidRequest: Cannot Clone Request\n");
			break;
		}

		Context = (PFILTER_REQUEST_CONTEXT)(&ClonedRequest->SourceReserved[0]);
		*Context = Request;

		bSubmitted = TRUE;
		ClonedRequest->RequestId = Request->RequestId;
		pFilter->PendingOidRequest = ClonedRequest;
		Status = NdisFOidRequest(pFilter->FilterHandle, ClonedRequest);

		if (Status != NDIS_STATUS_PENDING)
		{


			FilterOidRequestComplete(pFilter, ClonedRequest, Status);
			Status = NDIS_STATUS_PENDING;
		}



	} while (bFalse);

	if (bSubmitted == FALSE)
	{
		switch (Request->RequestType)
		{
		case NdisRequestMethod:
			Request->DATA.METHOD_INFORMATION.BytesRead = 0;
			Request->DATA.METHOD_INFORMATION.BytesNeeded = 0;
			Request->DATA.METHOD_INFORMATION.BytesWritten = 0;
			break;

		case NdisRequestSetInformation:
			Request->DATA.SET_INFORMATION.BytesRead = 0;
			Request->DATA.SET_INFORMATION.BytesNeeded = 0;
			break;

		case NdisRequestQueryInformation:
		case NdisRequestQueryStatistics:
		default:
			Request->DATA.QUERY_INFORMATION.BytesWritten = 0;
			Request->DATA.QUERY_INFORMATION.BytesNeeded = 0;
			break;
		}

	}
	//KdPrint(("<===FilterOidRequest: Status %8x.\n", Status));
	return Status;
}

//取消OID请求发送
_Use_decl_annotations_
VOID FilterCancelOidRequest(NDIS_HANDLE FilterModuleContext,PVOID RequestId){
	PMS_FILTER                          pFilter = (PMS_FILTER)FilterModuleContext;
	PNDIS_OID_REQUEST                   Request = NULL;
	PFILTER_REQUEST_CONTEXT             Context;
	PNDIS_OID_REQUEST                   OriginalRequest = NULL;
	BOOLEAN                             bFalse = FALSE;

	FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);

	Request = pFilter->PendingOidRequest;

	if (Request != NULL)
	{
		Context = (PFILTER_REQUEST_CONTEXT)(&Request->SourceReserved[0]);

		OriginalRequest = (*Context);
	}

	if ((OriginalRequest != NULL) && (OriginalRequest->RequestId == RequestId))
	{
		FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);

		NdisFCancelOidRequest(pFilter->FilterHandle, RequestId);
	}
	else
	{
		FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);
	}


}

//OID请求发送成功
_Use_decl_annotations_
VOID FilterOidRequestComplete(NDIS_HANDLE FilterModuleContext,PNDIS_OID_REQUEST Request,NDIS_STATUS Status){
	PMS_FILTER                          pFilter = (PMS_FILTER)FilterModuleContext;
	PNDIS_OID_REQUEST                   OriginalRequest;
	PFILTER_REQUEST_CONTEXT             Context;
	BOOLEAN                             bFalse = FALSE;

	//KdPrint(("===>FilterOidRequestComplete, Request %p.\n", Request));

	Context = (PFILTER_REQUEST_CONTEXT)(&Request->SourceReserved[0]);
	OriginalRequest = (*Context);

	if (OriginalRequest == NULL)
	{
		filterInternalRequestComplete(pFilter, Request, Status);
		return;
	}

	FILTER_ACQUIRE_LOCK(&pFilter->Lock, bFalse);

	ASSERT(pFilter->PendingOidRequest == Request);
	pFilter->PendingOidRequest = NULL;

	FILTER_RELEASE_LOCK(&pFilter->Lock, bFalse);

	switch (Request->RequestType)
	{
	case NdisRequestMethod:
		OriginalRequest->DATA.METHOD_INFORMATION.OutputBufferLength = Request->DATA.METHOD_INFORMATION.OutputBufferLength;
		OriginalRequest->DATA.METHOD_INFORMATION.BytesRead = Request->DATA.METHOD_INFORMATION.BytesRead;
		OriginalRequest->DATA.METHOD_INFORMATION.BytesNeeded = Request->DATA.METHOD_INFORMATION.BytesNeeded;
		OriginalRequest->DATA.METHOD_INFORMATION.BytesWritten = Request->DATA.METHOD_INFORMATION.BytesWritten;
		break;

	case NdisRequestSetInformation:
		OriginalRequest->DATA.SET_INFORMATION.BytesRead = Request->DATA.SET_INFORMATION.BytesRead;
		OriginalRequest->DATA.SET_INFORMATION.BytesNeeded = Request->DATA.SET_INFORMATION.BytesNeeded;
		break;

	case NdisRequestQueryInformation:
	case NdisRequestQueryStatistics:
	default:
		OriginalRequest->DATA.QUERY_INFORMATION.BytesWritten = Request->DATA.QUERY_INFORMATION.BytesWritten;
		OriginalRequest->DATA.QUERY_INFORMATION.BytesNeeded = Request->DATA.QUERY_INFORMATION.BytesNeeded;
		break;
	}

	(*Context) = NULL;

	NdisFreeCloneOidRequest(pFilter->FilterHandle, Request);

	NdisFOidRequestComplete(pFilter->FilterHandle, OriginalRequest, Status);

	//DEBUGP(DL_TRACE, "<===FilterOidRequestComplete.\n");
}

