#include "precomp.h"

/**
 * 黑名单列表操作
 * @Author Yue
 */

LIST_ENTRY BlackDataList;
KSPIN_LOCK BlackDataListLock;

//初始化BlackDataList
VOID InitBlackDataList(){
	KdPrint(("--NDIS--Init BlackDataList--\n"));
	InitializeListHead(&BlackDataList);
	KeInitializeSpinLock(&BlackDataListLock);
}

//清除BlackDataList
VOID UnInitBlackDataList(){
	KdPrint(("--NDIS-BlackDataList UnInit IN--\n"));
	KLOCK_QUEUE_HANDLE handle;
	KeAcquireInStackQueuedSpinLock(&BlackDataListLock,&handle);
	if (!IsListEmpty(&BlackDataList)){
		while (!IsListEmpty(&BlackDataList)){
			PLIST_ENTRY pEntry = RemoveTailList(&BlackDataList);
			PBLACK_LIST prl = CONTAINING_RECORD(pEntry, BLACK_LIST, ListEntry);
			ExFreePool(prl);
		}
	}
	else
		KdPrint(("List is Empty!!!!!"));
	KeReleaseInStackQueuedSpinLock(&handle);
	KdPrint(("--NDIS-BlackDataList UnInit OUT--\n"));
}

//插入黑名单链表
NTSTATUS InsertBlackList(PBLACK_LIST pBL){
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	KLOCK_QUEUE_HANDLE handle;

	KeAcquireInStackQueuedSpinLock(&BlackDataListLock,&handle);

	InsertHeadList(&BlackDataList,&pBL->ListEntry);
	Status = STATUS_SUCCESS;

	KeReleaseInStackQueuedSpinLock(&handle);

	return Status;
}

//传入CHAR类型的原始字符串，要匹配的目的字符串，要匹配字符串的长度，返回Boolean值
BOOLEAN KMPmatched(CHAR	*D, ULONG DLength, CHAR *M, ULONG MLength){

	BOOLEAN Matched = FALSE;

	////////////////CREATE/////////////NEXT//////////////////////////////

	INT next[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	/*for (int o = 0; o < MLength; o++)
		KdPrint(("next [%d] : %d\n", o, next[o]));*/

	int q, k;						//k记录所有前缀的对称值
	int h = MLength;				//模式字符串的长度
	//首字符的对称值肯定为0
	for (q = 1, k = 0; q < h; ++q)	//计算每一个位置的对称值
	{
		//k总是用来记录上一个前缀的最大对称值
		while (k > 0 && M[q] != M[k])
			k = next[k - 1];		//k将循环递减，值得注意的是next[k]<k总是成立
		if (M[q] == M[k])
			k++;					//增加k的唯一方法
		next[q] = k;				//获取最终值
		//KdPrint(("Next %d : %d\n", q, next[q]));
	}

	/*for (int o = 0; o < MLength; o++)
		KdPrint(("next [%d] : %d\n", o, next[o]));*/

	//////////////////////////////////////////////////////////////////

	for (int i = 0, z = 0; i < DLength - 1; ++i)
	{
		while (z > 0 && M[z] != D[i])
			z = next[z - 1];
		if (M[z] == D[i])
			z++;
		if (z == MLength)
		{
			Matched = TRUE;
			//KdPrint(("模式文本的偏移为 :%d\n", i - MLength + 1));
			z = next[z - 1];			//寻找下一个匹配
		}
	}

	//////////////////////////////////////////////////////////////////

	if (Matched){
		KdPrint(("=======NDIS==URL=========Matched it=================\n"));
	}
	else{
		KdPrint(("=======NDIS==URL=======Not Matched it================\n"));
	}

	return Matched;
}

//过滤操作:协议，端口，IP，MAC，网址
NTSTATUS Filtering(PDATA pdt,ULONG DataLength){
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	KLOCK_QUEUE_HANDLE handle;
	LIST_ENTRY* entry = NULL;

	KeAcquireInStackQueuedSpinLock(&BlackDataListLock,&handle);

	//BlackDataList是否为空
	if (IsListEmpty(&BlackDataList)){
		KdPrint(("--NDIS-BlackDataList Empty!--\n"));
	}
	else{
		int k = 1;
		KdPrint(("--NDIS-BlackDataList Not Empty!--\n"));
		for (entry = BlackDataList.Flink;
			entry != &BlackDataList;
			entry = entry->Flink){
			KdPrint(("第%d次！！！\n",k));
			k++;
			//提取链表节点
			PBLACK_LIST prl = CONTAINING_RECORD(entry, BLACK_LIST, ListEntry);
			int SameMacCountD = 0;
			int SameMacCountS = 0;
			int SameIpCountD = 0;
			int SameIpCountS = 0;

			//-----------------比较Mac-----------------
			for (int i = 0; i < 6; i++){
				if (pdt->DestinationMac[i] == prl->blackData.Mac[i])
					SameMacCountD += 1;
				if (pdt->SourceMac[i] == prl->blackData.Mac[i])
					SameMacCountS += 1;
			}
			if ((SameMacCountD == 6) || (SameMacCountS == 6)){
				KdPrint(("Mac 已匹配上黑名单Mac\n"));
				Status = STATUS_SUCCESS;
				break;
			}
			else
				KdPrint(("Mac 不匹配"));

			//-----------------比较Ip-----------------
			for (int j = 0; j < 4; j++){
				if (pdt->DestinationIp[j] == prl->blackData.Ip[j])
					SameIpCountD += 1;
				if (pdt->SourceIp[j] == prl->blackData.Ip[j])
					SameIpCountS += 1;
			}
			if ((SameIpCountD == 4) || (SameIpCountS == 4)){
				KdPrint(("Ip 已匹配上黑名单Ip\n"));
				Status = STATUS_SUCCESS;
				break;
			}
			else
				KdPrint(("Ip 不匹配"));

			//-----------------比较协议-----------------
			if (pdt->ProtoType != 0){
				if (pdt->ProtoType == prl->blackData.ProtoType){
					KdPrint(("ProtoType 已匹配上黑名单协议\n"));
					Status = STATUS_SUCCESS;
					break;
				}
				KdPrint(("协议 不匹配，继续向下\n"));
			}
			//过滤ARP,ICMP,IGMP等包头没有端口号的协议
			if ((pdt->ProtoType == PROTO_ARP)
				|| (pdt->ProtoType == PROTO_ICMP)
				|| (pdt->ProtoType == PROTO_IGMP)){
				KdPrint(("当前协议没有端口号，不能向下匹配\n"));
				break;
			}
			
			//-----------------比较端口-----------------
			//倘若数据包的端口为空
			if ((pdt->DestinationProt == 0)
				|| (pdt->SourceProt == 0)){
				KdPrint(("端口号为空,即非TCP/UDP协议\n"));
				break;
			}
			//不为空的情况下，比较端口
			if ((pdt->DestinationProt == prl->blackData.DestinationProt)
				||(pdt->SourceProt == prl->blackData.SourceProt)){
				KdPrint(("Port 已匹配上黑名单Port\n"));
				Status = STATUS_SUCCESS;
				break;
			}

			//-----------------比较HTTP头-----------------
			if ((pdt->ProtoType == PROTO_TCP) && (DataLength>54)){
				//匹配黑名单中的url
				if (KMPmatched(pdt->URL,
					DataLength,
					prl->blackData.URL,
					strlen(prl->blackData.URL))
					){
					KdPrint(("KMP Matched!!!!\n"));
					Status = STATUS_SUCCESS;
					break;
				}
			}
		}
	}
	KeReleaseInStackQueuedSpinLock(&handle);
	return Status;
}

//移除BlackList中指定规则
NTSTATUS RemoveBlackList(PBLACK_DATA pBD){
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PLIST_ENTRY entry = NULL;
	int time = 1;
	KdPrint(("--NDIS--RemoveBlackList--\n"));
	KLOCK_QUEUE_HANDLE handle;
	KeAcquireInStackQueuedSpinLock(&BlackDataListLock, &handle);

	if (IsListEmpty(&BlackDataList))
		KdPrint(("Black Data List is Empty\n"));
	else{
		KdPrint(("Black Data List Not Empty\n"));
		for (entry = BlackDataList.Flink;
			entry != &BlackDataList;
			entry = entry->Flink){
			//遍历整个链表，并确定哪个是节点
			//KdPrint(("第%d次\n",time));
			time++;
			int sameURL = 0;
			int sameMAC = 0;
			int sameIP = 0;
			PBLACK_LIST pBL =  CONTAINING_RECORD(entry, BLACK_LIST, ListEntry);
			//判断MAC
			for (int i = 0; i < 6; i++){
				if (pBL->blackData.Mac[i] == pBD->Mac[i])
					sameMAC += 1;
			}
			//判断IP
			for (int j = 0; j < 4; j++){
				if (pBL->blackData.Ip[j] == pBD->Ip[j])
					sameIP += 1;
			}
			//判断网址
			for (int k = 0; k < strlen(pBL->blackData.URL); k++){
				if (pBL->blackData.URL[k] == pBD->URL[k])
					sameURL += 1;
			}
			//判断协议,端口,以及上面元素相同数量
			if ((pBL->blackData.ProtoType == pBD->ProtoType) &&
				(pBL->blackData.DestinationProt == pBD->DestinationProt) &&
				(pBL->blackData.SourceProt == pBD->SourceProt) &&
				(sameMAC == 6) &&
				(sameIP == 4) &&
				(sameURL == strlen(pBL->blackData.URL))
				){
				KdPrint(("--NDIS已匹配-->删除--\n"));
				RemoveEntryList(&pBL->ListEntry);
				Status = STATUS_SUCCESS;
				break;
			}
		}
	}

	KeReleaseInStackQueuedSpinLock(&handle);
	return Status;
}
