
#ifndef _FILT_H
#define _FILT_H

#pragma warning(disable:28930) // Unused assignment of pointer, by design in samples
#pragma warning(disable:28931) // Unused assignment of variable, by design in samples

// TODO: Customize these to hint at your component for memory leak tracking.
// These should be treated like a pooltag.
#define FILTER_REQUEST_ID          'RTLF'
#define FILTER_ALLOC_TAG           'tliF'
#define FILTER_TAG                 'dnTF'

// TODO: Specify which version of the NDIS contract you will use here.
// In many cases, 6.0 is the best choice.  You only need to select a later
// version if you need a feature that is not available in 6.0.
//
// Legal values include:
//    6.0  Available starting with Windows Vista RTM
//    6.1  Available starting with Windows Vista SP1 / Windows Server 2008
//    6.20 Available starting with Windows 7 / Windows Server 2008 R2
//    6.30 Available starting with Windows 8 / Windows Server "8"
#define FILTER_MAJOR_NDIS_VERSION   6

#if defined(NDIS60)
#define FILTER_MINOR_NDIS_VERSION   0
#elif defined(NDIS620)
#define FILTER_MINOR_NDIS_VERSION   20
#elif defined(NDIS630)
#define FILTER_MINOR_NDIS_VERSION   30
#endif

/**
 * 驱动入口
 *
 * @Author Yue
 */

//
// Global variables
//
extern NDIS_HANDLE         FilterDriverHandle; // NDIS handle for filter driver
extern NDIS_HANDLE         FilterDriverObject;
extern NDIS_HANDLE         NdisFilterDeviceHandle;
extern PDEVICE_OBJECT      DeviceObject;

extern FILTER_LOCK         FilterListLock;
extern LIST_ENTRY          FilterModuleList;

#define FILTER_FRIENDLY_NAME        L"NdisFilter WALL"
#define FILTER_UNIQUE_NAME          L"{7d2e22c5-d9c9-4480-8fc8-67d16ad9838b}" //unique name, quid name
#define FILTER_SERVICE_NAME         L"NdisFilterTEST"


NDIS_HANDLE		NdisFHandle;//For Send OID by self

//
// The filter needs to handle IOCTLs
//
//LINK_NAME
#define LINKNAME_STRING             L"\\DosDevices\\NdisFilterTEST"
//DEVICE_NAME
#define NTDEVICE_STRING             L"\\Device\\NdisFilterTEST"

//////////////////////////////////////////////////////////////


/*

FTP:				21/tcp(0x15)
TFTP:				69/udp(0x45)
Secure Shell(安全登录),SCP(文件传输),端口重定向:
22/tcp(0x14)
Telnet远程登陆服务:	23/tcp(0x17)
SMTP:				25/tcp(0x19)
DNS服务:			53	  (0x35)
HTTP:				80	  (0x50)
POP3:				110/tcp(0x6e)
NNTP:				119	   (0x77)
NTP:				123		(0x7b)
IMAP				143		(0x8f)
SNMP				161		(0xa1)
IRC					194	    (0xc2)
HTTPS				(代理服务器)80/8080/3128/8081/9080 (0x50/0x1f90/0xc38/0x1f91/0x2378)
(服务器)443/tcp 443/udp (0x1bb)
HTTP服务器			80/tcp (0x50)

TOMCAT				8080 (0x1f90)
Symantec AV/Filter for MSE
8081 (0x1f91)
Oracle 数据库		1521 (0x5f1)
ORACLE EMCTL		1158 (0x486)
WIN2003远程登录		3389 (0xd3d)
Oracle XDB（ XML 数据库）
8080 (0x1f90)
MS SQL*SERVER数据库server
1433/tcp/udp(0x599)
MS SQL*SERVER数据库monitor
1434/tcp/udp(0x59a)

QQ的客户端端口:		4000 (0xfa0)
(因为每打开一个QQ客户端，就会占用一个端口，
所以就需要记录4000-4009都为QQ客户端端口)

注册端口：1024到49151。
动态或私有端口：49152到65535。
*/

#define ETHERTYPE_IP    0x0800
#define ETHERTYPE_ARP   0x0806

typedef struct _ETHeader         // 14 bytes
{
	UCHAR	dhost[6];			// 目的MAC地址destination mac address
	UCHAR	shost[6];			// 源MAC地址source mac address
	USHORT	type;				// 下层协议类型，如IP（ETHERTYPE_IP）、ARP（ETHERTYPE_ARP）等
} ETHeader, *PETHeader;

#define ARPHRD_ETHER 	1

// ARP协议opcodes
#define	ARPOP_REQUEST	1		// ARP 请求	
#define	ARPOP_REPLY		2		// ARP 响应

typedef struct _ARPHeader		// 28字节的ARP头
{
	USHORT	hrd;				//	硬件地址空间，以太网中为ARPHRD_ETHER
	USHORT	eth_type;			//  以太网类型，ETHERTYPE_IP ？？
	UCHAR	maclen;				//	MAC地址的长度，为6
	UCHAR	iplen;				//	IP地址的长度，为4
	USHORT	opcode;				//	操作代码，ARPOP_REQUEST为请求，ARPOP_REPLY为响应
	UCHAR	smac[6];			//	源MAC地址
	UCHAR	saddr[4];			//	源IP地址
	UCHAR	dmac[6];			//	目的MAC地址
	UCHAR	daddr[4];			//	目的IP地址
} ARPHeader, *PARPHeader;

//Protocol
#define PROTO_ARP	  8

#define PROTO_ICMP    1
#define PROTO_IGMP    2
#define PROTO_TCP     6
#define PROTO_UDP     17

typedef struct _IPHeader		// 20,USHORT占2个字节
{
	UCHAR     iphVerLen;      // 版本号和头长度（各占4位）
	UCHAR     ipTOS;          // 服务类型 
	USHORT    ipLength;       // 封包总长度，即整个IP报的长度
	USHORT    ipID;			  // 封包标识，惟一标识发送的每一个数据报

	USHORT     ipFlags;	      // 标志
	UCHAR     ipTTL;	      // 生存时间，就是TTL
	UCHAR     ipProtocol;     // 协议，可能是TCP、UDP、ICMP等
	USHORT    ipChecksum;     // 校验和
	UCHAR     ipSource[4];       // 源IP地址
	UCHAR     ipDestination[4];  // 目标IP地址
} IPHeader, *PIPHeader;

//  define the tcp flags....
#define   TCP_FIN   1
#define   TCP_SYN   2
#define   TCP_RST   4
#define   TCP_PSH   8
#define   TCP_ACK   16
#define   TCP_URG   32
#define   TCP_ACE   64
#define   TCP_CWR   128

typedef struct _TCPHeader	 //20 bytes
{
	PUCHAR			sourcePort[2];		// 16位源端口号
	PUCHAR			destinationPort[2];	// 16位目的端口号
	ULONG			sequenceNumber;		// 32位序列号
	ULONG			acknowledgeNumber;	// 32位确认号

	UCHAR			dataoffset;		// 高4位表示数据偏移
	UCHAR			flags;			// 6位标志位
	//FIN - 0x01
	//SYN - 0x02
	//RST - 0x04 
	//PUSH- 0x08
	//ACK- 0x10
	//URG- 0x20
	//ACE- 0x40
	//CWR- 0x80

	USHORT			windows;		// 16位窗口大小
	USHORT			checksum;		// 16位校验和
	USHORT			urgentPointer;		// 16位紧急数据偏移量 
} TCPHeader, *PTCPHeader;

typedef struct _UDPHeader
{
	USHORT			sourcePort;		// 源端口号		
	USHORT			destinationPort;// 目的端口号		
	USHORT			len;			// 封包长度
	USHORT			checksum;		// 校验和
} UDPHeader, *PUDPHeader;

typedef struct _ICMPHeader
{
	UCHAR   type;
	UCHAR   code;
	USHORT  checksum;
	USHORT  id;
	USHORT  sequence;
	ULONG   timestamp;
} ICMPHeader, *PICMPHeader;

//
// Types and macros to manipulate packet queue
//
typedef struct _QUEUE_ENTRY
{
	struct _QUEUE_ENTRY * Next;
}QUEUE_ENTRY, *PQUEUE_ENTRY;

typedef struct _QUEUE_HEADER
{
	PQUEUE_ENTRY     Head;
	PQUEUE_ENTRY     Tail;
} QUEUE_HEADER, PQUEUE_HEADER;


#if TRACK_RECEIVES
UINT         filterLogReceiveRefIndex = 0;
ULONG_PTR    filterLogReceiveRef[0x10000];
#endif

#if TRACK_SENDS
UINT         filterLogSendRefIndex = 0;
ULONG_PTR    filterLogSendRef[0x10000];
#endif

#if TRACK_RECEIVES
#define   FILTER_LOG_RCV_REF(_O, _Instance, _NetBufferList, _Ref)    \
{\
	filterLogReceiveRef[filterLogReceiveRefIndex++] = (ULONG_PTR)(_O); \
	filterLogReceiveRef[filterLogReceiveRefIndex++] = (ULONG_PTR)(_Instance); \
	filterLogReceiveRef[filterLogReceiveRefIndex++] = (ULONG_PTR)(_NetBufferList); \
	filterLogReceiveRef[filterLogReceiveRefIndex++] = (ULONG_PTR)(_Ref); \
if (filterLogReceiveRefIndex >= (0x10000 - 5))                    \
{                                                              \
	filterLogReceiveRefIndex = 0;                                 \
}                                                              \
}
#else
#define   FILTER_LOG_RCV_REF(_O, _Instance, _NetBufferList, _Ref)
#endif

#if TRACK_SENDS
#define   FILTER_LOG_SEND_REF(_O, _Instance, _NetBufferList, _Ref)    \
{\
	filterLogSendRef[filterLogSendRefIndex++] = (ULONG_PTR)(_O); \
	filterLogSendRef[filterLogSendRefIndex++] = (ULONG_PTR)(_Instance); \
	filterLogSendRef[filterLogSendRefIndex++] = (ULONG_PTR)(_NetBufferList); \
	filterLogSendRef[filterLogSendRefIndex++] = (ULONG_PTR)(_Ref); \
if (filterLogSendRefIndex >= (0x10000 - 5))                    \
{                                                              \
	filterLogSendRefIndex = 0;                                 \
}                                                              \
}

#else
#define   FILTER_LOG_SEND_REF(_O, _Instance, _NetBufferList, _Ref)
#endif


//
// DEBUG related macros.
//
#if DBG
#define FILTER_ALLOC_MEM(_NdisHandle, _Size)    \
	filterAuditAllocMem(\
	_NdisHandle, \
	_Size, \
	__FILENUMBER, \
	__LINE__);

#define FILTER_FREE_MEM(_pMem)                  \
	filterAuditFreeMem(_pMem);

#else
#define FILTER_ALLOC_MEM(_NdisHandle, _Size)     \
	NdisAllocateMemoryWithTagPriority(_NdisHandle, _Size, FILTER_ALLOC_TAG, LowPoolPriority)

#define FILTER_FREE_MEM(_pMem)    NdisFreeMemory(_pMem, 0, 0)

#endif //DBG

#if DBG_SPIN_LOCK
#define FILTER_INIT_LOCK(_pLock)                          \
	filterAllocateSpinLock(_pLock, __FILENUMBER, __LINE__)

#define FILTER_FREE_LOCK(_pLock)       filterFreeSpinLock(_pLock)


#define FILTER_ACQUIRE_LOCK(_pLock, DispatchLevel)  \
	filterAcquireSpinLock(_pLock, __FILENUMBER, __LINE__, DisaptchLevel)

#define FILTER_RELEASE_LOCK(_pLock, DispatchLevel)      \
	filterReleaseSpinLock(_pLock, __FILENUMBER, __LINE__, DispatchLevel)

#else
#define FILTER_INIT_LOCK(_pLock)      NdisAllocateSpinLock(_pLock)

#define FILTER_FREE_LOCK(_pLock)      NdisFreeSpinLock(_pLock)

#define FILTER_ACQUIRE_LOCK(_pLock, DispatchLevel)              \
{\
if (DispatchLevel)                                      \
{                                                       \
	NdisDprAcquireSpinLock(_pLock);                     \
}                                                       \
else                                                    \
{                                                       \
	NdisAcquireSpinLock(_pLock);                        \
}                                                       \
	}

#define FILTER_RELEASE_LOCK(_pLock, DispatchLevel)              \
{                                                           \
if (DispatchLevel)                                      \
{                                                       \
	NdisDprReleaseSpinLock(_pLock);                     \
}                                                       \
		else                                                    \
{                                                       \
	NdisReleaseSpinLock(_pLock);                        \
}                                                       \
}
#endif //DBG_SPIN_LOCK


#define NET_BUFFER_LIST_LINK_TO_ENTRY(_pNBL)    ((PQUEUE_ENTRY)(NET_BUFFER_LIST_NEXT_NBL(_pNBL)))
#define ENTRY_TO_NET_BUFFER_LIST(_pEnt)         (CONTAINING_RECORD((_pEnt), NET_BUFFER_LIST, Next))

#define InitializeQueueHeader(_QueueHeader)             \
{                                                       \
	(_QueueHeader)->Head = (_QueueHeader)->Tail = NULL; \
}

//
// Macros for queue operations
//
#define IsQueueEmpty(_QueueHeader)      ((_QueueHeader)->Head == NULL)

#define RemoveHeadQueue(_QueueHeader)                   \
	(_QueueHeader)->Head;                               \
{                                                   \
	PQUEUE_ENTRY pNext;                             \
	ASSERT((_QueueHeader)->Head);                   \
	pNext = (_QueueHeader)->Head->Next;             \
	(_QueueHeader)->Head = pNext;                   \
if (pNext == NULL)                              \
	(_QueueHeader)->Tail = NULL;                \
}

#define InsertHeadQueue(_QueueHeader, _QueueEntry)                  \
{                                                               \
	((PQUEUE_ENTRY)(_QueueEntry))->Next = (_QueueHeader)->Head; \
	(_QueueHeader)->Head = (PQUEUE_ENTRY)(_QueueEntry);         \
if ((_QueueHeader)->Tail == NULL)                           \
	(_QueueHeader)->Tail = (PQUEUE_ENTRY)(_QueueEntry);     \
}

#define InsertTailQueue(_QueueHeader, _QueueEntry)                      \
{                                                                   \
	((PQUEUE_ENTRY)(_QueueEntry))->Next = NULL;                     \
if ((_QueueHeader)->Tail)                                       \
	(_QueueHeader)->Tail->Next = (PQUEUE_ENTRY)(_QueueEntry);   \
		else                                                            \
		(_QueueHeader)->Head = (PQUEUE_ENTRY)(_QueueEntry);         \
		(_QueueHeader)->Tail = (PQUEUE_ENTRY)(_QueueEntry);             \
}


//
// Enum of filter's states
// Filter can only be in one state at one time
//
typedef enum _FILTER_STATE
{
	FilterStateUnspecified,
	FilterInitialized,
	FilterPausing,
	FilterPaused,
	FilterRunning,
	FilterRestarting,
	FilterDetaching
} FILTER_STATE;


typedef struct _FILTER_REQUEST
{
	NDIS_OID_REQUEST       Request;
	NDIS_EVENT             ReqEvent;
	NDIS_STATUS            Status;
} FILTER_REQUEST, *PFILTER_REQUEST;

//
// Define the filter struct
//
typedef struct _MS_FILTER
{
	LIST_ENTRY                     FilterModuleLink;
	//Reference to this filter
	ULONG                           RefCount;

	NDIS_HANDLE                     FilterHandle;

	NDIS_STRING                     FilterModuleName;
	NDIS_STRING                     MiniportFriendlyName;
	NDIS_STRING                     MiniportName;
	NET_IFINDEX                     MiniportIfIndex;

	NDIS_STATUS                     Status;
	NDIS_EVENT                      Event;
	ULONG                           BackFillSize;
	FILTER_LOCK                     Lock;    // Lock for protection of state and outstanding sends and recvs

	FILTER_STATE                    State;   // Which state the filter is in
	ULONG                           OutstandingSends;
	ULONG                           OutstandingRequest;
	ULONG                           OutstandingRcvs;
	FILTER_LOCK                     SendLock;
	FILTER_LOCK                     RcvLock;
	QUEUE_HEADER                    SendNBLQueue;
	QUEUE_HEADER                    RcvNBLQueue;

	PNDIS_HANDLE					SendNetBufferListPool;
	PNDIS_HANDLE					SendNetBufferPool;


	NDIS_STRING                     FilterName;
	ULONG                           CallsRestart;
	BOOLEAN                         TrackReceives;
	BOOLEAN                         TrackSends;
#if DBG
	BOOLEAN                         bIndicating;
#endif

	PNDIS_OID_REQUEST               PendingOidRequest;

}MS_FILTER, *PMS_FILTER;


typedef struct _FILTER_DEVICE_EXTENSION
{
	ULONG            Signature;
	NDIS_HANDLE      Handle;
} FILTER_DEVICE_EXTENSION, *PFILTER_DEVICE_EXTENSION;


#define FILTER_READY_TO_PAUSE(_Filter)      \
	((_Filter)->State == FilterPausing)

//
// The driver should maintain a list of NDIS filter handles
//
typedef struct _FL_NDIS_FILTER_LIST
{
	LIST_ENTRY              Link;
	NDIS_HANDLE             ContextHandle;
	NDIS_STRING             FilterInstanceName;
} FL_NDIS_FILTER_LIST, *PFL_NDIS_FILTER_LIST;

//
// The context inside a cloned request
//
typedef struct _NDIS_OID_REQUEST *FILTER_REQUEST_CONTEXT, **PFILTER_REQUEST_CONTEXT;


//
// function prototypes
//

DRIVER_INITIALIZE DriverEntry;

FILTER_SET_OPTIONS FilterRegisterOptions;

FILTER_ATTACH FilterAttach;

FILTER_DETACH FilterDetach;

DRIVER_UNLOAD FilterUnload;

FILTER_RESTART FilterRestart;

FILTER_PAUSE FilterPause;

FILTER_OID_REQUEST FilterOidRequest;

FILTER_CANCEL_OID_REQUEST FilterCancelOidRequest;

FILTER_STATUS FilterStatus;

FILTER_DEVICE_PNP_EVENT_NOTIFY FilterDevicePnPEventNotify;

FILTER_NET_PNP_EVENT FilterNetPnPEvent;

FILTER_OID_REQUEST_COMPLETE FilterOidRequestComplete;

FILTER_SEND_NET_BUFFER_LISTS FilterSendNetBufferLists;

FILTER_RETURN_NET_BUFFER_LISTS FilterReturnNetBufferLists;

FILTER_SEND_NET_BUFFER_LISTS_COMPLETE FilterSendNetBufferListsComplete;

FILTER_RECEIVE_NET_BUFFER_LISTS FilterReceiveNetBufferLists;

FILTER_CANCEL_SEND_NET_BUFFER_LISTS FilterCancelSendNetBufferLists;

FILTER_SET_MODULE_OPTIONS FilterSetModuleOptions;

DRIVER_DISPATCH NdisFilterDispatch;

DRIVER_DISPATCH NdisFilterDeviceIoControl;

_IRQL_requires_max_(PASSIVE_LEVEL)
NDIS_STATUS
NdisFilterRegisterDevice(
VOID
);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
NdisFilterDeregisterDevice(
VOID
);

_IRQL_requires_max_(DISPATCH_LEVEL)
PMS_FILTER
filterFindFilterModule(
_In_reads_bytes_(BufferLength)
PUCHAR                   Buffer,
_In_ ULONG                    BufferLength
);

_IRQL_requires_max_(DISPATCH_LEVEL)
NDIS_STATUS
filterDoInternalRequest(
_In_ PMS_FILTER                   FilterModuleContext,
_In_ NDIS_REQUEST_TYPE            RequestType,
_In_ NDIS_OID                     Oid,
_Inout_updates_bytes_to_(InformationBufferLength, *pBytesProcessed)
PVOID                        InformationBuffer,
_In_ ULONG                        InformationBufferLength,
_In_opt_ ULONG                    OutputBufferLength,
_In_ ULONG                        MethodId,
_Out_ PULONG                      pBytesProcessed
);

VOID
filterInternalRequestComplete(
_In_ NDIS_HANDLE                  FilterModuleContext,
_In_ PNDIS_OID_REQUEST            NdisRequest,
_In_ NDIS_STATUS                  Status
);

//分配新的NBL，用来保存即将需要解析过滤的NBL
PNET_BUFFER_LIST
filterAllocateNetBufferList(
PMS_FILTER	pFilter,
ULONG		OldMDLLength
);
//将旧的NBL复制给新的NBL
PNET_BUFFER_LIST
filterCopyToNewNetBufferList(
PNET_BUFFER_LIST	OldNBL,
PMS_FILTER			pFilter
);
//过滤解析报头及包信息
NDIS_STATUS
filterFilterNetBufferList(
PUCHAR		Data,
ULONG		DataLength
);
//获得NBL有效数据总长度
ULONG
filterGetNBLLength(
PNET_BUFFER_LIST NBL
);
//扫描其中一个NBL
BOOLEAN
filterScanSingleNBL(
PNET_BUFFER_LIST NetBufferLists,
//UCHAR			 Rules,
PMS_FILTER		 pFilter
);

//发送自定义DIY网络数据包
NTSTATUS
SendDIYNBL(
PIRP Irp,
PIO_STACK_LOCATION pIoStackIrp,
UINT *sizeofWrite
);

//KMP匹配
BOOLEAN
KMPmatched(
CHAR *D,
ULONG DLength,
CHAR *M,
ULONG MLength
);

//Ip 包过滤
BOOLEAN
IPFilter(
PIPHeader ipHeader
);

//HTTP 包过滤
BOOLEAN
HTTPFilter(
PUCHAR	Data,
ULONG	DataLength
);

//TCP 包过滤
BOOLEAN
TCPFilter(
PUCHAR		Data,
ULONG		DataLength,
PTCPHeader	tcpHeader
);

//ARP 包过滤
BOOLEAN
ARPFilter(
PARPHeader arpHeader
);

#endif  //_FILT_H


