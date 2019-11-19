#include <ntddk.h>

#define FILE_DEVICE_COMM_DRIVER 0x00008811

/**
 * IoControl头文件
 *
 * @Author Yue
 */

typedef struct _DATA{
	//Mac地址
	UCHAR      SourceMac[6];
	UCHAR	   DestinationMac[6];

	//IP地址
	UCHAR	   SourceIp[4];
	UCHAR	   DestinationIp[4];

	//端口
	USHORT      DestinationProt;
	USHORT	   SourceProt;

	//URL网址
	UCHAR	   URL[2048];

	//协议类型
	UCHAR     ProtoType;
}DATA, *PDATA;

//BLACK LISTS
typedef struct _BLACK_DATA{
	//Mac地址过滤
	UCHAR      Mac[6];

	//IP地址过滤
	UCHAR	   Ip[4];

	//端口过滤
	USHORT     DestinationProt;
	USHORT	   SourceProt;

	//需要过滤的URL网址
	UCHAR	   URL[20];

	//需要过滤的协议类型
	UCHAR     ProtoType;
}BLACK_DATA, *PBLACK_DATA;

typedef struct _BLACK_LIST{
	LIST_ENTRY ListEntry;
	BLACK_DATA blackData;
}BLACK_LIST, *PBLACK_LIST;

#define IOCTL_CLEAR_BLACK_LIST		CTL_CODE(FILE_DEVICE_COMM_DRIVER, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_COMM_SEND_NBL			CTL_CODE(FILE_DEVICE_COMM_DRIVER, 0x806, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_COMM_SET_SELFIP		CTL_CODE(FILE_DEVICE_COMM_DRIVER, 0x807, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DELETE_BLACK_LIST     CTL_CODE(FILE_DEVICE_COMM_DRIVER, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_BLACK_LIST		CTL_CODE(FILE_DEVICE_COMM_DRIVER, 0x809, METHOD_BUFFERED, FILE_ANY_ACCESS)

//初始化BlackDataList
VOID InitBlackDataList();

//清除BlackDataList
VOID UnInitBlackDataList();

//插入黑名单链表
NTSTATUS InsertBlackList(PBLACK_LIST pBL);

//移除黑名单节点
NTSTATUS RemoveBlackList(PBLACK_DATA pBD);

//过滤操作
NTSTATUS Filtering(PDATA pBD,ULONG Datalength);

NTSTATUS COMM_DirectOutIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite);
NTSTATUS COMM_DirectInIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite);
NTSTATUS COMM_BufferedIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite);
NTSTATUS COMM_NeitherIo(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite);

NTSTATUS QueryOidValue(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite);
NTSTATUS SetOidValue(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite);

//用户增加黑名单节点
NTSTATUS SetBlackList(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite);

//用户移除指定黑名单节点
NTSTATUS RemoveBlack(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, UINT *sizeofWrite);