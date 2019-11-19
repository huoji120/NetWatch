#include <iostream>
#include <Windows.h>
#include <stdlib.h>
#include <winternl.h>
#pragma comment(lib,"ws2_32.lib")
#define DEVICE_NAME L"\\Device\\EzFireWall"
#define DEVICE_SERVER_NAME L"EzFireWall"
/*
enum ReportType
{
	r_income, //进来auth
	r_output, //出去auth
	r_stream_income,  //TCP流交互
	r_stream_output
};
enum Protocoltype
{
	Pro_ICMP = 1,
	Pro_IGMP = 2,
	Pro_TCP = 6,
	Pro_UDP = 17,
	Pro_RDP = 27,
	Pro_UNKNOWN
};
struct Networkreport {
	ReportType type;
	Protocoltype Protocol;
	DWORD IPaddr;
	DWORD BuffDataLen;
	char* BuffData;
};
std::string GetSigHex(char* data, int len)
{
	char buf[0xFFFF] = { 0 };
	for (int i = 0; i < len; i++)
	{
		char test[8] = { 0 };
		if (i == len - 1)
		{
			sprintf_s(test, "%02X", (BYTE)data[i]);
			strcat_s(buf, test);
		}
		else
		{
			sprintf_s(test, "%02X ", (BYTE)data[i]);
			strcat_s(buf, test);
		}
	}
	return std::string(buf);
}
int main()
{
	HANDLE hPipe = CreateNamedPipe(
		TEXT("\\\\.\\Pipe\\EzFireWall"),
		PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		0,
		0,
		NMPWAIT_WAIT_FOREVER,
		NULL);
	if (INVALID_HANDLE_VALUE == hPipe)
		return false;
    std::cout << "创建管道完毕,监听程序...\n";
	const int size = 1024 * 10;
	char buf[size];
	DWORD rlen = 0;
	while (true)
	{
		if (ConnectNamedPipe(hPipe, NULL) != NULL)
		{
			if (ReadFile(hPipe, buf, size, &rlen, NULL) == FALSE)
				continue;
			else
			{
				//接收信息
				Networkreport* buffer_tmp = (Networkreport*)&buf;
				SIZE_T buffer_len = sizeof(Networkreport) + buffer_tmp->BuffDataLen;
				Networkreport* buffer = (Networkreport*)malloc(buffer_len);
				memcpy(buffer, buffer_tmp, buffer_len);
				char* data = (char*)malloc(buffer->BuffDataLen);
				BYTE* tmp = (BYTE*)buffer + sizeof(Networkreport);
				memcpy(data, tmp, buffer->BuffDataLen);
				DWORD RemoteIP = buffer->IPaddr;
				printf("远程IP:%u.%u.%u.%u 协议类型: %d 数据类型: %d 长度: %d \n", (RemoteIP >> 24) & 0xFF, (RemoteIP >> 16) & 0xFF, (RemoteIP >> 8) & 0xFF, RemoteIP & 0xFF, buffer->Protocol, buffer->type, buffer->BuffDataLen);
				if (buffer->type == r_stream_income || buffer->type == r_stream_output)
				{
					printf("数据: %s \n", GetSigHex(data,buffer->BuffDataLen).c_str());
				}
				free(data);
				free(buffer);
			}
		}

	}
	std::cout << "出现错误 \n";
	system("pause");
	return 0;
}
*/
#define IOCTL_ADD_BLACKLIST_DATA \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1337, METHOD_IN_DIRECT, FILE_ANY_ACCESS)
typedef NTSTATUS(WINAPI* NtOpenFileEx)(
	_Out_ PHANDLE            FileHandle,
	_In_  ACCESS_MASK        DesiredAccess,
	_In_  POBJECT_ATTRIBUTES ObjectAttributes,
	_Out_ PIO_STATUS_BLOCK   IoStatusBlock,
	_In_  ULONG              ShareAccess,
	_In_  ULONG              OpenOptions
	);
struct Networkstruct {
	int data_len;
	DWORD IP;
	char data[255];
};
typedef struct _PUSH_DATA {
	DWORD BlockIP;
	SIZE_T dataLen;
	char data[255];
}PUSH_DATA, * PPUSH_DATA;
NtOpenFileEx fpNtOpenFile = (NtOpenFileEx)GetProcAddress(GetModuleHandleA("ntdll"), "NtOpenFile");
HANDLE deviceHandle_;
bool is_loaded()
{
	if (!deviceHandle_ || deviceHandle_ == INVALID_HANDLE_VALUE) {
		//deviceHandle_ = CreateFile(L"C:\\windows\\TEMP\\cpuz147\\cpuz145_x64.sys", FILE_ALL_ACCESS, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		IO_STATUS_BLOCK io_status;
		NTSTATUS status;

		UNICODE_STRING    device_name = UNICODE_STRING{ sizeof(DEVICE_NAME) - sizeof(WCHAR), sizeof(DEVICE_NAME), (PWSTR)DEVICE_NAME };
		OBJECT_ATTRIBUTES obj_attr = OBJECT_ATTRIBUTES{ sizeof(OBJECT_ATTRIBUTES), nullptr, &device_name, 0, nullptr, nullptr };

		status = fpNtOpenFile(
			&deviceHandle_, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
			&obj_attr, &io_status, 0, OPEN_EXISTING);

		if (!NT_SUCCESS(status)) {
			ULONG i = 10;
			do {
				status = fpNtOpenFile(
					&deviceHandle_, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
					&obj_attr, &io_status, 0, OPEN_EXISTING);
				Sleep(250);
			} while (!NT_SUCCESS(status) && i--);
		}
	}
	return deviceHandle_ && deviceHandle_ != INVALID_HANDLE_VALUE;
}

int main()
{
	
	if (!is_loaded())
	{
		printf("加载驱动失败! %d \n", GetLastError());
		system("pause");
		return 0;
	}
	WSADATA wsaData;
	SOCKET ClientSocket;
	int port = 5099;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		return false;
	}

	SOCKET sockSrv = socket(AF_INET, SOCK_STREAM, 0);

	SOCKADDR_IN addrSrv;
	addrSrv.sin_family = AF_INET;
	addrSrv.sin_port = htons(port); //1024以上的端口号  
	addrSrv.sin_addr.S_un.S_addr = htonl(INADDR_ANY);

	int retVal = bind(sockSrv, (LPSOCKADDR)&addrSrv, sizeof(SOCKADDR_IN));
	if (retVal == SOCKET_ERROR) {
		return false;
	}

	if (listen(sockSrv, 10) == SOCKET_ERROR) {
		return false;
	}

	SOCKADDR_IN addrClient;
	int len = sizeof(SOCKADDR);
	static bool first = false;
	ClientSocket = accept(sockSrv, (SOCKADDR*)&addrClient, &len);
	if (ClientSocket == SOCKET_ERROR) {
		return false;
	}

	while (true)
	{
		char recvBuf[255];
		memset(recvBuf, 0, sizeof(recvBuf));
		if (recv(ClientSocket, recvBuf, sizeof(recvBuf), 0) == 0 || ClientSocket == INVALID_SOCKET)
		{
			first = false;
			closesocket(ClientSocket);
			ClientSocket = accept(sockSrv, (SOCKADDR*)&addrClient, &len);
			continue;
		}
		Networkstruct* buffer = (Networkstruct*)recvBuf;
		
		
		//1说明是ip 2说明是data
		char	output;
		DWORD	returnLen, read;
		PUSH_DATA data = { 0 };
		data.BlockIP = buffer->IP;
		data.dataLen = buffer->data_len;
		printf("buffer->data %s \n", buffer->data);
		memcpy(data.data, buffer->data,buffer->data_len);
		printf("buffer len: %d data: %s IP: 0x%08X\n", data.dataLen, data.data, data.BlockIP);
		
		if (!DeviceIoControl(deviceHandle_,
			IOCTL_ADD_BLACKLIST_DATA,
			(LPVOID)&data,
			sizeof(PUSH_DATA),
			&output,
			sizeof(char),
			&returnLen,
			NULL))
		{
			printf("DeviceIoControl错误: %d\n", GetLastError());
		}
		else
		{
			printf("提交规则成功 \n");
		}
		closesocket(ClientSocket);
		ClientSocket = accept(sockSrv, (SOCKADDR*)&addrClient, &len);
	}
	closesocket(sockSrv);
	WSACleanup();


	system("pause");
	return 0;
}