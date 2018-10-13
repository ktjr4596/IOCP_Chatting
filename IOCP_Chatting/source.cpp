#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "Ws2_32.lib")

#include <iostream>
#include <WinSock2.h>
#include <thread>
#include <string>

using std::cout;
using std::endl;
using std::cerr;

const int MAX_BUFFER = 1024;
const int SERVER_PORT = 3600;


struct SOCKETINFO
{
	WSAOVERLAPPED overlapped;
	WSABUF dataBuffer;
	SOCKET socket;
	char messageBuffer[MAX_BUFFER];
	int receiveBytes;
	int sendBytes;
};

DWORD WINAPI makeThread(LPVOID hIOCP);
static void sendThread(SOCKETINFO &);
int main()
{
	// Winsock Start - windock.dll 로드
	WSADATA WSAData;
	if (WSAStartup(MAKEWORD(2, 2), &WSAData) != 0)
	{
		printf("Error - Can not load 'winsock.dll' file\n");
		return 1;
	}

	// 1. 소켓생성  
	SOCKET listenSocket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (listenSocket == INVALID_SOCKET)
	{
		printf("Error - Invalid socket\n");
		return 1;
	}

	// 서버정보 객체설정
	SOCKADDR_IN serverAddr;
	memset(&serverAddr, 0, sizeof(SOCKADDR_IN));
	serverAddr.sin_family = PF_INET;
	serverAddr.sin_port = htons(SERVER_PORT);
	serverAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);

	// 2. 소켓설정
	if (bind(listenSocket, (struct sockaddr*)&serverAddr, sizeof(SOCKADDR_IN)) == SOCKET_ERROR)
	{
		printf("Error - Fail bind\n");
		// 6. 소켓종료
		closesocket(listenSocket);
		// Winsock End
		WSACleanup();
		return 1;
	}

	// 3. 수신대기열생성
	if (listen(listenSocket, 5) == SOCKET_ERROR)
	{
		printf("Error - Fail listen\n");
		// 6. 소켓종료
		closesocket(listenSocket);
		// Winsock End
		WSACleanup();
		return 1;
	}

	// 완료결과를 처리하는 객체(CP : Completion Port) 생성
	HANDLE hIOCP = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);

	// 워커스레드 생성
	// - CPU * 2개
	SYSTEM_INFO systemInfo;
	GetSystemInfo(&systemInfo);
	int threadCount = systemInfo.dwNumberOfProcessors * 2;
	unsigned long threadId;
	// - thread Handler 선언
	HANDLE *hThread = (HANDLE *)malloc(threadCount * sizeof(HANDLE));
	// - thread 생성
	for (int i = 0; i < threadCount; i++)
	{
		hThread[i] = CreateThread(NULL, 0, makeThread, &hIOCP, 0, &threadId);
	}

	SOCKADDR_IN clientAddr;
	int addrLen = sizeof(SOCKADDR_IN);
	memset(&clientAddr, 0, addrLen);
	SOCKET clientSocket;
	SOCKETINFO *socketInfo;
	DWORD receiveBytes;
	DWORD flags;

	while (1)
	{
		clientSocket = accept(listenSocket, (struct sockaddr *)&clientAddr, &addrLen);
		if (clientSocket == INVALID_SOCKET)
		{
			printf("Error - Accept Failure\n");
			return 1;
		}

		socketInfo = (struct SOCKETINFO *)malloc(sizeof(struct SOCKETINFO));
		memset((void *)socketInfo, 0x00, sizeof(struct SOCKETINFO));
		socketInfo->socket = clientSocket;
		socketInfo->receiveBytes = 0;
		socketInfo->sendBytes = 0;
		socketInfo->dataBuffer.len = MAX_BUFFER;
		socketInfo->dataBuffer.buf = socketInfo->messageBuffer;
		flags = 0;

		hIOCP = CreateIoCompletionPort((HANDLE)clientSocket, hIOCP, (DWORD)socketInfo, 0);

		// 중첩 소캣을 지정하고 완료시 실행될 함수를 넘겨준다.
		if (WSARecv(socketInfo->socket, &socketInfo->dataBuffer, 1, &receiveBytes, &flags, &(socketInfo->overlapped), NULL))
		{
			if (WSAGetLastError() != WSA_IO_PENDING)
			{
				printf("Error - IO pending Failure\n");
				return 1;
			}
		}
	}

	// 6-2. 리슨 소켓종료
	closesocket(listenSocket);

	// Winsock End
	WSACleanup();

	return 0;
}

DWORD WINAPI makeThread(LPVOID hIOCP)
{
	HANDLE threadHandler = *((HANDLE *)hIOCP);
	DWORD receiveBytes;
	DWORD sendBytes;
	DWORD completionKey;
	DWORD flags;
	struct SOCKETINFO *eventSocket;
	while (1)
	{
		// 입출력 완료 대기
		if (GetQueuedCompletionStatus(threadHandler, &receiveBytes, &completionKey, (LPOVERLAPPED *)&eventSocket, INFINITE) == 0)
		{
			printf("Error - GetQueuedCompletionStatus Failure\n");
			closesocket(eventSocket->socket);
			free(eventSocket);
			return 1;
		}

		std::thread t(sendThread, std::ref(eventSocket));
	
		//eventSocket->dataBuffer.len = receiveBytes;
		//printf("%d\n", eventSocket->socket);
		
		if (receiveBytes == 0)
		{
			closesocket(eventSocket->socket);
			free(eventSocket);
			continue;
		}
		else
		{
			printf("TRACE - Receive message : %s (%d bytes)\n", eventSocket->dataBuffer.buf, eventSocket->dataBuffer.len);

		//	printf("Input yout message : ");
		//	std::cin >> eventSocket->messageBuffer;
		//	eventSocket->sendBytes = strlen(eventSocket->messageBuffer);
		//	if (WSASend(eventSocket->socket, &(eventSocket->dataBuffer), 1, &sendBytes, 0, NULL, NULL) == SOCKET_ERROR)
		//	{
		//		if (WSAGetLastError() != WSA_IO_PENDING)
		//		{
		//			printf("Error - Fail WSASend(error_code : %d)\n", WSAGetLastError());
		//		}
		//	}

			//printf("TRACE - Send message : %s (%d bytes)\n", eventSocket->dataBuffer.buf, eventSocket->dataBuffer.len);

			memset(eventSocket->messageBuffer, 0x00, MAX_BUFFER);
			eventSocket->receiveBytes = 0;
			eventSocket->sendBytes = 0;
			eventSocket->dataBuffer.len = MAX_BUFFER;
			eventSocket->dataBuffer.buf = eventSocket->messageBuffer;
			flags = 0;

			if (WSARecv(eventSocket->socket, &(eventSocket->dataBuffer), 1, &receiveBytes, &flags, &eventSocket->overlapped, NULL) == SOCKET_ERROR)
			{
				if (WSAGetLastError() != WSA_IO_PENDING)
				{
					printf("Error - Fail WSARecv(error_code : %d)\n", WSAGetLastError());
				}
			}
		}
	}
}


static void sendThread(SOCKETINFO & eventsocket)
{
	DWORD sendBytes;
	while (1)
	{
		printf("Input yout message : ");
		std::cin >> eventsocket.messageBuffer;
		eventsocket.sendBytes = strlen(eventsocket.messageBuffer);
		if (WSASend(eventsocket.socket, &(eventsocket.dataBuffer), 1, &sendBytes, 0, NULL, NULL) == SOCKET_ERROR)
		{
			if (WSAGetLastError() != WSA_IO_PENDING)
			{
				printf("Error - Fail WSASend(error_code : %d)\n", WSAGetLastError());
			}
		}
		printf("TRACE - Send message : %s (%d bytes)\n", eventsocket.dataBuffer.buf,eventsocket.dataBuffer.len);
	}
}





//---------------------------------
//#define _WINSOCK_DEPRECATED_NO_WARNINGS
//#pragma comment(lib, "Ws2_32.lib")
//
//#include <iostream>
//#include <WinSock2.h>
//#include <thread>
//#include <string>
//
//using std::cout;
//using std::endl;
//using std::cerr;
//
//const int MAX_BUFFER = 1024;
//const int SERVER_PORT = 3600;
//const char * SERVER_IP = "192.168.10.205";
//
//struct SOCKETINFO
//{
//	WSAOVERLAPPED overlapped;
//	WSABUF dataBuffer;
//	SOCKET socket;
//	char messageBuffer[MAX_BUFFER];
//	int receiveBytes;
//	int sendBytes;
//};
//DWORD WINAPI MakeThread(LPVOID hIOCP);

//int main()
//{
//	WSADATA WSAData;
//	if (WSAStartup(MAKEWORD(2, 2), &WSAData) != 0)
//	{
//		cerr << "Error - Can not load 'winsock.dll' file" << endl;
//		getchar();
//		return -1;
//	}
//
//	SOCKET listenSocket = WSASocketW(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
//	if (listenSocket == INVALID_SOCKET)
//	{
//		cerr << "Error_Invalid socket" << endl;
//		getchar();
//		return -1;
//	}
//
//	SOCKADDR_IN ServerAddr;
//	memset(&ServerAddr, 0, sizeof(SOCKADDR_IN));
//	ServerAddr.sin_family = PF_INET;
//	ServerAddr.sin_port = htons(SERVER_PORT);
//	ServerAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
//
//
//
//
//
//
//	SYSTEM_INFO systemInfo;
//	GetSystemInfo(&systemInfo);
//	int threadCount = systemInfo.dwNumberOfProcessors * 2;
//	unsigned long threadId;
//
//	HANDLE * hThread = new HANDLE;
//
//
//
//	SOCKADDR_IN clientAddr;
//	int addrLen = sizeof(SOCKADDR_IN);
//	memset(&clientAddr, 0, addrLen);
//	SOCKET ClientSocket;
//	SOCKETINFO * socketInfo;
//	DWORD ReceiveBytes;
//	DWORD Flags;
//
//	const char * message = "hello,world";
//
//
//
//	if (connect(listenSocket, (sockaddr *)& ServerAddr, sizeof(ServerAddr)) != 0)
//	{
//		printf("error-connection error\n");
//		closesocket(listenSocket);
//
//		// Winsock End
//		WSACleanup();
//		return -1;
//	}
//
//
//
//	//send(listenSocket, message, strlen(message), 0);
//	//getchar();
//	char receivebuf[MAX_BUFFER];
//	//send(listenSocket, message, strlen(message), 0);
//	Flags = 0;
//	std::string Str_message;
//	int str_len = 0;
//	while (true)
//	{
//		printf("input yout message : ");
//		std::cin >> Str_message;
//		send(listenSocket, Str_message.c_str(), Str_message.size(), 0);
//		str_len = recv(listenSocket, receivebuf, 1024, 0);
//		printf("%d\n", str_len);
//		receivebuf[str_len + 1] = '\0';
//
//		puts(receivebuf);
//
//	}
//
//
//
//	closesocket(listenSocket);
//
//	// Winsock End
//	WSACleanup();
//
//	return 0;
//}

