//L4D2 Lan over IPv6
//hook dll

//using hox patch

#include <stdio.h>
#include <WinSock2.h>
#include <Windows.h>
#include <WS2tcpip.h>
#pragma comment (lib,"ws2_32.lib")

#define SERVER_PORT 34665
#define CLIENT_PORT 32105
#define MAPTABLE_SIZE 7
#define MAP_FILE "v4v6map.txt"

struct mapnode {
	IN_ADDR ipv4;
	IN6_ADDR ipv6;
};

typedef int (__stdcall *pFuncRecvfrom)(SOCKET, char*, int, int, struct sockaddr*, int*);
typedef int (__stdcall *pFuncSendto)(SOCKET, const char*, int, int, const struct sockaddr*, int);
typedef int (__stdcall *pFuncGetsockname)(SOCKET, struct sockaddr*, int*);

mapnode maptable[MAPTABLE_SIZE] = { 0 };
LPVOID pMyrecvfrom;
LPVOID pMysendto;
LPVOID pRecvfromOrg;
LPVOID pSendtoOrg;
LPVOID pGetsocknameOrg;
SOCKET serverSocket;
SOCKET clientSocket;

TCHAR debugString[10];

void v4v6map() {
	FILE *f = fopen(MAP_FILE, "r");
	if (f == NULL) {
		OutputDebugString(L"Mapfile open failed.");
		return;
	}
	char buff[30];
	int i;
	for (i = 0; i < MAPTABLE_SIZE; i++) {
		if (fscanf(f, "%s", buff) == EOF)
			break;
		InetPtonA(AF_INET, buff, &(maptable[i].ipv4));
		fscanf(f, "%s", buff);
		InetPtonA(PF_INET6, buff, &(maptable[i].ipv6));
	}
	fclose(f);
	wsprintf(debugString, L"%d %s", i, L"items has added to maptable.");
	OutputDebugString(debugString);
}

void socket_init() {
	WSADATA wsaData;
	if (!!WSAStartup(MAKEWORD(2, 2), &wsaData)) {
		OutputDebugString(L"WSAStartup failed.");
		return;
	}
	
	serverSocket = socket(PF_INET6, SOCK_DGRAM, 0);
	clientSocket = socket(PF_INET6, SOCK_DGRAM, 0);
	if (serverSocket == INVALID_SOCKET || clientSocket == INVALID_SOCKET) {
		OutputDebugString(L"Create socket failed.");
		return;
	}

	unsigned long mode = 1;
	ioctlsocket(serverSocket, FIONBIO, &mode);
	ioctlsocket(clientSocket, FIONBIO, &mode);

	sockaddr_in6 socketAddr;
	memset(&socketAddr, 0, sizeof(socketAddr));

	socketAddr.sin6_family = PF_INET6;
	socketAddr.sin6_port = SERVER_PORT;
	socketAddr.sin6_addr = in6addr_any;
	if (bind(serverSocket, (struct sockaddr *)&socketAddr, sizeof(socketAddr)) == SOCKET_ERROR) {
		OutputDebugString(L"bind failed.");
		return;
	}
	socketAddr.sin6_port = CLIENT_PORT;
	if (bind(clientSocket, (struct sockaddr *)&socketAddr, sizeof(socketAddr))) {
		OutputDebugString(L"bind failed.");
		return;
	}
}

int __stdcall myrecvfrom(SOCKET s, char *buf, int len, int flags, struct sockaddr *from, int *fromlen) {
	int i, j;
	DWORD pRecvfrom = 0x2333333;
	DWORD pGetsockname = 0x2333334;
	DWORD pServerSocket = 0x2333335;
	DWORD pClientSocket = 0x2333336;
	mapnode *pMaptable = (mapnode*)0x2333337;
	sockaddr_in recvfromTemp;
	sockaddr_in6 recvfrom6Temp;
	int sockaddrSize = sizeof(recvfromTemp);
	int sockaddr6Size = sizeof(recvfrom6Temp);
	if (((pFuncGetsockname)pGetsockname)(s, (struct sockaddr *)&recvfromTemp, &sockaddrSize) == 0) {
		if (recvfromTemp.sin_port == SERVER_PORT || recvfromTemp.sin_port == CLIENT_PORT) {
			int result = ((pFuncRecvfrom)(pRecvfrom + 2))(recvfromTemp.sin_port == SERVER_PORT ? *((SOCKET*)pServerSocket) : *((SOCKET*)pClientSocket), buf, len, flags, (sockaddr *)&recvfrom6Temp, &sockaddr6Size);
			if (result <= 0)
				return result;
			for (i = 0; i < MAPTABLE_SIZE; i++) {
				for (j = 0; j < 16; j++)			//memcmp
					if (pMaptable[i].ipv6.u.Byte[j] != recvfrom6Temp.sin6_addr.u.Byte[j])
						break;
				if (j == 16) {				//memcmp == 0
					((sockaddr_in*)from)->sin_addr.S_un.S_addr = pMaptable[i].ipv4.S_un.S_addr;
					((sockaddr_in*)from)->sin_port = recvfrom6Temp.sin6_port;
					((sockaddr_in*)from)->sin_family = PF_INET;
					for (j = 0; j < 8; j++)
						((sockaddr_in*)from)->sin_zero[j] = 0;
					*fromlen = sockaddrSize;
					return result;
				}
			}
		}
	} 
	return ((pFuncRecvfrom)((DWORD)pRecvfrom+2))(s, buf, len, flags, from, fromlen);
}

int __stdcall mysendto(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen) {
	int i, j;
	DWORD pSendto = 0x2333333;
	DWORD pGetsockname = 0x2333334;
	DWORD pServerSocket = 0x2333335;
	DWORD pClientSocket = 0x2333336;
	mapnode *pMaptable = (mapnode*)0x2333337;
	sockaddr_in sendtoTemp;
	sockaddr_in6 sendto6Temp;
	int sockaddrSize = sizeof(sendtoTemp);
	int sockaddr6Size = sizeof(sendto6Temp);
	if (((pFuncGetsockname)(pGetsockname))(s, (sockaddr *)&sendtoTemp, &sockaddrSize) == 0) {
		if (sendtoTemp.sin_port == SERVER_PORT || sendtoTemp.sin_port == CLIENT_PORT) {
			for (i = 0; i < MAPTABLE_SIZE; i++) {
				if (((sockaddr_in*)to)->sin_addr.S_un.S_addr == pMaptable[i].ipv4.S_un.S_addr) {
					sendto6Temp.sin6_family = PF_INET6;
					sendto6Temp.sin6_flowinfo = 0;
					sendto6Temp.sin6_scope_id = 0;
					sendto6Temp.sin6_port = ((sockaddr_in *)to)->sin_port;
					for (j = 0; j < 16; j++)				//memcpy
						sendto6Temp.sin6_addr.u.Byte[j] = pMaptable[i].ipv6.u.Byte[j];
					return ((pFuncSendto)(pSendto + 2))(sendtoTemp.sin_port == SERVER_PORT ? *(SOCKET*)pServerSocket : *(SOCKET*)pClientSocket, buf, len, flags, (sockaddr*)&sendto6Temp, sockaddr6Size);
				}
			}
		}
	}
	return ((pFuncSendto)(pSendto + 2))(s, buf, len, flags, to, tolen);
}

void Writehookfunctions() {
	pRecvfromOrg = GetProcAddress(GetModuleHandle(L"ws2_32.dll"), "recvfrom");
	pSendtoOrg = GetProcAddress(GetModuleHandle(L"ws2_32.dll"), "sendto");
	pGetsocknameOrg = GetProcAddress(GetModuleHandle(L"ws2_32.dll"), "getsockname");

	DWORD myrecvfromSize = (DWORD)mysendto - (DWORD)myrecvfrom;
	DWORD mysendtoSize = (DWORD)Writehookfunctions - (DWORD)mysendto;
	DWORD socketSize = sizeof(SOCKET);
	DWORD maptableSize = sizeof(mapnode) * MAPTABLE_SIZE;

	pMyrecvfrom = VirtualAlloc(NULL, myrecvfromSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	pMysendto = VirtualAlloc(NULL, mysendtoSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	memcpy(pMyrecvfrom, myrecvfrom, myrecvfromSize);
	memcpy(pMysendto, mysendto, mysendtoSize);

	LPVOID pSocketandMaptable = VirtualAlloc(NULL, socketSize * 2 + maptableSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	LPVOID pServerSocket = pSocketandMaptable;
	LPVOID pClientSocket = (LPVOID)((DWORD)pSocketandMaptable + sizeof(SOCKET));
	LPVOID pMaptable = (LPVOID)((DWORD)pSocketandMaptable + (sizeof(SOCKET) * 2));
	memcpy(pServerSocket, &serverSocket, socketSize);
	memcpy(pClientSocket, &clientSocket, socketSize);
	memcpy(pMaptable, maptable, maptableSize);

	memcpy((LPVOID)((DWORD)pMyrecvfrom + 9), &pRecvfromOrg, sizeof(pRecvfromOrg));
	memcpy((LPVOID)((DWORD)pMyrecvfrom + 16), &pGetsocknameOrg, sizeof(pGetsocknameOrg));
	memcpy((LPVOID)((DWORD)pMyrecvfrom + 23), &pServerSocket, sizeof(pServerSocket));
	memcpy((LPVOID)((DWORD)pMyrecvfrom + 30), &pClientSocket, sizeof(pClientSocket));
	memcpy((LPVOID)((DWORD)pMyrecvfrom + 37), &pMaptable, sizeof(pMaptable));

	memcpy((LPVOID)((DWORD)pMysendto + 9), &pSendtoOrg, sizeof(pSendtoOrg));
	memcpy((LPVOID)((DWORD)pMysendto + 16), &pGetsocknameOrg, sizeof(pGetsocknameOrg));
	memcpy((LPVOID)((DWORD)pMysendto + 23), &pServerSocket, sizeof(pServerSocket));
	memcpy((LPVOID)((DWORD)pMysendto + 30), &pClientSocket, sizeof(pClientSocket));
	memcpy((LPVOID)((DWORD)pMysendto + 37), &pMaptable, sizeof(pMaptable));
}

void
hook() {
	OutputDebugString(L"Start to hook.");
	if (((PBYTE)pRecvfromOrg)[0] == 0xeb) {
		OutputDebugString(L"Already hooked by other programs.");
		return;
	}

	BYTE buff1[2] = { 0xeb,0xf9 };
	BYTE buff2[5] = { 0xe9,0 };

	DWORD recvfromOldProtect, sendtoOldProtect;
	if (!VirtualProtect((LPVOID)((DWORD)pRecvfromOrg - 5), 7, PAGE_EXECUTE_READWRITE, &recvfromOldProtect) || !VirtualProtect((LPVOID)((DWORD)pSendtoOrg - 5), 7, PAGE_EXECUTE_READWRITE, &sendtoOldProtect)) {
		OutputDebugString(L"VirtualProtect failed.");
		return;
	}

	DWORD distance;
	distance = (DWORD)pMyrecvfrom - (DWORD)pRecvfromOrg;
	memcpy(&buff2[1], &distance, 4);
	memcpy((LPVOID)((DWORD)pRecvfromOrg - 5), buff2, 5);
	memcpy(pRecvfromOrg, buff1, 2);
	distance = (DWORD)pMysendto - (DWORD)pSendtoOrg;
	memcpy(&buff2[1], &distance, 4);
	memcpy((LPVOID)((DWORD)pSendtoOrg - 5), buff2, 5);
	memcpy(pSendtoOrg, buff1, 2);

	VirtualProtect((LPVOID)((DWORD)pRecvfromOrg - 5), 7, recvfromOldProtect, &recvfromOldProtect);
	VirtualProtect((LPVOID)((DWORD)pSendtoOrg - 5), 7, sendtoOldProtect, &sendtoOldProtect);

	OutputDebugString(L"hook completed.");
}

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID lpvReserved) {
	switch (dwReason) {
	case DLL_PROCESS_ATTACH:
		OutputDebugString(L"L4D2 Lan over IPv6 attached!");
		v4v6map();
		socket_init();
		Writehookfunctions();
		hook();
		break;
	}
}

