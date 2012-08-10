#include "windows.h"
#include "stdio.h"
#include "magnesfuncs.h"
#include "string.h"

#define SIZE 6

BYTE JMP[SIZE] = {0};
BYTE backupBytes[SIZE] ={0};
DWORD oldProtect, myProtect = PAGE_EXECUTE_READWRITE;

BOOL ParseDetourArgs(PCHAR szRawArgs,PCHAR szTarget,PCHAR szSrc,PCHAR szDll);

	HANDLE hNamedPipe;
	HMODULE hSuppliedDll;
	DWORD dwBuffSize;
	DWORD dwBytesRead;

	CHAR szRawArgs[MAG_BUFFER];
	
	CHAR szDllName[MAG_BUFFER];
	
	CHAR szTargetFunc[MAG_BUFFER];
	
	CHAR szSuppliedFunc[MAG_BUFFER];
	

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	
	ZeroMemory(szRawArgs,MAG_BUFFER);
	ZeroMemory(szDllName,MAG_BUFFER);
	ZeroMemory(szTargetFunc,MAG_BUFFER);
	ZeroMemory(szSuppliedFunc,MAG_BUFFER);

	hNamedPipe = CreateNamedPipeA("\\\\.\\pipe\\dllargs",
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_BYTE,
		PIPE_UNLIMITED_INSTANCES ,
		MAG_BUFFER,
		MAG_BUFFER,
		INFINITE,
		NULL);

	Sleep(1000);
	if(!ReadFile(hNamedPipe,
		szRawArgs,
		MAG_BUFFER,
		&dwBytesRead,
		NULL))
	{
		
	}

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		
		//break;
	case DLL_THREAD_ATTACH:
		//break;
	case DLL_THREAD_DETACH:
		//break;
	case DLL_PROCESS_DETACH:
		MessageBoxExA(NULL,
		szRawArgs,
		"Hooked",
		MB_ABORTRETRYIGNORE,
		0);
		break;
	}
	//return TRUE;
}
BOOL ParseDetourArgs(PCHAR szRawArgs,PCHAR szTarget,PCHAR szSrc,PCHAR szDll)
{
	/*MessageBoxA(NULL,
		szRawArgs,
		szRawArgs,
		MB_ABORTRETRYIGNORE);*/
	return TRUE;
}