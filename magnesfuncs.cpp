#include "windows.h"
#include "Tlhelp32.h"
#include "stdio.h"
#include "conio.h"
#include "DbgHelp.h"
#include "magnesfuncs.h"

#pragma comment(lib, "Dbghelp.lib")


DWORD PidByName(WCHAR * name)
{
	DWORD dwPid;
	BOOL success;
	PROCESSENTRY32 prProcess;
	HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); //snapping all processes
	prProcess.dwSize = sizeof(PROCESSENTRY32);
	success = Process32First(hProcessSnap,&prProcess);
	do{
		if(wcscmp(name,prProcess.szExeFile) == 0)
		{
			return prProcess.th32ProcessID;
		}
	}while(Process32Next( hProcessSnap, &prProcess ));
	return -1;
}
BOOL EnableDebugPrivilege(BOOL bEnable) 
{
	BOOL bOk = FALSE; 
	HANDLE hToken;
	if(::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) 
	{	
		LUID uID;
		::LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &uID);
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = uID;
		tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
		::AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		bOk = (::GetLastError() == ERROR_SUCCESS);
		::CloseHandle(hToken);
	}
	return bOk;
}