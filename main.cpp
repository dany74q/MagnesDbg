#include "windows.h"
#include "Tlhelp32.h"
#include "stdio.h"
#include "conio.h"
#include "DbgHelp.h"
#include "magnesfuncs.h"

#define DETOUR "C:\\HookingDLL\\Detour.dll"

#ifdef _M_IX86
	#define OS "X86"
#elif _M_X64
	#define OS "X64"
#elif _M_IA64
	#define OS "IA64"
#endif

#pragma comment(lib, "Dbghelp.lib")

BOOL Detour(DWORD dwPid,PCHAR szTargetFunction,PCHAR szReplacementFunction,PCHAR szDll);
BOOL HookByInjection(PCHAR szHookedDll,DWORD dwProcId);
BOOL StackWalker(DWORD dwPid);

DWORD ThreadIdSnapper(DWORD dwPid);

int main(int argc, char ** argv)
{
	WCHAR szProcName;

	SymInitialize( GetCurrentProcess(), NULL, TRUE ); //Called in this process, as well is in the target
	Detour(5200,"CreateFileA","MyCreateFileA","C:\\HookingDLL\\Shield.dll");
	printf("%s\n",OS);
	printf("Can Debug:%d\n",EnableDebugPrivilege(TRUE));

	//HookByInjection("mdbg.dll",8132);
	
	/*MultiByteToWideChar(CP_ACP, //converting argv[1] to a wchar, so i can get its pid from the name
		MB_COMPOSITE,
		argv[1],
		-1,
		&szProcName,
		MAX_PATH);*/

	//StackWalker(PidByName(&szProcName));

	getch();
	return 0;
}

void GUI()
{
	
}

DWORD ThreadIdSnapper(DWORD dwPid)
{
	HANDLE hThreadSnapshot = INVALID_HANDLE_VALUE;
	THREADENTRY32 teAllThreads;

	hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,dwPid);
	teAllThreads.dwSize = sizeof(THREADENTRY32);
	if(INVALID_HANDLE_VALUE == hThreadSnapshot)
	{
		return -1;
	}
	if(FALSE == Thread32First(hThreadSnapshot,&teAllThreads))
	{
		printf("LastError:%d\n",GetLastError());
		return -1;
	}
	printf("Threads:\n");
	do{
		if(teAllThreads.th32OwnerProcessID == dwPid)
		{
			printf("--%d\n", teAllThreads.th32ThreadID);

		}
	}while(Thread32Next(hThreadSnapshot, &teAllThreads));	
	CloseHandle(hThreadSnapshot);
	return -1;
}

BOOL StackWalker(DWORD dwPid)
{
	HANDLE hTargetProc = INVALID_HANDLE_VALUE;
	HANDLE hThread = INVALID_HANDLE_VALUE;

	STACKFRAME64 stkCallStack;
	CONTEXT coThreadContext;
	char Input [MAG_BUFFER];

	UINT MaxStackFrames = MAX_FRAMES;
	DWORD MachineType;
	UINT StackFrame = 0;

	ThreadIdSnapper(dwPid);

	printf("Select Thread:\n");
	gets(Input);
	/*++ getting ready to walk the stack ++*/
	hTargetProc = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE,
		dwPid);

	hThread = OpenThread(THREAD_ALL_ACCESS,
		FALSE,
		atoi(Input));
	
	if(!SuspendThread(hThread))
	{
		//cleanup func
	}

	ZeroMemory( &coThreadContext, sizeof( CONTEXT ) ); //context struct cleanup
	coThreadContext.ContextFlags = CONTEXT_CONTROL;

	if(!GetThreadContext(hThread,&coThreadContext))
	{
		//cleanup func
	}
    ZeroMemory( &stkCallStack, sizeof( STACKFRAME64 ) ); //stack cleanup
	/*creating Stackframe for a 32bit comp*/

	 MachineType				   = IMAGE_FILE_MACHINE_I386;
	 stkCallStack.AddrPC.Offset    = coThreadContext.Eip;
	 stkCallStack.AddrPC.Mode      = AddrModeFlat;
	 stkCallStack.AddrFrame.Offset = coThreadContext.Ebp;
	 stkCallStack.AddrFrame.Mode   = AddrModeFlat;
	 stkCallStack.AddrStack.Offset = coThreadContext.Esp;
	 stkCallStack.AddrStack.Mode   = AddrModeFlat;

	while(StackFrame < MaxStackFrames)
	{
		if(!StackWalk64(
			MachineType,
			hTargetProc,
			hThread,
			&stkCallStack,
			&coThreadContext,
			NULL,
			SymFunctionTableAccess64,
			SymGetModuleBase64,
			NULL))
		{
			return FALSE;
		}

		if(stkCallStack.AddrPC.Offset != 0)
		{
			printf("--Call Address:0x%x\n",stkCallStack.AddrPC.Offset);
			StackFrame++;
		}
		else{
			return TRUE;
		}
	}
	ResumeThread(hThread);
	return TRUE;
}

BOOL HookByInjection(PCHAR szHookedDll,DWORD dwProcId)			//The hook will be set by injecting a DLL, if unspecified by user, would use default DLL
{
	BOOL bSuccess;

	HANDLE hTargetProcess = INVALID_HANDLE_VALUE;
	HANDLE hRemoteThread = INVALID_HANDLE_VALUE;

	HMODULE hmDllToLoad;
	HMODULE hmKernel32;

	FARPROC fpLoadLib;

	LPVOID lpTargetProcMem = NULL;

	DWORD dwRemoteThreadId;

	/*Will add UNICODE support in the future, using ascii only now*/
	hmKernel32 = GetModuleHandleA("kernel32.dll");
	fpLoadLib = GetProcAddress(hmKernel32,"LoadLibraryA");

	hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE,
		dwProcId);

	if(INVALID_HANDLE_VALUE == hTargetProcess)
	{
		//reserved for cleanup
	}

	lpTargetProcMem = VirtualAllocEx(hTargetProcess,	//allocating space for the dll path 
		NULL,
		strlen(szHookedDll) + 1,
		MEM_COMMIT,
		PAGE_EXECUTE_READWRITE);

	if(NULL == lpTargetProcMem)
	{
		//reserved for cleanup
	}
	
	bSuccess = WriteProcessMemory(hTargetProcess,
		lpTargetProcMem,
		szHookedDll,
		strlen(szHookedDll)+1,
		NULL);
	if(FALSE == bSuccess)
	{
		//reserved for cleanup
	}

	hRemoteThread = CreateRemoteThread(hTargetProcess,
		NULL,
		NULL,
		(LPTHREAD_START_ROUTINE)fpLoadLib,
		lpTargetProcMem,
		0,
		&dwRemoteThreadId);

	if(INVALID_HANDLE_VALUE == hRemoteThread)
	{
		//reserved for cleanup
	}
	return TRUE;
}
BOOL Detour(DWORD dwPid,PCHAR szTargetFunction,PCHAR szReplacementFunction,PCHAR szDll)
{
	HANDLE hNamedPipe = INVALID_HANDLE_VALUE;
	CHAR szRawArgs[MAG_BUFFER];
	DWORD dwBytesWritten;
	if(!HookByInjection(szDll,dwPid))
	{
		return FALSE;
	}
	if(!HookByInjection(DETOUR,dwPid))
	{
		return FALSE;
	}
	Sleep(100);
	printf("Opening Pipe\n");
	hNamedPipe = CreateFileA("\\\\.\\pipe\\dllargs",
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	ZeroMemory(szRawArgs,MAG_BUFFER);
	memcpy(szRawArgs,szTargetFunction,strlen(szTargetFunction));
	memcpy(&szRawArgs[strlen(szTargetFunction)]," ",1);
	memcpy(&szRawArgs[strlen(szTargetFunction)+1],szReplacementFunction,strlen(szReplacementFunction));
	memcpy(&szRawArgs[strlen(szTargetFunction)+1+strlen(szReplacementFunction)]," ",1);
	memcpy(&szRawArgs[strlen(szTargetFunction)+1+strlen(szReplacementFunction)+1],szDll,strlen(szDll));
    printf("%s\n",szRawArgs);
	if(!WriteFile(hNamedPipe,szRawArgs,MAG_BUFFER,&dwBytesWritten,NULL))
	{
		printf("Couldn't pass arguments\n");
		return FALSE;
	}
	return TRUE;
}

void SimpleGui()
{
	//WriteConsole(
}

BOOL GarbageCollector()
{
	return TRUE;
}