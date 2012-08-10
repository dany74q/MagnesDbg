#ifndef MAGNESFUNCTIONS_H
#define MAGNESFUNCTIONS_H

#include "windows.h"
#include "Tlhelp32.h"
#include "stdio.h"
#include "conio.h"
#include "DbgHelp.h"

#pragma comment(lib, "Dbghelp.lib")

#define MAG_BUFFER 1024 //i like my buffers 1024
#define MAX_FRAMES 1024

DWORD PidByName(WCHAR * name);

BOOL EnableDebugPrivilege(BOOL bEnable);

#endif