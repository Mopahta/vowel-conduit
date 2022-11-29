#include <Windows.h>
#include <iostream>
#include <fstream>
#include <TlHelp32.h>
#include <stdio.h>
#include <string>

#define _DEBUG

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
	BYTE* baseAddress;
	HINSTANCE hMod;
	FARPROC fOffset;
};


//Note: Exception support only x64 with build params /EHa or /EHc
bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize, FARPROC fOffset, 
				  bool ClearHeader = true, bool ClearNonNeededSections = true, 
				  bool AdjustProtections = true);
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);