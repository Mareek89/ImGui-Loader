#pragma once

#include <Windows.h>

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

#ifdef _WIN64
using f_RtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif

struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
	f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
	BYTE* pbase;
	HINSTANCE hMod;
	DWORD fdwReasonParam;
	LPVOID reservedParam;
	BOOL SEHSupport;
};

//Note: Exception support only x64 with build params /EHa or /EHc
bool ManualMapDll(HANDLE hProc, BYTE* pSrcData, SIZE_T FileSize, bool ClearHeader = true, bool ClearNonNeededSections = true, bool AdjustProtections = true, bool SEHExceptionSupport = true, DWORD fdwReason = DLL_PROCESS_ATTACH, LPVOID lpReserved = 0);
void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);
int manual_map(const char* dll_path, const char* proccessname);

//typedef BOOL(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);
//
//typedef struct _MANUAL_INJECT {
//	LPVOID  ImageBase;
//	PIMAGE_NT_HEADERS64 NtHeaders;
//	PIMAGE_BASE_RELOCATION BaseRelocation;
//	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
//	decltype(LoadLibraryA)* fnLoadLibraryA;
//	decltype(GetProcAddress)* fnGetProcAddress;
//}MANUAL_INJECT, * PMANUAL_INJECT;
//
//class manualmap {
//public:
//	int ManualMapMain(uint32_t usergroup, const char* proccessname, const char* dllname);
//	int Map(unsigned int pid, LPCSTR dllname, LPCSTR exename);
//};

extern MANUAL_MAPPING_DATA* g_manual_map;


