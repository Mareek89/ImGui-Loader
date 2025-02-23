#include "process.h"

std::string Process::ExePath()
{
	char buffer[MAX_PATH];
	GetModuleFileName(NULL, buffer, MAX_PATH);
	std::string::size_type pos = std::string(buffer).find_last_of("\\/");
	return std::string(buffer).substr(0, pos);
}

uint32_t Process::get_process_thread_num_by_pid(uint32_t process_id) {
	PROCESSENTRY32 process_info;
	process_info.dwSize = sizeof(process_info);

	HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (h_snapshot == INVALID_HANDLE_VALUE)
		return 0;

	BOOL ret = Process32First(h_snapshot, &process_info);
	while (ret) {
		if (process_info.th32ProcessID == process_id) {
			CloseHandle(h_snapshot);
			return process_info.cntThreads;
		}
		ret = Process32Next(h_snapshot, &process_info);
	}
	return 0;
}

uint32_t Process::get_aow_pid(const char* processName)
{
	uint32_t ret = 0;
	uint32_t thread_count_max = 0;
	PROCESSENTRY32 process_info;
	process_info.dwSize = sizeof(process_info);

	HANDLE h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (h_snapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(h_snapshot, &process_info);
	do {
		if (strcmp(process_info.szExeFile, processName) == 0) {
			uint32_t tmp_thread_count = get_process_thread_num_by_pid(process_info.th32ProcessID);

			if (tmp_thread_count > thread_count_max) {
				thread_count_max = tmp_thread_count;
				ret = process_info.th32ProcessID;
			}
		}
	} while (Process32Next(h_snapshot, &process_info));
	CloseHandle(h_snapshot);
	return ret;
}

DWORD Process::GetProcessID(const char* processName)
{
	HANDLE Snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	PROCESSENTRY32 procStruct;
	procStruct.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(Snap, &procStruct))
	{
		do {
			if (!strcmp(processName, procStruct.szExeFile))
			{
				dwProcessId = (UINT32)procStruct.th32ProcessID;
				break;
			}
		} while (Process32Next(Snap, &procStruct));
	}
	CloseHandle(Snap);
	return(dwProcessId);
}

bool Process::is_process_running(const char* name)
{
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 PE32;
	ZeroMemory(&PE32, sizeof(PE32));
	PE32.dwSize = sizeof(PE32);

	if (Process32First(Snapshot, &PE32))
	{
		do
		{
			if (!strcmp(PE32.szExeFile, name))
			{
				CloseHandle(Snapshot);
				return true;
			}
		} while (Process32Next(Snapshot, &PE32));
	}

	CloseHandle(Snapshot);

	return false;
}

bool Process::Attach(const char* exeName, bool waitForProcess)
{
	PROCESSENTRY32 processEntry = { 0 };

	while (true)
	{
		HANDLE snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (snapShot == INVALID_HANDLE_VALUE)
			continue;

		processEntry.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(snapShot, &processEntry))
		{
			do
			{
				if (strcmp(processEntry.szExeFile, exeName) == 0)
				{
					CloseHandle(snapShot);
					dwProcessId = processEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(snapShot, &processEntry));
		}

		Sleep(30);

		if (!waitForProcess || dwProcessId != 0)
			break;
	}

	if (dwProcessId == 0)
		return 0;

	hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, FALSE, dwProcessId);

	return (hProcess != 0);
}

Process* g_pProcess = new Process;
