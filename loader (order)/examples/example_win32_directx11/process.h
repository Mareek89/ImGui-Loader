#pragma once

#include <Windows.h>
#include <string>
#include <TlHelp32.h>

class Process
{
public:
	std::string ExePath();
	DWORD GetProcessID(const char* processName);
	bool is_process_running(const char* name);
	bool Attach(const char* exeName, bool waitForProcess);
	uint32_t get_aow_pid(const char* processName);
	uint32_t get_process_thread_num_by_pid(uint32_t process_id);

	HANDLE hProcess;
	DWORD dwProcessId;
};

extern Process* g_pProcess;



