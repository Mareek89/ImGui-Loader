#pragma once

#pragma comment( lib, "Wtsapi32" )
#include <wtsapi32.h>
#include <thread>
#include <winnt.h>
#include "syscall.h"
#include "native.h"
extern "C" void crash_asm();

namespace security {

	static BOOL Is_RegKeyValueExists(HKEY hKey, const TCHAR* lpSubKey, const TCHAR* lpValueName, const TCHAR* search_str)
	{
		HKEY hkResult = NULL;
		TCHAR lpData[1024] = { 0 };
		DWORD cbData = MAX_PATH;

		if (RegOpenKeyEx(hKey, lpSubKey, NULL, KEY_READ, &hkResult) == ERROR_SUCCESS)
		{
			if (RegQueryValueEx(hkResult, lpValueName, NULL, NULL, (LPBYTE)lpData, &cbData) == ERROR_SUCCESS)
			{
				if (strstr((PCTSTR)lpData, search_str) != NULL)
				{
					RegCloseKey(hkResult);
					return TRUE;
				}
			}
			RegCloseKey(hkResult);
		}
		return FALSE;

	}

	static BOOL Is_RegKeyExists(HKEY hKey, const TCHAR* lpSubKey)
	{
		HKEY hkResult = NULL;
		TCHAR lpData[1024] = { 0 };
		DWORD cbData = MAX_PATH;

		if (RegOpenKeyEx(hKey, lpSubKey, NULL, KEY_READ, &hkResult) == ERROR_SUCCESS)
		{
			RegCloseKey(hkResult);
			return TRUE;
		}

		return FALSE;
	}

	static bool get_process_debug_port()
	{
		uint64_t remote_debug = 0;

		auto NtQueryInfoProcess = g_syscalls.get<native::NtQueryInformationProcess>(xorstr_("NtQueryInformationProcess"));
		if (NtQueryInfoProcess == nullptr)
		{
			return false;
		}

		auto status = NtQueryInfoProcess(GetCurrentProcess(), native::ProcessDebugPort, &remote_debug, sizeof(remote_debug), NULL);
		if (!NT_SUCCESS(status) && remote_debug != 0)
		{
			return true;
		}

		return false;
	}

	static bool get_process_debug_flags()
	{
		uint32_t debug_inherit = 0;

		auto NtQueryInfoProcess = g_syscalls.get<native::NtQueryInformationProcess>(xorstr_("NtQueryInformationProcess"));
		if (NtQueryInfoProcess == nullptr)
		{
			return false;
		}

		auto status = NtQueryInfoProcess(GetCurrentProcess(), native::ProcessDebugFlags, &debug_inherit, sizeof(DWORD), NULL);
		if (!NT_SUCCESS(status) && debug_inherit == 0)
		{
			return true;
		}

		return false;
	}

	static bool hide_thread_from_debugger(HANDLE thread)
	{
		const auto thread_hide_from_debugger = 0x11;

		auto NtSetInformationThread = g_syscalls.get<native::NtSetInformationThread>(xorstr_("NtSetInformationThread"));
		if (NtSetInformationThread == nullptr)
		{
			return false;
		}

		auto status = NtSetInformationThread(thread, thread_hide_from_debugger, nullptr, 0);
		if (!NT_SUCCESS(status))
		{
			return false;
		}

		return true;
	}

	//static void size_of_image()
	//{
	//	auto pPeb = (PPEB)__readgsqword(0x60);
	//	if (pPeb == nullptr)
	//		return;

	//	//printf(xorstr_("[+] Increasing SizeOfImage in PE Header to: 0x100000 \n"));

	//	// The following pointer hackery is because winternl.h defines incomplete PEB types
	//	PLIST_ENTRY InLoadOrderModuleList = (PLIST_ENTRY)pPeb->Ldr->Reserved2[1]; // pPeb->Ldr->InLoadOrderModuleList
	//	PLDR_DATA_TABLE_ENTRY tableEntry = CONTAINING_RECORD(InLoadOrderModuleList, LDR_DATA_TABLE_ENTRY, Reserved1[0] /*InLoadOrderLinks*/);
	//	PULONG pEntrySizeOfImage = (PULONG)&tableEntry->Reserved3[1]; // &tableEntry->SizeOfImage
	//	*pEntrySizeOfImage = (ULONG)((INT_PTR)tableEntry->DllBase + 0x100000);
	//}

	//static void erase_pe_header_from_memory()
	//{
	//	//printf(xorstr_("[+] Erasing PE header from memory \n"));
	//	DWORD OldProtect = 0;

	//	// Get base address of module
	//	char* pBaseAddr = (char*)GetModuleHandle(NULL);

	//	// Change memory protection
	//	VirtualProtect(pBaseAddr, 4096, // Assume x86 page size
	//		PAGE_READWRITE, &OldProtect);

	//	// Erase the header
	//	SecureZeroMemory(pBaseAddr, 4096);
	//}

	static void virtual_pc_reg_keys()
	{
		/* Array of strings of blacklisted registry keys */
		const TCHAR* szKeys[] = {
			xorstr_("SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters"),
		};

		WORD dwlength = sizeof(szKeys) / sizeof(szKeys[0]);

		/* Check one by one */
		for (int i = 0; i < dwlength; i++)
		{
			TCHAR msg[256] = "";
			sprintf_s(msg, sizeof(msg) / sizeof(TCHAR), xorstr_("Checking reg key %s "), szKeys[i]);
			if (Is_RegKeyExists(HKEY_LOCAL_MACHINE, szKeys[i]))
			{
				//printf(xorstr_("[+] Virtual PC detected! \n"));
				crash_asm();
			}
		}
	}

	static void vbox_reg_key_value()
	{
		/* Array of strings of blacklisted registry key values */
		const TCHAR* szEntries[][3] = {
			{ xorstr_("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), xorstr_("Identifier"), xorstr_("VBOX") },
			{ xorstr_("HARDWARE\\Description\\System"), xorstr_("SystemBiosVersion"), xorstr_("VBOX") },
			{ xorstr_("HARDWARE\\Description\\System"), xorstr_("VideoBiosVersion"), xorstr_("VIRTUALBOX") },
			{ xorstr_("HARDWARE\\Description\\System"), xorstr_("SystemBiosDate"), xorstr_("06/23/99") },
		};

		WORD dwLength = sizeof(szEntries) / sizeof(szEntries[0]);

		for (int i = 0; i < dwLength; i++)
		{
			TCHAR msg[256] = "";
			sprintf_s(msg, sizeof(msg) / sizeof(TCHAR), xorstr_("Checking reg key HARDWARE\\Description\\System - %s is set to %s"), szEntries[i][1], szEntries[i][2]);
			if (Is_RegKeyValueExists(HKEY_LOCAL_MACHINE, szEntries[i][0], szEntries[i][1], szEntries[i][2]))
			{
				//printf(xorstr_("[+] Virtual Box detected! \n"));
				crash_asm();
			}
		}
	}

	static void vmware_reg_key_value()
	{
		/* Array of strings of blacklisted registry key values */
		const TCHAR* szEntries[][3] = {
			{ xorstr_("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), xorstr_("Identifier"), xorstr_("VMWARE") },
			{ xorstr_("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), xorstr_("Identifier"), xorstr_("VMWARE") },
			{ xorstr_("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"), xorstr_("Identifier"), xorstr_("VMWARE") },
			{ xorstr_("SYSTEM\\ControlSet001\\Control\\SystemInformation"), xorstr_("SystemManufacturer"), xorstr_("VMWARE") },
			{ xorstr_("SYSTEM\\ControlSet001\\Control\\SystemInformation"), xorstr_("SystemProductName"), xorstr_("VMWARE") },
		};

		WORD dwLength = sizeof(szEntries) / sizeof(szEntries[0]);

		for (int i = 0; i < dwLength; i++)
		{
			TCHAR msg[256] = "";
			sprintf_s(msg, sizeof(msg) / sizeof(TCHAR), xorstr_("Checking reg key %s"), szEntries[i][0]);
			if (Is_RegKeyValueExists(HKEY_LOCAL_MACHINE, szEntries[i][0], szEntries[i][1], szEntries[i][2]))
			{
				//printf(xorstr_("[+] VMWare detected! \n"));
				crash_asm();
			}
		}
	}

	static bool is_debugger_present()
		/*++
		Routine Description:
			Calls the IsDebuggerPresent() API. This function is part of the
			Win32 Debugging API and it returns TRUE if a user mode debugger
			is present. Internally, it simply returns the value of the
			PEB->BeingDebugged flag.
		Arguments:
			None
		Return Value:
			TRUE - if debugger was detected
			FALSE - otherwise
		--*/
	{
		if (IsDebuggerPresent() == 1)
		{
			//printf(xorstr_("[+] Debugger detected! \n"));
			crash_asm();
		}

		return false;
	}

	static bool check_remote_debugger_present()
		/*++
		Routine Description:
			CheckRemoteDebuggerPresent() is another Win32 Debugging API function;
			it can be used to check if a remote process is being debugged. However,
			we can also use this as another method for checking if our own process
			is being debugged. This API internally calls the NTDLL export
			NtQueryInformationProcess function with the SYSTEM_INFORMATION_CLASS
			set to 7 (ProcessDebugPort).
		Arguments:
			None
		Return Value:
			TRUE - if debugger was detected
			FALSE - otherwise
		--*/
	{
		auto debugger_present = 0;
		CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugger_present);

		if (debugger_present == 1)
		{
			//printf(xorstr_("[+] Debugger detected! \n"));
			crash_asm();
		}

		return false;
	}

	static bool is_being_debugged()
		/*++
		Routine Description:
			Checks if the BeingDebugged flag is set in the Process Environment Block (PEB).
			This is effectively the same code that IsDebuggerPresent() executes internally.
			The PEB pointer is fetched from DWORD FS:[0x30] on x86_32 and QWORD GS:[0x60] on x86_64.
		Arguments:
			None
		Return Value:
			TRUE - if debugger was detected
			FALSE - otherwise
		--*/
	{
		auto pPEB = (PPEB)__readgsqword(0x60);
		if (pPEB == nullptr)
			return false;

		if (pPEB->BeingDebugged == 1)
		{
			//printf(xorstr_("[+] Debugger detected! \n"));
			crash_asm();
		}

		return false;
	}

	static bool is_dll_blacklisted()
	{
		HMODULE h_module = nullptr;

		static std::list<std::string> dll_list =
		{
			xorstr_("avghookx.dll"),    // AVG
			xorstr_("avghooka.dll"),	// AVG
			xorstr_("snxhk.dll"),		// Avast
			xorstr_("sbiedll.dll"),		// Sandboxie
			xorstr_("dbghelp.dll"),		// WindBG
			xorstr_("api_log.dll"),		// iDefense Lab
			xorstr_("dir_watch.dll"),	// iDefense Lab
			xorstr_("pstorec.dll"),		// SunBelt Sandbox
			xorstr_("vmcheck.dll"),		// Virtual PC
			xorstr_("wpespy.dll"),		// WPE Pro
			xorstr_("cmdvrt64.dll"),	// Comodo Container
			xorstr_("cmdvrt32.dll"),	// Comodo Container
		};

		//printf("dll list size: %d \n", dll_list.size());
		for (int i = 0; i < dll_list.size(); i++)
		{
			for (auto& module_name : dll_list)
			{
				h_module = GetModuleHandleA(module_name.c_str());
				//printf("module name: %s \n", module_name.c_str());
				if (h_module == nullptr)
					continue;

				std::string dll_name = module_name.c_str();
				if (dll_name.find(module_name) != std::string::npos)
				{
					//printf(xorstr_("[+] blacklisted dll found! \n"));
					crash_asm();
				}
			}
		}

		return false;
	}

	static bool is_window_blacklisted()
	{
		static std::list<std::string> window_list =
		{ xorstr_("TFormMain.UnicodeClass"),
			xorstr_("TApplication"),
			xorstr_("Qt5QWindowIcon"),
			xorstr_("Qt5152QWindowIcon"),
			xorstr_("OLLYDBG"),
			xorstr_("TMainForm"),
			xorstr_("XTPMainFrame"),
			xorstr_("Afx:00400000:0"),
			xorstr_("UPP-CLASS-W"),
			xorstr_("dbgviewClass"),
			xorstr_("WinDbgFrameClass"),
			xorstr_("Window"),
			//xorstr_("#32770"),
			xorstr_("ATL:003DD3A8"),
			xorstr_("ATL:00007FF60F9566B0"),
			xorstr_("ATL:0084E148"),
			xorstr_("ATL:00007FF79431F240"),
			xorstr_("PROCMON_WINDOW_CLASS"),
			xorstr_("PROCEXPLORER"),
			xorstr_("ID"),
			xorstr_("ThunderRT6FormDC"),
			xorstr_("ThunderRT6Main"),
			xorstr_("WindowsForms10.Window.8.app.0.13965fa_r6_ad1"),
			xorstr_("WindowsForms10.Window.8.app.0.141b42a_r6_ad1")

			//xorstr_("ConsoleWindowClass"),

		};

		for (HWND hwnd = GetTopWindow(NULL); hwnd != NULL; hwnd = GetNextWindow(hwnd, GW_HWNDNEXT))
		{
			if (!IsWindowVisible(hwnd))
				continue;

			int length = GetWindowTextLength(hwnd);
			if (length == 0)
				continue;

			/*char* title = new char[length + 1];
			GetWindowTextA(hwnd, title, length + 1);*/
			TCHAR class_name[MAX_PATH];
			GetClassNameA(hwnd, class_name, _countof(class_name));

			for (auto& name : window_list)
			{
				std::string window_name = class_name;
				if (window_name == name)
				{
					//printf(xorstr_("[+] Found window class name! \n"));
					crash_asm();
				}
			}

			//std::cout << "HWND: " << hwnd << " Title: " << className << std::endl;
		}

		return false;
	}

	static bool is_process_blacklisted()
	{
		static std::list<std::string> process_list =
		{
			xorstr_("ida"),
			xorstr_("ollydbg"),
			xorstr_("HxD"),
			xorstr_("ResourceHacker"),
			xorstr_("ProcessHacker"),
			xorstr_("httpdebugger"),
			xorstr_("windowrenamer"),
			xorstr_("CrySearch"),
			xorstr_("pe-sieve"),
			xorstr_("PowerTool"),
			xorstr_("windbg"),
			xorstr_("DebugView"),
			xorstr_("CheatEngine"),
			xorstr_("DbgView"),
			xorstr_("PETools"),
			xorstr_("LordPE"),
			xorstr_("tcpview"),
			xorstr_("autoruns"),
			xorstr_("autorunsc"),
			xorstr_("filemon"),
			xorstr_("procmon"),
			xorstr_("regmon"),
			xorstr_("procexp"),
			xorstr_("idaq"),
			xorstr_("idaq64"),
			xorstr_("ImmunityDebugger"),
			xorstr_("Wireshark"),
			xorstr_("dumpcap"),
			xorstr_("HookExplorer"),
			xorstr_("ImportREC"),
			xorstr_("SysInspector"),
			xorstr_("proc_analyzer"),
			xorstr_("sysAnalyzer"),
			xorstr_("sniff_hit"),
			xorstr_("joeboxcontrol"),
			xorstr_("joeboxserver"),
			xorstr_("x32dbg"),
			xorstr_("x64dbg"),
			xorstr_("Fiddler")
		};

		WTS_PROCESS_INFO* pWPIs = NULL;
		DWORD dwProcCount = 0;
		if (WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE, NULL, 1, &pWPIs, &dwProcCount))
		{
			//Go through all processes retrieved
			for (DWORD i = 0; i < dwProcCount; i++)
			{
				std::string proc_name = pWPIs[i].pProcessName;
				//printf(("process list: %s \n"), proc_name.c_str());

				for (auto& name : process_list)
				{
					if (proc_name.find(name) != std::string::npos)
					{
						//printf(xorstr_("[+] unauthorized program opened! \n"));
						crash_asm();
					}
				}
			}
		}

		return false;
	}

	static void init_security() {
		//Driver doesn`t load correctly if the nether functions gets initialized
		//security::erase_pe_header_from_memory();
		//security::size_of_image();

		while (true) {
			security::vbox_reg_key_value();
			security::vmware_reg_key_value();
			security::virtual_pc_reg_keys();

			if (security::get_process_debug_flags()
				|| security::get_process_debug_port()
				|| security::check_remote_debugger_present()
				|| security::is_debugger_present()
				|| security::is_being_debugged()
				|| security::is_process_blacklisted()
				|| security::is_window_blacklisted()
				|| security::is_dll_blacklisted())

				std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	}
}

