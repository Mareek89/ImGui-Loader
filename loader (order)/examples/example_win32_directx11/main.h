#pragma once

#include <dwmapi.h>
#include <Windows.h>
#include <string>
#include <D3DX11tex.h>
#pragma comment(lib, "D3DX11.lib")

// IMGUI
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"


#include "driver comm/alpc.h"
#include "colors.h"
#include "logo.h"
#include "poppins.h"
#include "ico_font.h"
#include "roboto.h"

// PICTURE GAME

#include "fortnite_pic.h"
#include "escape_from_pic.h"
#include "apex_pic.h"
#include "valorant_pic.h"
#include "pubg_pic.h"
#include "spoofer.h"

#include "user_circle.h"

// SUPPORT

#include "discord_pic.h"
#include "inject_pic.h"
#include <imgui_internal.h>

#include "xorstr.h"

static ID3D11Device* g_pd3dDevice = NULL;
static ID3D11DeviceContext* g_pd3dDeviceContext = NULL;
static IDXGISwapChain* g_pSwapChain = NULL;
static ID3D11RenderTargetView* g_mainRenderTargetView = NULL;

using namespace std;

#define WIDTH  690 // Loader Size X
#define HEIGHT 480 // Loader Size Y

bool CreateDeviceD3D(HWND hWnd);
void CleanupDeviceD3D();
void CreateRenderTarget();
void CleanupRenderTarget();
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

D3DX11_IMAGE_LOAD_INFO info0; ID3DX11ThreadPump* pump0{ nullptr };
ID3D11ShaderResourceView* lg = nullptr;

// GAME PIC INICIAL

ID3D11ShaderResourceView* fn = nullptr;
ID3D11ShaderResourceView* pbg = nullptr;
ID3D11ShaderResourceView* eft = nullptr;
ID3D11ShaderResourceView* ax = nullptr;
ID3D11ShaderResourceView* vl = nullptr;


ID3D11ShaderResourceView* uc = nullptr;

ID3D11ShaderResourceView* ds = nullptr;
ID3D11ShaderResourceView* ij = nullptr;
HWND hwnd;
RECT rc;

ImFont* ico;
ImFont* time_font;
ImFont* rob;
ImFont* minimal_text;

std::string s_second, s_minute, s_hour, s_day, s_month;
std::string hwnd_time;

int tabs = 0, sub_tabs = 0, panel_tabs = 0, status_tabs = 0;

int active_logintab = 0;
float logintab_alpha = 0.f, logintab_add;


int active_tab = 0;
float tab_alpha = 0.f, tab_add;

int active_subtab = 0;
float subtab_alpha = 0.f, subtab_add;

int active_statustab = 0;
float statustab_alpha = 0.f, statustab_add;

bool product = false, login_panel = true;

float timer_inject = 0.f;

void RenderBlur(HWND hwnd)
{
    struct ACCENTPOLICY
    {
        int na;
        int nf;
        int nc;
        int nA;
    };
    struct WINCOMPATTRDATA
    {
        int na;
        PVOID pd;
        ULONG ul;
    };

    const HINSTANCE hm = LoadLibrary(xorstr_("user32.dll"));
    if (hm)
    {
        typedef BOOL(WINAPI* pSetWindowCompositionAttribute)(HWND, WINCOMPATTRDATA*);

        const pSetWindowCompositionAttribute SetWindowCompositionAttribute = (pSetWindowCompositionAttribute)GetProcAddress(hm, xorstr_("SetWindowCompositionAttribute"));
        if (SetWindowCompositionAttribute)
        {
            ACCENTPOLICY policy = { 3, 0, 0, 0 };

            WINCOMPATTRDATA data = { 19, &policy,sizeof(ACCENTPOLICY) };
            SetWindowCompositionAttribute(hwnd, &data);
        }
        FreeLibrary(hm);
    }
}

void DrawTextCentered(const char* text)
{
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetColorU32(c::text_world));
    ImGui::SetCursorPos(ImVec2((ImGui::GetWindowWidth() - ImGui::CalcTextSize(text).x) / 2.f + 120.f / 2, (ImGui::GetWindowHeight() - ImGui::CalcTextSize(text).y) / 2.f));
    ImGui::Text(text);
    ImGui::PopStyleColor();
}

void DrawTextCenteredX(const char* text, float y)
{
    ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetColorU32(c::text_world));
    ImGui::SetCursorPosY(y);
    ImGui::SetCursorPosX((ImGui::GetWindowWidth() - ImGui::CalcTextSize(text).x) / 2.f + 120 / 2);
    ImGui::Text(text);
    ImGui::PopStyleColor();
}

void AlignForWidth(float width, float y = 0.f, float alignment = 0.5f) // Center widgets :)
{
    ImGuiStyle& style = ImGui::GetStyle();
    float avail = ImGui::GetContentRegionAvail().x;
    float off = (avail - width) * alignment;
    if (off > 0.0f)
        ImGui::SetCursorPosY(y);
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + off + 120 / 2);
}

void move_window() {

    GetWindowRect(hwnd, &rc);

    if (ImGui::GetWindowPos().x != 0 || ImGui::GetWindowPos().y != 0)
    {
        MoveWindow(hwnd, rc.left + ImGui::GetWindowPos().x, rc.top + ImGui::GetWindowPos().y, WIDTH, HEIGHT, TRUE);
        ImGui::SetWindowPos(ImVec2(0.f, 0.f));
    }

}

namespace ImGui {

    bool BufferingBar(const char* label, float value, const ImVec2& size_arg, const ImU32& bg_col, const ImU32& fg_col) {
        ImGuiWindow* window = GetCurrentWindow();
        if (window->SkipItems)
            return false;

        ImGuiContext& g = *GImGui;
        const ImGuiStyle& style = g.Style;
        const ImGuiID id = window->GetID(label);

        ImVec2 pos = window->DC.CursorPos;
        ImVec2 size = size_arg;
        size.x -= style.FramePadding.x * 2;

        const ImRect bb(pos, ImVec2(pos.x + size.x, pos.y + size.y));
        ItemSize(bb, style.FramePadding.y);
        if (!ItemAdd(bb, id))
            return false;

        // Render
        const float circleStart = size.x * 0.7f;
        const float circleEnd = size.x;
        const float circleWidth = circleEnd - circleStart;

        window->DrawList->AddRectFilled(bb.Min, ImVec2(pos.x + circleStart, bb.Max.y), bg_col);
        window->DrawList->AddRectFilled(bb.Min, ImVec2(pos.x + circleStart * value, bb.Max.y), fg_col);

        const float t = g.Time;
        const float r = size.y / 2;
        const float speed = 1.5f;

        const float a = speed * 0;
        const float b = speed * 0.333f;
        const float c = speed * 0.666f;

        const float o1 = (circleWidth + r) * (t + a - speed * (int)((t + a) / speed)) / speed;
        const float o2 = (circleWidth + r) * (t + b - speed * (int)((t + b) / speed)) / speed;
        const float o3 = (circleWidth + r) * (t + c - speed * (int)((t + c) / speed)) / speed;

        window->DrawList->AddCircleFilled(ImVec2(pos.x + circleEnd - o1, bb.Min.y + r), r, bg_col);
        window->DrawList->AddCircleFilled(ImVec2(pos.x + circleEnd - o2, bb.Min.y + r), r, bg_col);
        window->DrawList->AddCircleFilled(ImVec2(pos.x + circleEnd - o3, bb.Min.y + r), r, bg_col);
    }

    bool Spinner(const char* label, float radius, int thickness, const ImU32& color) {
        ImGuiWindow* window = GetCurrentWindow();
        if (window->SkipItems)
            return false;

        ImGuiContext& g = *GImGui;
        const ImGuiStyle& style = g.Style;
        const ImGuiID id = window->GetID(label);

        ImVec2 pos = window->DC.CursorPos;
        ImVec2 size((radius) * 2, (radius + style.FramePadding.y) * 2);

        const ImRect bb(pos, ImVec2(pos.x + size.x, pos.y + size.y));
        ItemSize(bb, style.FramePadding.y);
        if (!ItemAdd(bb, id))
            return false;

        // Render
        window->DrawList->PathClear();

        int num_segments = 30;
        int start = abs(ImSin(g.Time * 1.8f) * (num_segments - 5));

        const float a_min = IM_PI * 2.0f * ((float)start) / (float)num_segments;
        const float a_max = IM_PI * 2.0f * ((float)num_segments - 3) / (float)num_segments;

        const ImVec2 centre = ImVec2(pos.x + radius, pos.y + radius + style.FramePadding.y);

        for (int i = 0; i < num_segments; i++) {
            const float a = a_min + ((float)i / (float)num_segments) * (a_max - a_min);
            window->DrawList->PathLineTo(ImVec2(centre.x + ImCos(a + g.Time * 8) * radius,
                centre.y + ImSin(a + g.Time * 8) * radius));
        }

        window->DrawList->PathStroke(color, false, thickness);
    }
}