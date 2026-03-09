/**
 * remote_desktop.c
 * Delta encoding matching UnsafeStreamCodec (first frame full JPEG, later = changed rects).
 * Uses GDI+ JPEG encoding - same output as C# JpgCompression for server DecodeData compatibility.
 * Format: 4-byte LE total + full JPEG or [X Y W H len][JPEG]...
 */
#include "pch.h"
#include "remote_desktop.h"
#include "remote_log.h"
#include "gdiplus_jpeg.h"
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

#define REMOTE_DESKTOP_MAX_WIDTH  1920
#define REMOTE_DESKTOP_MAX_HEIGHT 1080
#define MAX_MONITORS 16
#define CHECK_BLOCK_W  50
#define CHECK_BLOCK_H  1

typedef struct { unsigned int width; unsigned int height; int x; int y; } monitor_rect_t;
typedef struct { monitor_rect_t rect; HMONITOR hMon; int is_primary; } monitor_entry_t;
static monitor_entry_t g_monitors[MAX_MONITORS];
static int g_monitor_count = 0;

static BOOL CALLBACK enum_monitor_collect(HMONITOR hMon, HDC hdc, LPRECT r, LPARAM lp) {
    (void)hdc; (void)lp;
    if (g_monitor_count >= MAX_MONITORS || !r) return TRUE;
    g_monitors[g_monitor_count].rect.x = r->left;
    g_monitors[g_monitor_count].rect.y = r->top;
    g_monitors[g_monitor_count].rect.width = (unsigned int)(r->right - r->left);
    g_monitors[g_monitor_count].rect.height = (unsigned int)(r->bottom - r->top);
    g_monitors[g_monitor_count].hMon = hMon;
    g_monitors[g_monitor_count].is_primary = 0;
    g_monitor_count++;
    return TRUE;
}

static void ensure_monitors_sorted(void) {
    int i;
    MONITORINFO mi;
    if (g_monitor_count <= 0) return;
    mi.cbSize = sizeof(mi);
    for (i = 0; i < g_monitor_count; i++) {
        if (GetMonitorInfoW(g_monitors[i].hMon, &mi))
            g_monitors[i].is_primary = (mi.dwFlags & MONITORINFOF_PRIMARY) ? 1 : 0;
    }
    for (i = 1; i < g_monitor_count; i++) {
        if (g_monitors[i].is_primary) {
            monitor_entry_t tmp = g_monitors[0];
            g_monitors[0] = g_monitors[i];
            g_monitors[i] = tmp;
            break;
        }
    }
}

static void get_monitor_rect(int display_index, monitor_rect_t* out) {
    out->width = 0; out->height = 0; out->x = 0; out->y = 0;
    g_monitor_count = 0;
    EnumDisplayMonitors(NULL, NULL, enum_monitor_collect, 0);
    ensure_monitors_sorted();
    if (display_index < 0 || display_index >= g_monitor_count) display_index = 0;
    if (g_monitor_count > 0) *out = g_monitors[display_index].rect;
    if (out->width == 0 || out->height == 0) {
        out->width = (unsigned int)GetSystemMetrics(SM_CXSCREEN);
        out->height = (unsigned int)GetSystemMetrics(SM_CYSCREEN);
        out->x = 0; out->y = 0;
    }
}

void remote_desktop_get_monitor_bounds(int display_index, int* out_x, int* out_y, unsigned int* out_width, unsigned int* out_height) {
    monitor_rect_t r;
    if (!out_x || !out_y || !out_width || !out_height) return;
    get_monitor_rect(display_index, &r);
    *out_x = r.x;
    *out_y = r.y;
    *out_width = r.width;
    *out_height = r.height;
}

static void scale_to_max(unsigned int* w, unsigned int* h) {
    unsigned int width = *w, height = *h;
    if (width <= REMOTE_DESKTOP_MAX_WIDTH && height <= REMOTE_DESKTOP_MAX_HEIGHT) return;
    if (width > REMOTE_DESKTOP_MAX_WIDTH || height > REMOTE_DESKTOP_MAX_HEIGHT) {
        if (width * REMOTE_DESKTOP_MAX_HEIGHT > height * REMOTE_DESKTOP_MAX_WIDTH) {
            height = (unsigned int)((unsigned long)height * REMOTE_DESKTOP_MAX_WIDTH / width);
            width = REMOTE_DESKTOP_MAX_WIDTH;
        } else {
            width = (unsigned int)((unsigned long)width * REMOTE_DESKTOP_MAX_HEIGHT / height);
            height = REMOTE_DESKTOP_MAX_HEIGHT;
        }
    }
    if (width == 0) width = 1;
    if (height == 0) height = 1;
    *w = width; *h = height;
}

static unsigned char* g_prev_bgra = NULL;
static unsigned int g_prev_width = 0;
static unsigned int g_prev_height = 0;

void remote_desktop_reset(void) {
    if (g_prev_bgra) {
        HeapFree(GetProcessHeap(), 0, g_prev_bgra);
        g_prev_bgra = NULL;
    }
    g_prev_width = 0;
    g_prev_height = 0;
}

/* Put 4-byte LE value at out. */
static void put_u32(unsigned char* out, unsigned int v) {
    out[0] = (unsigned char)(v);
    out[1] = (unsigned char)(v >> 8);
    out[2] = (unsigned char)(v >> 16);
    out[3] = (unsigned char)(v >> 24);
}

unsigned char* remote_desktop_capture(int display_index, int quality, unsigned int* out_len, int* out_w, int* out_h) {
    monitor_rect_t rect;
    get_monitor_rect(display_index, &rect);
    if (rect.width == 0 || rect.height == 0) {
        rect.width = (unsigned int)GetSystemMetrics(SM_CXSCREEN);
        rect.height = (unsigned int)GetSystemMetrics(SM_CYSCREEN);
        rect.x = 0; rect.y = 0;
    }
    unsigned int out_width = rect.width, out_height = rect.height;
    scale_to_max(&out_width, &out_height);
    if (out_width > 4096 || out_height > 4096) return NULL;
    if (quality <= 0) quality = 75;
    if (quality > 100) quality = 100;

    HDC hScreen = GetDC(NULL);
    if (!hScreen) return NULL;
    HDC hMemDC = CreateCompatibleDC(hScreen);
    HBITMAP hBmp = CreateCompatibleBitmap(hScreen, (int)out_width, (int)out_height);
    if (!hMemDC || !hBmp) {
        if (hBmp) DeleteObject(hBmp);
        if (hMemDC) DeleteDC(hMemDC);
        ReleaseDC(NULL, hScreen);
        return NULL;
    }
    SelectObject(hMemDC, hBmp);
    SetStretchBltMode(hMemDC, HALFTONE);
    StretchBlt(hMemDC, 0, 0, (int)out_width, (int)out_height, hScreen, rect.x, rect.y, (int)rect.width, (int)rect.height, SRCCOPY);

    BITMAPINFOHEADER bi = { 0 };
    bi.biSize = sizeof(BITMAPINFOHEADER);
    bi.biWidth = (LONG)out_width;
    bi.biHeight = -(LONG)out_height;  /* Negative = top-down, matches C# and GDI+ */
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    unsigned int stride = ((out_width * 4 + 3) & ~3u);
    unsigned char* bgra = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, stride * out_height);
    if (!bgra) {
        DeleteObject(hBmp); DeleteDC(hMemDC); ReleaseDC(NULL, hScreen);
        return NULL;
    }
    GetDIBits(hMemDC, hBmp, 0, (UINT)out_height, bgra, (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    DeleteObject(hBmp); DeleteDC(hMemDC); ReleaseDC(NULL, hScreen);

    int width_i = (int)out_width;
    int height_i = (int)out_height;
    unsigned char* buf = NULL;
    unsigned int total = 0;

    /* Send full JPEG every frame; server uses direct decode. DecodeData fails for C client. */
    {
        unsigned char* jpeg = NULL;
        unsigned int jlen = 0;
        if (!gdiplus_jpeg_encode_bgra(width_i, height_i, (int)stride, bgra, quality, &jpeg, &jlen) || !jpeg) {
            HeapFree(GetProcessHeap(), 0, bgra);
            return NULL;
        }
        HeapFree(GetProcessHeap(), 0, bgra);

        total = 4 + jlen;
        buf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, total);
        if (!buf) { HeapFree(GetProcessHeap(), 0, jpeg); return NULL; }
        put_u32(buf, jlen);
        memcpy(buf + 4, jpeg, (size_t)jlen);
        HeapFree(GetProcessHeap(), 0, jpeg);
    }

    *out_len = total;
    if (out_w) *out_w = (int)out_width;
    if (out_h) *out_h = (int)out_height;
    return buf;
}
