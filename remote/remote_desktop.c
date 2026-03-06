/**
 * remote_desktop.c
 * Capture screen and encode as full-frame JPEG. Uses libjpeg-turbo when available, else stb.
 */
#include "pch.h"
#include "remote_desktop.h"
#include "remote_log.h"
#include "stb_image_write.h"
#include <stdlib.h>
#include <string.h>
#ifdef REMOTE_USE_TURBOJPEG
#include <turbojpeg.h>
#pragma comment(lib, "turbojpeg.lib")
#endif

#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "user32.lib")

#define REMOTE_DESKTOP_MAX_WIDTH  1920
#define REMOTE_DESKTOP_MAX_HEIGHT 1080
#define MAX_MONITORS 16

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

typedef struct { unsigned char* buf; unsigned int used; unsigned int cap; } jpeg_ctx_t;
static void jpeg_write_cb(void* ctx, void* data, int size) {
    jpeg_ctx_t* j = (jpeg_ctx_t*)ctx;
    if (!j || size <= 0) return;
    while (j->used + (unsigned int)size > j->cap) {
        unsigned int new_cap = j->cap ? j->cap * 2 : 65536;
        if (new_cap < j->used + (unsigned int)size) new_cap = j->used + (unsigned int)size;
        unsigned char* p = !j->buf ? (unsigned char*)HeapAlloc(GetProcessHeap(), 0, new_cap)
            : (unsigned char*)HeapReAlloc(GetProcessHeap(), 0, j->buf, new_cap);
        if (!p) return;
        j->buf = p; j->cap = new_cap;
    }
    memcpy(j->buf + j->used, data, (size_t)size);
    j->used += (unsigned int)size;
}

/* Capture and encode as full-frame JPEG. 4-byte LE length + JPEG bytes. */
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
    bi.biHeight = (LONG)out_height;
    bi.biPlanes = 1;
    bi.biBitCount = 32;
    bi.biCompression = BI_RGB;
    unsigned int row_bytes = ((out_width * 4 + 3) & ~3u);
    unsigned int bgra_size = row_bytes * out_height;
    unsigned char* bgra = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, bgra_size);
    if (!bgra) {
        DeleteObject(hBmp); DeleteDC(hMemDC); ReleaseDC(NULL, hScreen);
        return NULL;
    }
    GetDIBits(hMemDC, hBmp, 0, (UINT)out_height, bgra, (BITMAPINFO*)&bi, DIB_RGB_COLORS);
    DeleteObject(hBmp); DeleteDC(hMemDC); ReleaseDC(NULL, hScreen);

    /* BGRA bottom-up -> RGB top-down */
    unsigned int pixels = out_width * out_height;
    unsigned char* rgb = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, pixels * 3);
    if (!rgb) { HeapFree(GetProcessHeap(), 0, bgra); return NULL; }
    { unsigned int x, y;
      for (y = 0; y < out_height; y++) {
        unsigned int src_y = out_height - 1 - y;
        for (x = 0; x < out_width; x++) {
            unsigned int so = src_y * row_bytes + x * 4;
            unsigned int do_ = (y * out_width + x) * 3;
            rgb[do_ + 0] = bgra[so + 2];
            rgb[do_ + 1] = bgra[so + 1];
            rgb[do_ + 2] = bgra[so + 0];
        }
      }
    }
    HeapFree(GetProcessHeap(), 0, bgra);

    unsigned int jlen = 0;
#ifdef REMOTE_USE_TURBOJPEG
    {
        tjhandle tj = tjInitCompress();
        unsigned long ulen = 0;
        unsigned char* jpeg = NULL;
        if (tj && tjCompress2(tj, rgb, (int)out_width, (int)(out_width * 3), (int)out_height, TJPF_RGB, &jpeg, &ulen, TJSAMP_420, quality, TJFLAG_FASTDCT) == 0 && jpeg && ulen > 0) {
            jlen = (unsigned int)ulen;
            unsigned int total = 4 + jlen;
            unsigned char* buf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, total);
            if (buf) {
                buf[0] = (unsigned char)(jlen);
                buf[1] = (unsigned char)(jlen >> 8);
                buf[2] = (unsigned char)(jlen >> 16);
                buf[3] = (unsigned char)(jlen >> 24);
                memcpy(buf + 4, jpeg, jlen);
                tjFree(jpeg);
                if (tj) tjDestroy(tj);
                HeapFree(GetProcessHeap(), 0, rgb);
                *out_len = total;
                if (out_w) *out_w = (int)out_width;
                if (out_h) *out_h = (int)out_height;
                return buf;
            }
            tjFree(jpeg);
        }
        if (jpeg) tjFree(jpeg);
        if (tj) tjDestroy(tj);
    }
#endif
    /* Fallback: stb_image_write */
    jpeg_ctx_t jctx = { 0 };
    stbi_flip_vertically_on_write(0);
    if (!stbi_write_jpg_to_func(jpeg_write_cb, &jctx, (int)out_width, (int)out_height, 3, rgb, quality)) {
        HeapFree(GetProcessHeap(), 0, rgb);
        return NULL;
    }
    HeapFree(GetProcessHeap(), 0, rgb);
    if (!jctx.buf || jctx.used == 0) {
        if (jctx.buf) HeapFree(GetProcessHeap(), 0, jctx.buf);
        return NULL;
    }
    jlen = jctx.used;
    unsigned int total = 4 + jlen;
    unsigned char* buf = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, total);
    if (!buf) { HeapFree(GetProcessHeap(), 0, jctx.buf); return NULL; }
    buf[0] = (unsigned char)(jlen);
    buf[1] = (unsigned char)(jlen >> 8);
    buf[2] = (unsigned char)(jlen >> 16);
    buf[3] = (unsigned char)(jlen >> 24);
    memcpy(buf + 4, jctx.buf, jlen);
    HeapFree(GetProcessHeap(), 0, jctx.buf);
    *out_len = total;
    if (out_w) *out_w = (int)out_width;
    if (out_h) *out_h = (int)out_height;
    return buf;
}
