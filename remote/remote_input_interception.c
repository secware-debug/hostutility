/**
 * remote_input_interception.c
 * Thin wrapper over the Interception driver API for remote keyboard/mouse control.
 */
#include "pch.h"
#include "remote_input_interception.h"
#include "remote_log.h"
#include "interception/interception.h"
#include <stdlib.h>
#include <string.h>

#ifndef MAPVK_VK_TO_VSC_EX
#define MAPVK_VK_TO_VSC_EX 4
#endif

static InterceptionContext g_ctx = NULL;
static InterceptionDevice g_kbd_dev = 0;
static InterceptionDevice g_mou_dev = 0;

/* cppinterception-style capture: pick actual keyboard (<11) and mouse (>=11) devices by hardware ID.
 * If filters are NULL/empty, picks the first keyboard and first mouse discovered. */
static int capture_input_devices(const wchar_t* keyboard_filter, const wchar_t* mouse_filter) {
    wchar_t buffer[500];
    int mouse_found = 0;
    int kb_found = 0;
    InterceptionDevice curr_device = 1;

    g_kbd_dev = 0;
    g_mou_dev = 0;

    while (curr_device < 21) {
        unsigned int size = interception_get_hardware_id(g_ctx, curr_device, buffer, (unsigned int)sizeof(buffer));
        if (size == 0) {
            curr_device++;
            continue;
        }

        /* `size` is treated as wchar_t count (matches cppinterception usage). */
        buffer[(size < (unsigned int)(sizeof(buffer) / sizeof(buffer[0])) ? size : (unsigned int)(sizeof(buffer) / sizeof(buffer[0])) - 1)] = L'\0';

        if (curr_device < 11) {
            g_kbd_dev = curr_device;
            kb_found = 1;
            if (!keyboard_filter || keyboard_filter[0] == L'\0' || wcsstr(buffer, keyboard_filter) != NULL) {
                curr_device = 11;
            } else {
                curr_device++;
            }
            continue;
        }

        g_mou_dev = curr_device;
        mouse_found = 1;
        if (!mouse_filter || mouse_filter[0] == L'\0' || wcsstr(buffer, mouse_filter) != NULL) {
            break;
        }
        curr_device++;
    }

    remote_log("[interception] captured devices: kbd=%d mouse=%d", (int)g_kbd_dev, (int)g_mou_dev);
    return kb_found && mouse_found;
}

/* Last normalized absolute mouse position (0..65535) for button/wheel strokes.
 * Some Interception/driver setups ignore button/wheel strokes when x/y are zero
 * or when stroke flags don't match the device expectation. */
static int g_last_nx = 0;
static int g_last_ny = 0;
static int g_has_last_pos = 0;

/* Returns scan code in low byte.
 * The Interception C API expects extended markers in `information` as INTERCEPTION_KEY_E0/E1
 * (0x02/0x04). The upstream cppinterception wrapper treats any extended bit as E0. */
static unsigned short vk_to_scan(unsigned char vk, int* out_info) {
    UINT sc = MapVirtualKeyExA(vk, MAPVK_VK_TO_VSC_EX, NULL);
    unsigned int ext = (sc >> 8) & 0xFF;
    *out_info = (ext & 0xE0) ? INTERCEPTION_KEY_E0 : 0;
    return (unsigned short)(sc & 0xFF);
}

int remote_input_interception_init(void) {
    if (g_ctx) return 1;
    g_ctx = interception_create_context();
    if (!g_ctx) {
        remote_log("[interception] init failed (driver not installed?)");
        return 0;
    }
    if (!capture_input_devices(NULL, NULL)) {
        remote_log("[interception] capture_input_devices failed (no kb/mouse?)");
        interception_destroy_context(g_ctx);
        g_ctx = NULL;
        return 0;
    }
    remote_log("[interception] init OK (kbd=%d mouse=%d)", (int)g_kbd_dev, (int)g_mou_dev);
    return 1;
}

void remote_input_interception_shutdown(void) {
    if (g_ctx) {
        interception_destroy_context(g_ctx);
        g_ctx = NULL;
    }
    g_kbd_dev = 0;
    g_mou_dev = 0;
}

int remote_input_interception_is_ready(void) {
    return g_ctx != NULL && g_kbd_dev != 0 && g_mou_dev != 0;
}

void remote_input_interception_mouse_move(int px, int py, int virt_x, int virt_y, int virt_w, int virt_h) {
    if (!g_ctx || !g_mou_dev) return;
    int x0 = virt_x;
    int y0 = virt_y;
    int w = virt_w;
    int h = virt_h;
    if (w <= 0 || h <= 0) {
        w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        x0 = GetSystemMetrics(SM_XVIRTUALSCREEN);
        y0 = GetSystemMetrics(SM_YVIRTUALSCREEN);
        if (w <= 0) w = GetSystemMetrics(SM_CXSCREEN);
        if (h <= 0) h = GetSystemMetrics(SM_CYSCREEN);
    }
    if (w <= 0) w = 1;
    if (h <= 0) h = 1;
    int nx = (int)((unsigned long long)(px - x0) * 65535 / (unsigned)w);
    int ny = (int)((unsigned long long)(py - y0) * 65535 / (unsigned)h);
    if (nx < 0) nx = 0;
    if (nx > 65535) nx = 65535;
    if (ny < 0) ny = 0;
    if (ny > 65535) ny = 65535;

    g_last_nx = nx;
    g_last_ny = ny;
    g_has_last_pos = 1;

    InterceptionMouseStroke ms = { 0 };
    ms.state = 0;
    ms.flags = INTERCEPTION_MOUSE_MOVE_ABSOLUTE | INTERCEPTION_MOUSE_VIRTUAL_DESKTOP;
    ms.rolling = 0;
    ms.x = nx;
    ms.y = ny;
    ms.information = 0;
    interception_send(g_ctx, g_mou_dev, (const InterceptionStroke*)&ms, 1);
}

int remote_input_interception_mouse_button(int button, int down) {
    if (!g_ctx || !g_mou_dev) return 0;
    unsigned short state = 0;
    if (button == 0) state = down ? INTERCEPTION_MOUSE_LEFT_BUTTON_DOWN : INTERCEPTION_MOUSE_LEFT_BUTTON_UP;
    else if (button == 1) state = down ? INTERCEPTION_MOUSE_RIGHT_BUTTON_DOWN : INTERCEPTION_MOUSE_RIGHT_BUTTON_UP;
    else if (button == 2) state = down ? INTERCEPTION_MOUSE_MIDDLE_BUTTON_DOWN : INTERCEPTION_MOUSE_MIDDLE_BUTTON_UP;
    else return 0;

    InterceptionMouseStroke ms = { 0 };
    ms.state = state;
    // For button up/down strokes, Interception expects a pure button state (flags=0).
    ms.flags = 0;
    ms.rolling = 0;
    /* Keep x/y zero to match cppinterception behavior. */
    ms.x = 0;
    ms.y = 0;
    ms.information = 0;
    int sent = interception_send(g_ctx, g_mou_dev, (const InterceptionStroke*)&ms, 1);
    remote_log("[interception] mouse_button button=%d down=%d state=0x%X flags=0x%X x=%d y=%d sent=%d",
        button, down, (unsigned int)state, (unsigned int)ms.flags, ms.x, ms.y, sent);
    return sent;
}

int remote_input_interception_mouse_wheel(int delta) {
    if (!g_ctx || !g_mou_dev) return 0;
    InterceptionMouseStroke ms = { 0 };
    ms.state = INTERCEPTION_MOUSE_WHEEL;
    // Wheel strokes are not moves; keep flags clear.
    ms.flags = 0;
    /* Wheel delta: WHEEL_DELTA is 120 (0x78), negative is down. */
    ms.rolling = (short)delta;
    ms.x = 0;
    ms.y = 0;
    ms.information = 0;
    int sent = interception_send(g_ctx, g_mou_dev, (const InterceptionStroke*)&ms, 1);
    remote_log("[interception] mouse_wheel delta=%d state=0x%X flags=0x%X x=%d y=%d sent=%d",
        delta, (unsigned int)ms.state, (unsigned int)ms.flags, ms.x, ms.y, sent);
    return sent;
}

void remote_input_interception_key(unsigned char vk, int key_down) {
    if (!g_ctx || !g_kbd_dev) return;
    int info = 0;
    unsigned short sc = vk_to_scan(vk, &info);

    InterceptionKeyStroke ks = { 0 };
    ks.code = sc;
    ks.state = key_down ? INTERCEPTION_KEY_DOWN : INTERCEPTION_KEY_UP;
    ks.information = (unsigned int)info; /* E0/E1 in information field (matches cppinterception). */
    interception_send(g_ctx, g_kbd_dev, (const InterceptionStroke*)&ks, 1);
}
