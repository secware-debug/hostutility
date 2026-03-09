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

#define DEF_KBD INTERCEPTION_KEYBOARD(0)
#define DEF_MOU INTERCEPTION_MOUSE(0)

#ifndef MAPVK_VK_TO_VSC_EX
#define MAPVK_VK_TO_VSC_EX 4
#endif

static InterceptionContext g_ctx = NULL;

static unsigned short vk_to_scan(unsigned char vk, int* out_extended) {
    UINT sc = MapVirtualKeyExA(vk, MAPVK_VK_TO_VSC_EX, NULL);
    *out_extended = (sc >> 8) & 0x01;
    return (unsigned short)(sc & 0xFF);
}

int remote_input_interception_init(void) {
    if (g_ctx) return 1;
    g_ctx = interception_create_context();
    if (!g_ctx) {
        remote_log("[interception] init failed (driver not installed?)");
        return 0;
    }
    remote_log("[interception] init OK");
    return 1;
}

void remote_input_interception_shutdown(void) {
    if (g_ctx) {
        interception_destroy_context(g_ctx);
        g_ctx = NULL;
    }
}

int remote_input_interception_is_ready(void) {
    return g_ctx != NULL;
}

void remote_input_interception_mouse_move(int px, int py) {
    if (!g_ctx) return;
    int w = GetSystemMetrics(SM_CXVIRTUALSCREEN);
    int h = GetSystemMetrics(SM_CYVIRTUALSCREEN);
    int x0 = GetSystemMetrics(SM_XVIRTUALSCREEN);
    int y0 = GetSystemMetrics(SM_YVIRTUALSCREEN);
    if (w <= 0) w = GetSystemMetrics(SM_CXSCREEN);
    if (h <= 0) h = GetSystemMetrics(SM_CYSCREEN);
    if (w <= 0) w = 1;
    if (h <= 0) h = 1;
    int nx = (int)((unsigned long long)(px - x0) * 65535 / (unsigned)w);
    int ny = (int)((unsigned long long)(py - y0) * 65535 / (unsigned)h);
    if (nx < 0) nx = 0;
    if (nx > 65535) nx = 65535;
    if (ny < 0) ny = 0;
    if (ny > 65535) ny = 65535;

    InterceptionMouseStroke ms = { 0 };
    ms.state = 0;
    ms.flags = INTERCEPTION_MOUSE_MOVE_ABSOLUTE | INTERCEPTION_MOUSE_VIRTUAL_DESKTOP;
    ms.rolling = 0;
    ms.x = nx;
    ms.y = ny;
    ms.information = 0;
    interception_send(g_ctx, DEF_MOU, (const InterceptionStroke*)&ms, 1);
}

void remote_input_interception_mouse_button(int button, int down) {
    if (!g_ctx) return;
    unsigned short state = 0;
    if (button == 0) state = down ? INTERCEPTION_MOUSE_LEFT_BUTTON_DOWN : INTERCEPTION_MOUSE_LEFT_BUTTON_UP;
    else if (button == 1) state = down ? INTERCEPTION_MOUSE_RIGHT_BUTTON_DOWN : INTERCEPTION_MOUSE_RIGHT_BUTTON_UP;
    else if (button == 2) state = down ? INTERCEPTION_MOUSE_MIDDLE_BUTTON_DOWN : INTERCEPTION_MOUSE_MIDDLE_BUTTON_UP;
    else return;

    InterceptionMouseStroke ms = { 0 };
    ms.state = state;
    ms.flags = INTERCEPTION_MOUSE_MOVE_RELATIVE;
    ms.rolling = 0;
    ms.x = 0;
    ms.y = 0;
    ms.information = 0;
    interception_send(g_ctx, DEF_MOU, (const InterceptionStroke*)&ms, 1);
}

void remote_input_interception_mouse_wheel(int delta) {
    if (!g_ctx) return;
    InterceptionMouseStroke ms = { 0 };
    ms.state = INTERCEPTION_MOUSE_WHEEL;
    ms.flags = INTERCEPTION_MOUSE_MOVE_RELATIVE;
    ms.rolling = (short)delta;
    ms.x = 0;
    ms.y = 0;
    ms.information = 0;
    interception_send(g_ctx, DEF_MOU, (const InterceptionStroke*)&ms, 1);
}

void remote_input_interception_key(unsigned char vk, int key_down) {
    if (!g_ctx) return;
    //remote_log("[interception] key vk=0x%02X (%u) %s", (unsigned)vk, (unsigned)vk, key_down ? "down" : "up");
    int extended = 0;
    unsigned short sc = vk_to_scan(vk, &extended);

    InterceptionKeyStroke ks = { 0 };
    ks.code = sc;
    ks.state = key_down ? INTERCEPTION_KEY_DOWN : INTERCEPTION_KEY_UP;
    if (extended) ks.state |= INTERCEPTION_KEY_E0;
    ks.information = 0;
    interception_send(g_ctx, DEF_KBD, (const InterceptionStroke*)&ks, 1);
}
