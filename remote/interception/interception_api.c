/**
 * interception_api.c - Interception driver API implementation.
 * Ported from https://github.com/kennyhml/cppinterception (interception_c_api/interception.cpp).
 * Driver must be installed. Opens \\.\interception00 through \\.\interception19.
 */
#include "../pch.h"
#include "interception.h"
#include "../remote_log.h"
#include <stdio.h>
#include <string.h>

#ifndef CTL_CODE
#define FILE_DEVICE_UNKNOWN 0x00000022
#define METHOD_BUFFERED 0
#define FILE_ANY_ACCESS 0
#define CTL_CODE(DeviceType, Function, Method, Access) \
    (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

#define IOCTL_SET_PRECEDENCE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_PRECEDENCE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_FILTER     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_FILTER     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x808, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SET_EVENT      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x820, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_READ           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x840, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_GET_HARDWARE_ID CTL_CODE(FILE_DEVICE_UNKNOWN, 0x880, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _KEYBOARD_INPUT_DATA {
    unsigned short UnitId;
    unsigned short MakeCode;
    unsigned short Flags;
    unsigned short Reserved;
    unsigned long ExtraInformation;
} KEYBOARD_INPUT_DATA, *PKEYBOARD_INPUT_DATA;

typedef struct _MOUSE_INPUT_DATA {
    unsigned short UnitId;
    unsigned short Flags;
    unsigned short ButtonFlags;
    unsigned short ButtonData;
    unsigned long RawButtons;
    long LastX;
    long LastY;
    unsigned long ExtraInformation;
} MOUSE_INPUT_DATA, *PMOUSE_INPUT_DATA;

typedef struct {
    HANDLE handle;
    HANDLE unempty;
} device_entry_t;

static device_entry_t* to_devices(InterceptionContext ctx) { return (device_entry_t*)ctx; }

InterceptionContext interception_create_context(void) {
    char device_name[] = "\\\\.\\interception00";
    DWORD bytes_returned;
    int i;
    device_entry_t* arr;

    arr = (device_entry_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, INTERCEPTION_MAX_DEVICE * sizeof(device_entry_t));
    if (!arr) return NULL;

    for (i = 0; i < INTERCEPTION_MAX_DEVICE; i++) {
        HANDLE zero_padded[2] = { 0 };
        sprintf_s(&device_name[sizeof(device_name) - 3], 3, "%02d", i);

        /* Original oblitum driver uses GENERIC_READ only. Try READ|WRITE first; fallback to READ if Access Denied. */
        arr[i].handle = CreateFileA(device_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (arr[i].handle == INVALID_HANDLE_VALUE && GetLastError() == 5) {
            remote_log("[interception] CreateFile %s AccessDenied, retrying with GENERIC_READ only", device_name);
            arr[i].handle = CreateFileA(device_name, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        }
        if (arr[i].handle == INVALID_HANDLE_VALUE) {
            remote_log("[interception] CreateFile %s failed: err=%lu (2=NotFound 5=AccessDenied)", device_name, (unsigned long)GetLastError());
            interception_destroy_context(arr);
            return NULL;
        }

        arr[i].unempty = CreateEventA(NULL, TRUE, FALSE, NULL);
        if (!arr[i].unempty) {
            remote_log("[interception] CreateEvent failed: err=%lu", (unsigned long)GetLastError());
            interception_destroy_context(arr);
            return NULL;
        }

        zero_padded[0] = arr[i].unempty;
        if (!DeviceIoControl(arr[i].handle, IOCTL_SET_EVENT, zero_padded, sizeof(zero_padded), NULL, 0, &bytes_returned, NULL)) {
            remote_log("[interception] DeviceIoControl(IOCTL_SET_EVENT) %s failed: err=%lu", device_name, (unsigned long)GetLastError());
            interception_destroy_context(arr);
            return NULL;
        }
    }
    return arr;
}

void interception_destroy_context(InterceptionContext context) {
    device_entry_t* arr = to_devices(context);
    unsigned int i;
    if (!context) return;
    for (i = 0; i < INTERCEPTION_MAX_DEVICE; i++) {
        if (arr[i].handle != INVALID_HANDLE_VALUE)
            CloseHandle(arr[i].handle);
        if (arr[i].unempty)
            CloseHandle(arr[i].unempty);
    }
    HeapFree(GetProcessHeap(), 0, context);
}

int interception_send(InterceptionContext context, InterceptionDevice device, const InterceptionStroke* stroke, unsigned int nstroke) {
    device_entry_t* arr = to_devices(context);
    DWORD written = 0;

    if (!context || nstroke == 0 || interception_is_invalid(device) || !arr[device - 1].handle) return 0;

    if (interception_is_keyboard(device)) {
        PKEYBOARD_INPUT_DATA raw = (PKEYBOARD_INPUT_DATA)HeapAlloc(GetProcessHeap(), 0, nstroke * sizeof(KEYBOARD_INPUT_DATA));
        if (!raw) return 0;
        for (unsigned int i = 0; i < nstroke; i++) {
            const InterceptionKeyStroke* ks = (const InterceptionKeyStroke*)stroke;
            raw[i].UnitId = 0;
            raw[i].MakeCode = ks[i].code;
            raw[i].Flags = ks[i].state;
            raw[i].Reserved = 0;
            raw[i].ExtraInformation = ks[i].information;
        }
        DeviceIoControl(arr[device - 1].handle, IOCTL_WRITE, raw, (DWORD)(nstroke * sizeof(KEYBOARD_INPUT_DATA)), NULL, 0, &written, NULL);
        HeapFree(GetProcessHeap(), 0, raw);
        return (int)(written / sizeof(KEYBOARD_INPUT_DATA));
    } else {
        PMOUSE_INPUT_DATA raw = (PMOUSE_INPUT_DATA)HeapAlloc(GetProcessHeap(), 0, nstroke * sizeof(MOUSE_INPUT_DATA));
        if (!raw) return 0;
        for (unsigned int i = 0; i < nstroke; i++) {
            const InterceptionMouseStroke* ms = (const InterceptionMouseStroke*)stroke;
            raw[i].UnitId = 0;
            raw[i].Flags = ms[i].flags;
            raw[i].ButtonFlags = ms[i].state;
            raw[i].ButtonData = ms[i].rolling;
            raw[i].RawButtons = 0;
            raw[i].LastX = ms[i].x;
            raw[i].LastY = ms[i].y;
            raw[i].ExtraInformation = ms[i].information;
        }
        DeviceIoControl(arr[device - 1].handle, IOCTL_WRITE, raw, (DWORD)(nstroke * sizeof(MOUSE_INPUT_DATA)), NULL, 0, &written, NULL);
        HeapFree(GetProcessHeap(), 0, raw);
        return (int)(written / sizeof(MOUSE_INPUT_DATA));
    }
}

int interception_is_keyboard(InterceptionDevice device) {
    return device >= INTERCEPTION_KEYBOARD(0) && device <= INTERCEPTION_KEYBOARD(INTERCEPTION_MAX_KEYBOARD - 1);
}

int interception_is_mouse(InterceptionDevice device) {
    return device >= INTERCEPTION_MOUSE(0) && device <= INTERCEPTION_MOUSE(INTERCEPTION_MAX_MOUSE - 1);
}

int interception_is_invalid(InterceptionDevice device) {
    return !interception_is_keyboard(device) && !interception_is_mouse(device);
}
