/**
 * remote_log.c
 * DebugView logging; only active in Debug build (_DEBUG).
 */
#include "pch.h"
#include "remote_log.h"
#include <stdarg.h>
#include <stdio.h>

/* Set to 1 for debug logging. Per-frame logs (loop, transport send/recv) significantly slow remote desktop. */
#define REMOTE_LOG_ENABLED 1

#if REMOTE_LOG_ENABLED
static char s_buf[512];
#endif

void remote_log(const char* fmt, ...) {
#if REMOTE_LOG_ENABLED
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(s_buf, sizeof(s_buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    s_buf[sizeof(s_buf) - 1] = '\0';
    OutputDebugStringA("[remote] ");
    OutputDebugStringA(s_buf);
    OutputDebugStringA("\r\n");
#else
    (void)fmt;
#endif
}

void remote_log_prefix(const char* prefix, const char* fmt, ...) {
#if REMOTE_LOG_ENABLED
    va_list ap;
    va_start(ap, fmt);
    int n = _snprintf_s(s_buf, sizeof(s_buf), _TRUNCATE, "[remote][%s] ", prefix);
    if (n > 0 && n < (int)sizeof(s_buf))
        _vsnprintf_s(s_buf + n, sizeof(s_buf) - (size_t)n, _TRUNCATE, fmt, ap);
    va_end(ap);
    s_buf[sizeof(s_buf) - 1] = '\0';
    OutputDebugStringA(s_buf);
    OutputDebugStringA("\r\n");
#else
    (void)prefix;
    (void)fmt;
#endif
}

#define REMOTE_LOG_HEX_MAX 64
#if REMOTE_LOG_ENABLED
static char s_hex_buf[REMOTE_LOG_HEX_MAX * 3 + 64];
#endif

void remote_log_hex(const char* label, const unsigned char* buf, unsigned int len) {
#if REMOTE_LOG_ENABLED
    if (!buf) { OutputDebugStringA("[remote] "); OutputDebugStringA(label); OutputDebugStringA(": (null)\r\n"); return; }
    if (len > REMOTE_LOG_HEX_MAX) len = REMOTE_LOG_HEX_MAX;
    int n = _snprintf_s(s_hex_buf, sizeof(s_hex_buf), _TRUNCATE, "[remote] %s[%u]: ", label, len);
    if (n < 0) return;
    char* p = s_hex_buf + (n > 0 ? n : 0);
    size_t cap = sizeof(s_hex_buf) - (size_t)(p - s_hex_buf);
    for (unsigned int i = 0; i < len && cap > 3; i++) {
        int w = _snprintf_s(p, cap, _TRUNCATE, "%02X ", buf[i]);
        if (w <= 0) break;
        p += w;
        cap -= (size_t)w;
    }
    if (len == 0) p += _snprintf_s(p, cap, _TRUNCATE, "(empty)");
    _snprintf_s(p, cap, _TRUNCATE, "\r\n");
    s_hex_buf[sizeof(s_hex_buf) - 1] = '\0';
    OutputDebugStringA(s_hex_buf);
#else
    (void)label;
    (void)buf;
    (void)len;
#endif
}
