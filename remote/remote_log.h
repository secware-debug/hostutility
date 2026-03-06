/**
 * remote_log.h
 * Logging for remote.dll: OutputDebugString (visible in DebugView).
 * Logs only when _DEBUG is defined (Debug builds).
 */
#ifndef REMOTE_LOG_H
#define REMOTE_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

/* Log a message (printf-style format). No-op in Release. */
void remote_log(const char* fmt, ...);

/* Log with a prefix such as "[remote] ". */
void remote_log_prefix(const char* prefix, const char* fmt, ...);

/* Log first `len` bytes of `buf` as hex (e.g. "recv payload[8]: 08 32 0A 03 31 2E 30 ..."). Max 64 bytes dumped. */
void remote_log_hex(const char* label, const unsigned char* buf, unsigned int len);

#ifdef __cplusplus
}
#endif

#endif /* REMOTE_LOG_H */
