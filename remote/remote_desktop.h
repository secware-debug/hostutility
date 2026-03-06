/**
 * remote_desktop.h
 * Screen capture for Remote Desktop. Produces codec first-frame format: 4-byte LE length + BMP bytes.
 * Caller must HeapFree the returned buffer.
 */
#ifndef REMOTE_DESKTOP_H
#define REMOTE_DESKTOP_H

#ifdef __cplusplus
extern "C" {
#endif

/* Capture the given display (0-based index). quality 1-100 = JPEG compression. *out_len = total bytes; *out_w, *out_h = resolution. */
unsigned char* remote_desktop_capture(int display_index, int quality, unsigned int* out_len, int* out_w, int* out_h);

#ifdef __cplusplus
}
#endif

#endif /* REMOTE_DESKTOP_H */
