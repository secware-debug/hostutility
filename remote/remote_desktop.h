/**
 * remote_desktop.h
 * Screen capture for Remote Desktop. Delta encoding (first frame full JPEG, later = changed rects).
 * Format matches UnsafeStreamCodec. Caller must HeapFree the returned buffer.
 */
#ifndef REMOTE_DESKTOP_H
#define REMOTE_DESKTOP_H

#ifdef __cplusplus
extern "C" {
#endif

/* Reset delta state (call when CreateNew received). */
void remote_desktop_reset(void);

/* Get bounds of the given display (0-based index). Used to convert monitor-relative coords to screen coords for input. */
void remote_desktop_get_monitor_bounds(int display_index, int* out_x, int* out_y, unsigned int* out_width, unsigned int* out_height);

/* Capture the given display (0-based index). quality 1-100 = JPEG. *out_len = total bytes; *out_w, *out_h = resolution. */
unsigned char* remote_desktop_capture(int display_index, int quality, unsigned int* out_len, int* out_w, int* out_h);

#ifdef __cplusplus
}
#endif

#endif /* REMOTE_DESKTOP_H */
