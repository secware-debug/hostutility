/**
 * remote_input_interception.h
 * Simple API for keyboard and mouse control via the Interception driver.
 * Requires the driver to be installed. Call remote_input_interception_init() before use.
 */
#ifndef REMOTE_INPUT_INTERCEPTION_H
#define REMOTE_INPUT_INTERCEPTION_H

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize interception context. Returns 1 on success, 0 on failure (driver not installed). */
int remote_input_interception_init(void);

/* Shutdown and release resources. Safe to call even if init failed. */
void remote_input_interception_shutdown(void);

/* Returns 1 if interception is ready for use. */
int remote_input_interception_is_ready(void);

/* Mouse: move cursor to screen coordinates (px, py).
 * virt_x/y/w/h = full virtual desktop bounds in physical pixels (from EnumDisplayMonitors). */
void remote_input_interception_mouse_move(int px, int py, int virt_x, int virt_y, int virt_w, int virt_h);

/* Mouse: button 0=left, 1=right, 2=middle. down=1 for press, 0 for release. */
int remote_input_interception_mouse_button(int button, int down);

/* Mouse: scroll delta (positive=up, negative=down). Typical: 120 or -120. */
int remote_input_interception_mouse_wheel(int delta);

/* Keyboard: vk = virtual key code (VK_*), key_down=1 for press, 0 for release. */
void remote_input_interception_key(unsigned char vk, int key_down);

#ifdef __cplusplus
}
#endif

#endif /* REMOTE_INPUT_INTERCEPTION_H */
