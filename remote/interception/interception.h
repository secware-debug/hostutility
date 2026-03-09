/**
 * interception.h - C API for the Interception driver.
 * Sourced from https://github.com/kennyhml/cppinterception (interception_c_api).
 * Used under MIT license. Driver: https://github.com/oblitum/Interception
 */
#ifndef REMOTE_INTERCEPTION_H
#define REMOTE_INTERCEPTION_H

#define INTERCEPTION_MAX_KEYBOARD 10
#define INTERCEPTION_MAX_MOUSE 10
#define INTERCEPTION_MAX_DEVICE ((INTERCEPTION_MAX_KEYBOARD) + (INTERCEPTION_MAX_MOUSE))

#define INTERCEPTION_KEYBOARD(index) ((index) + 1)
#define INTERCEPTION_MOUSE(index) ((INTERCEPTION_MAX_KEYBOARD) + (index) + 1)

typedef void* InterceptionContext;
typedef int InterceptionDevice;
typedef int InterceptionPrecedence;
typedef unsigned short InterceptionFilter;
typedef int (*InterceptionPredicate)(InterceptionDevice device);

enum InterceptionKeyState {
    INTERCEPTION_KEY_DOWN = 0x00,
    INTERCEPTION_KEY_UP = 0x01,
    INTERCEPTION_KEY_E0 = 0x02,
    INTERCEPTION_KEY_E1 = 0x04,
};

enum InterceptionMouseState {
    INTERCEPTION_MOUSE_LEFT_BUTTON_DOWN = 0x001,
    INTERCEPTION_MOUSE_LEFT_BUTTON_UP = 0x002,
    INTERCEPTION_MOUSE_RIGHT_BUTTON_DOWN = 0x004,
    INTERCEPTION_MOUSE_RIGHT_BUTTON_UP = 0x008,
    INTERCEPTION_MOUSE_MIDDLE_BUTTON_DOWN = 0x010,
    INTERCEPTION_MOUSE_MIDDLE_BUTTON_UP = 0x020,
    INTERCEPTION_MOUSE_WHEEL = 0x400,
};

enum InterceptionMouseFlag {
    INTERCEPTION_MOUSE_MOVE_RELATIVE = 0x000,
    INTERCEPTION_MOUSE_MOVE_ABSOLUTE = 0x001,
    INTERCEPTION_MOUSE_VIRTUAL_DESKTOP = 0x002,
};

typedef struct {
    unsigned short state;
    unsigned short flags;
    short rolling;
    int x;
    int y;
    unsigned int information;
} InterceptionMouseStroke;

typedef struct {
    unsigned short code;
    unsigned short state;
    unsigned int information;
} InterceptionKeyStroke;

typedef char InterceptionStroke[sizeof(InterceptionMouseStroke)];

InterceptionContext interception_create_context(void);
void interception_destroy_context(InterceptionContext context);
int interception_send(InterceptionContext context, InterceptionDevice device, const InterceptionStroke* stroke, unsigned int nstroke);
int interception_is_keyboard(InterceptionDevice device);
int interception_is_mouse(InterceptionDevice device);
int interception_is_invalid(InterceptionDevice device);

#endif /* REMOTE_INTERCEPTION_H */
