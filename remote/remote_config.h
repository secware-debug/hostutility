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

typedef struct remote_config {
    char server_address[256];
    unsigned short server_port;
    int valid;
} remote_config_t;

/* Load config from config.json. Returns 1 on success, 0 on failure. */
int remote_config_load(remote_config_t* out_config);

#ifdef __cplusplus
}
#endif

#endif /* REMOTE_CONFIG_H */
