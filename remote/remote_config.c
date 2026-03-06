/**
 * remote_config.c
 * Minimal config.json parser for ServerAddress and ServerPort.
 * No external JSON library; single-file implementation.
 */
#include "pch.h"
#include "remote_config.h"
#include "remote_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONFIG_MAX_FILE 4096
#define CONFIG_FILENAME "config.json"

static void trim_whitespace(const char** p) {
    while (**p == ' ' || **p == '\t' || **p == '\r' || **p == '\n') (*p)++;
}

static int parse_string_value(const char* json, const char* key, char* out, size_t out_size) {
    char search[64];
    _snprintf_s(search, _countof(search), _TRUNCATE, "\"%s\"", key);
    const char* pos = strstr(json, search);
    if (!pos) return 0;
    pos += strlen(search);
    trim_whitespace(&pos);
    if (*pos != ':') return 0;
    pos++;
    trim_whitespace(&pos);
    if (*pos != '"') return 0;
    pos++;
    size_t i = 0;
    while (pos[i] && pos[i] != '"' && i < out_size - 1) {
        out[i] = pos[i];
        i++;
    }
    out[i] = '\0';
    return 1;
}

static int parse_int_value(const char* json, const char* key, int* out) {
    char search[64];
    _snprintf_s(search, _countof(search), _TRUNCATE, "\"%s\"", key);
    const char* pos = strstr(json, search);
    if (!pos) return 0;
    pos += strlen(search);
    trim_whitespace(&pos);
    if (*pos != ':') return 0;
    pos++;
    trim_whitespace(&pos);
    *out = (int)strtol(pos, NULL, 10);
    return 1;
}

int remote_config_load(remote_config_t* out_config) {
    if (!out_config) return 0;
    memset(out_config, 0, sizeof(*out_config));
    out_config->server_port = 4782; /* default */

    char path[MAX_PATH];
    DWORD len = GetModuleFileNameA(NULL, path, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        remote_log("config: GetModuleFileName failed");
        return 0;
    }
    /* Replace executable name with config filename */
    char* last_slash = strrchr(path, '\\');
    if (last_slash) *(last_slash + 1) = '\0';
    else path[0] = '\0';
    strcat_s(path, MAX_PATH, CONFIG_FILENAME);

    FILE* f = NULL;
    if (fopen_s(&f, path, "r") != 0 || !f) {
        remote_log("config: not found at %s, trying cwd", path);
        if (fopen_s(&f, CONFIG_FILENAME, "r") != 0 || !f) {
            remote_log("config: not found at " CONFIG_FILENAME);
            return 0;
        }
    }

    char buf[CONFIG_MAX_FILE];
    size_t n = fread(buf, 1, CONFIG_MAX_FILE - 1, f);
    fclose(f);
    if (n == 0) return 0;
    buf[n] = '\0';

    if (!parse_string_value(buf, "ServerAddress", out_config->server_address, sizeof(out_config->server_address)))
        strcpy_s(out_config->server_address, sizeof(out_config->server_address), "127.0.0.1");
    int port = 0;
    if (parse_int_value(buf, "ServerPort", &port) && port > 0 && port <= 65535)
        out_config->server_port = (unsigned short)port;
    out_config->valid = 1;
    return 1;
}
