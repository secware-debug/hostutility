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

static int parse_bool_value(const char* json, const char* key, int* out) {
    char search[64];
    _snprintf_s(search, _countof(search), _TRUNCATE, "\"%s\"", key);
    const char* pos = strstr(json, search);
    if (!pos) return 0;
    pos += strlen(search);
    trim_whitespace(&pos);
    if (*pos != ':') return 0;
    pos++;
    trim_whitespace(&pos);
    if (strncmp(pos, "true", 4) == 0) { *out = 1; return 1; }
    if (strncmp(pos, "false", 5) == 0) { *out = 0; return 1; }
    return 0;
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
    /* Resolve directory of this DLL (not the host EXE), so config.json next to remote.dll works. */
    HMODULE hModule = NULL;
    DWORD len = 0;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)&remote_config_load, &hModule)) {
        len = GetModuleFileNameA(hModule, path, MAX_PATH);
    }
    if (len == 0 || len >= MAX_PATH) {
        /* Fallback: host executable directory. */
        len = GetModuleFileNameA(NULL, path, MAX_PATH);
    }
    if (len == 0 || len >= MAX_PATH) {
        remote_log("config: GetModuleFileName failed");
        return 0;
    }

    /* Replace module name with config filename */
    {
        char* last_slash = strrchr(path, '\\');
        if (last_slash) *(last_slash + 1) = '\0';
        else path[0] = '\0';
        strcat_s(path, MAX_PATH, CONFIG_FILENAME);
    }

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
    /* Optional stable client UUID (64 chars). If missing/invalid length, client falls back to generating one. */
    (void)parse_string_value(buf, "Uuid", out_config->uuid, sizeof(out_config->uuid));
    if (out_config->uuid[0] == '\0') {
        /* Be tolerant to different json casing. */
        (void)parse_string_value(buf, "uuid", out_config->uuid, sizeof(out_config->uuid));
    }
    if (out_config->uuid[0] == '\0') {
        /* Some clients may provide "UUID" (all-caps). */
        (void)parse_string_value(buf, "UUID", out_config->uuid, sizeof(out_config->uuid));
    }

    int port = 0;
    if (parse_int_value(buf, "ServerPort", &port) && port > 0 && port <= 65535)
        out_config->server_port = (unsigned short)port;
    int trans = 90;
    if (parse_int_value(buf, "GhostTransparency", &trans) && trans >= 0 && trans <= 100)
        out_config->ghost_transparency = trans;
    else
        out_config->ghost_transparency = 90;
    int kl = 0;
    if (parse_bool_value(buf, "Keylogging", &kl))
        out_config->keylogging = kl;
    else if (parse_int_value(buf, "Keylogging", &kl) && (kl == 0 || kl == 1))
        out_config->keylogging = kl;
    else
        out_config->keylogging = 0;

    int pim = 0;
    /* ping_interval_minutes is optional; when <= 0 ping is disabled. */
    if (parse_int_value(buf, "ping_interval_minutes", &pim) && pim > 0)
        out_config->ping_interval_minutes = pim;
    else
        out_config->ping_interval_minutes = 0;
    out_config->valid = 1;
    return 1;
}
