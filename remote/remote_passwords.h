/**
 * remote_passwords.h
 * Password recovery - reads from Windows Credential Manager.
 * RecoveredAccount: Username, Password, Url, Application.
 */
#ifndef REMOTE_PASSWORDS_H
#define REMOTE_PASSWORDS_H

#ifdef __cplusplus
extern "C" {
#endif

#define REMOTE_MAX_ACCOUNTS  256
#define REMOTE_ACCOUNT_STR_LEN 2048

typedef struct {
    char username[REMOTE_ACCOUNT_STR_LEN];
    char password[REMOTE_ACCOUNT_STR_LEN];
    char url[REMOTE_ACCOUNT_STR_LEN];
    char application[REMOTE_ACCOUNT_STR_LEN];
} remote_recovered_account_t;

/* Collect credentials from Windows Credential Manager. Returns number of accounts (0..REMOTE_MAX_ACCOUNTS). */
unsigned int remote_passwords_collect(remote_recovered_account_t* accounts, unsigned int max_accounts);

#ifdef __cplusplus
}
#endif

#endif /* REMOTE_PASSWORDS_H */
