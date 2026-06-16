#ifndef DB_UTILS_H
#define DB_UTILS_H

#include "protocol.h" // Per MAX_USERNAME_LEN e MAX_PASSWORD_LEN

typedef struct {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
    int consumed;
    int total;
} User;

// Verifica le credenziali e, se corrette, popola la struct User. Restituisce 1 se OK, 0 se errate.
int authenticate_user(const char *username, const char *password, User *out_user);

// Aggiorna il valore "consumed" dell'utente nel file JSON e lo salva su disco
int update_user_consumed(const char *username, int new_consumed);

// Aggiunge nuovi crediti al totale dell'utente
int add_user_credits(const char *username, int amount_to_add);

#endif