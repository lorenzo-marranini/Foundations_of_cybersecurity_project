#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/db_utils.h"
#include "../include/cJSON.h"
#include "../include/crypto_utils.h"

#define DB_PATH "db/users.json"

// Funzione helper per leggere tutto il file in memoria
static char* read_file(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(length + 1);
    fread(data, 1, length, f);
    data[length] = '\0';
    fclose(f);
    return data;
}

// Funzione helper per salvare la stringa JSON su file
static int write_file(const char *filename, const char *data) {
    FILE *f = fopen(filename, "w");
    if (!f) return 0;
    fprintf(f, "%s", data);
    fclose(f);
    return 1;
}

int authenticate_user(const char *username, const char *password, User *out_user) {
    char *json_data = read_file(DB_PATH);
    if (!json_data) {
        printf("[DB ERRORE] Impossibile trovare o aprire il file %s!\n", DB_PATH);
        return 0; // File inesistente
    }

    cJSON *json = cJSON_Parse(json_data);
    free(json_data);
    if (!json) {
        printf("[DB ERRORE] Il file JSON ha un errore di sintassi (es. virgole mancanti)!\n");
        return 0;
    }

    cJSON *users_array = cJSON_GetObjectItemCaseSensitive(json, "users");
    cJSON *user_item = NULL;
    int found = 0;

    cJSON_ArrayForEach(user_item, users_array) {
        cJSON *u_name = cJSON_GetObjectItemCaseSensitive(user_item, "username");
        cJSON *u_salt = cJSON_GetObjectItemCaseSensitive(user_item, "salt");
        cJSON *u_hash = cJSON_GetObjectItemCaseSensitive(user_item, "password_hash");

        if (!cJSON_IsString(u_name) || !cJSON_IsString(u_salt) || !cJSON_IsString(u_hash))
            continue;

        if (strcmp(u_name->valuestring, username) != 0)
            continue;

        // Decode hex salt
        const char *salt_hex = u_salt->valuestring;
        size_t salt_hex_len = strlen(salt_hex);
        unsigned char salt_bytes[64];
        if (hex_to_bytes(salt_hex, salt_hex_len, salt_bytes) != 0)
            break;

        // Compute PBKDF2 of the supplied password
        unsigned char computed_hash[32];
        if (hash_password_pbkdf2(password, salt_bytes, salt_hex_len / 2, computed_hash, sizeof(computed_hash)) != 0)
            break;

        // Encode computed hash to hex and compare with stored value
        char computed_hex[65];
        bytes_to_hex(computed_hash, sizeof(computed_hash), computed_hex);

        if (strcmp(computed_hex, u_hash->valuestring) == 0) {
            strncpy(out_user->username, u_name->valuestring, MAX_USERNAME_LEN);
            out_user->password[0] = '\0';
            out_user->consumed = cJSON_GetObjectItemCaseSensitive(user_item, "consumed")->valueint;
            out_user->total = cJSON_GetObjectItemCaseSensitive(user_item, "total")->valueint;
            found = 1;
        }
        break;
    }

    cJSON_Delete(json);
    return found;
}

int update_user_consumed(const char *username, int new_consumed) {
    char *json_data = read_file(DB_PATH);
    if (!json_data) return 0;

    cJSON *json = cJSON_Parse(json_data);
    free(json_data);
    if (!json) return 0;

    cJSON *users_array = cJSON_GetObjectItemCaseSensitive(json, "users");
    cJSON *user_item = NULL;
    int updated = 0;

    cJSON_ArrayForEach(user_item, users_array) {
        cJSON *u_name = cJSON_GetObjectItemCaseSensitive(user_item, "username");
        if (cJSON_IsString(u_name) && strcmp(u_name->valuestring, username) == 0) {
            // Aggiorniamo il valore
            cJSON *c_item = cJSON_GetObjectItemCaseSensitive(user_item, "consumed");
            cJSON_SetNumberValue(c_item, new_consumed);
            updated = 1;
            break;
        }
    }

    if (updated) {
        char *new_json_string = cJSON_Print(json);
        write_file(DB_PATH, new_json_string);
        free(new_json_string);
    }

    cJSON_Delete(json);
    return updated;
}

// Aggiunge nuovi crediti
int add_user_credits(const char *username, int amount_to_add) {
    char *json_data = read_file(DB_PATH);
    if (!json_data) return 0;

    cJSON *json = cJSON_Parse(json_data);
    free(json_data);
    if (!json) return 0;

    cJSON *users_array = cJSON_GetObjectItemCaseSensitive(json, "users");
    cJSON *user_item = NULL;
    int updated = 0;

    cJSON_ArrayForEach(user_item, users_array) {
        cJSON *u_name = cJSON_GetObjectItemCaseSensitive(user_item, "username");
        if (cJSON_IsString(u_name) && strcmp(u_name->valuestring, username) == 0) {
            // Trovato l'utente, aggiorniamo il campo "total"
            cJSON *t_item = cJSON_GetObjectItemCaseSensitive(user_item, "total");
            int new_total = t_item->valueint + amount_to_add;
            cJSON_SetNumberValue(t_item, new_total);
            updated = 1;
            break;
        }
    }

    if (updated) {
        char *new_json_string = cJSON_Print(json);
        write_file(DB_PATH, new_json_string);
        free(new_json_string);
    }

    cJSON_Delete(json);
    return updated;
}