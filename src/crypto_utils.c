#include "../include/crypto_utils.h"
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/evp.h>



// --- Generazione Chiavi Effimere (ECDHE) ---
EVP_PKEY* generate_ephemeral_key(void) {
    // Crea il contesto per le chiavi a curva ellittica
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) {
        fprintf(stderr, "Errore: Creazione contesto EC fallita\n");
        return NULL;
    }

    EVP_PKEY_keygen_init(pctx);
    // Usa la curva standard P-256 (prime256v1)
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        fprintf(stderr, "Errore: Generazione chiave effimera fallita\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey; // La chiave contiene sia la parte pubblica che privata
}

// --- Esportazione della Chiave Pubblica per la Rete ---
int export_public_key(EVP_PKEY *pkey, unsigned char *buffer, size_t *len) {
    unsigned char *temp_ptr = buffer;
    // i2d_PUBKEY scrive i byte e sposta il puntatore temp_ptr in avanti
    int bytes_written = i2d_PUBKEY(pkey, &temp_ptr);
    if (bytes_written < 0) {
        fprintf(stderr, "Errore: Esportazione chiave pubblica fallita\n");
        return -1;
    }
    *len = (size_t)bytes_written;
    return 0;
}

// --- Importazione della Chiave Pubblica dalla Rete ---
EVP_PKEY* import_public_key(const unsigned char *buffer, size_t len) {
    const unsigned char *temp_ptr = buffer;
    // d2i_PUBKEY legge i byte dal buffer e ricostruisce la struttura EVP_PKEY
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &temp_ptr, len);
    if (!pkey) {
        fprintf(stderr, "Errore: Importazione chiave pubblica fallita\n");
        ERR_print_errors_fp(stderr);
    }
    return pkey;
}

// --- Derivazione del Segreto Condiviso ---
int derive_shared_secret(EVP_PKEY *my_key, EVP_PKEY *peer_pub_key, unsigned char *secret_out, size_t *secret_len) {
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_key, NULL);
    if (!ctx) return -1;

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peer_pub_key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    // Prima chiamata per ottenere la lunghezza del segreto
    if (EVP_PKEY_derive(ctx, NULL, secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    // Seconda chiamata per scrivere effettivamente i byte del segreto
    if (EVP_PKEY_derive(ctx, secret_out, secret_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    return 0;
}

// --- Generazione del Nonce (per il No-Replay) ---
int generate_nonce(unsigned char *nonce, size_t len) {
    if (RAND_bytes(nonce, len) != 1) {
        fprintf(stderr, "Errore: Generazione numeri casuali fallita\n");
        return -1;
    }
    return 0;
}


// --- Funzione per l'Hashing ---
int calculate_sha256(const unsigned char *data, size_t data_len, unsigned char *hash_out) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "Errore: Impossibile creare il contesto EVP_MD_CTX\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    unsigned int hash_len;

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        fprintf(stderr, "Errore: Inizializzazione SHA-256 fallita\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (1 != EVP_DigestUpdate(mdctx, data, data_len)) {
        fprintf(stderr, "Errore: Aggiornamento hash fallito\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (1 != EVP_DigestFinal_ex(mdctx, hash_out, &hash_len)) {
        fprintf(stderr, "Errore: Estrazione finale dell'hash fallita\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    return 0; 
}

// --- Funzione per la Firma Digitale ---
int sign_data(const unsigned char *data, size_t data_len, const char *priv_key_path, unsigned char *sig_out, size_t *sig_len) {
    FILE *key_file = fopen(priv_key_path, "r");
    if (!key_file) {
        perror("Errore nell'apertura del file della chiave privata");
        return -1;
    }

    EVP_PKEY *priv_key = PEM_read_PrivateKey(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!priv_key) {
        fprintf(stderr, "Errore: Impossibile caricare la chiave privata dal file\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Errore: Impossibile creare il contesto di firma\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(priv_key);
        return -1;
    }

    if (1 != EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, priv_key)) {
        fprintf(stderr, "Errore: Inizializzazione della firma fallita\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(priv_key);
        return -1;
    }

    if (1 != EVP_DigestSignUpdate(mdctx, data, data_len)) {
        fprintf(stderr, "Errore: Aggiornamento dei dati per la firma fallito\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(priv_key);
        return -1;
    }

    if (1 != EVP_DigestSignFinal(mdctx, NULL, sig_len)) {
        fprintf(stderr, "Errore: Calcolo della lunghezza della firma fallito\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(priv_key);
        return -1;
    }

    if (1 != EVP_DigestSignFinal(mdctx, sig_out, sig_len)) {
        fprintf(stderr, "Errore: Generazione effettiva della firma fallita\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(priv_key);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(priv_key);
    return 0; 
}

// --- Funzione per la Verifica della Firma ---
int verify_signature(const unsigned char *data, size_t data_len, const unsigned char *signature, size_t sig_len, const char *pub_key_path) {
    FILE *key_file = fopen(pub_key_path, "r");
    if (!key_file) {
        perror("Errore nell'apertura del file della chiave pubblica");
        return -1;
    }

    EVP_PKEY *pub_key = PEM_read_PUBKEY(key_file, NULL, NULL, NULL);
    fclose(key_file);
    if (!pub_key) {
        fprintf(stderr, "Errore: Impossibile caricare la chiave pubblica dal file\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "Errore: Impossibile creare il contesto di verifica\n");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pub_key);
        return -1;
    }

    if (1 != EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pub_key)) {
        fprintf(stderr, "Errore: Inizializzazione della verifica fallita\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pub_key);
        return -1;
    }

    if (1 != EVP_DigestVerifyUpdate(mdctx, data, data_len)) {
        fprintf(stderr, "Errore: Aggiornamento dei dati per la verifica fallito\n");
        ERR_print_errors_fp(stderr);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pub_key);
        return -1;
    }

    int ret = EVP_DigestVerifyFinal(mdctx, signature, sig_len);
    if (ret != 1) {
        // La firma potrebbe essere semplicemente invalida, oppure esserci stato un errore interno
        fprintf(stderr, "Avviso o Errore: Verifica della firma non superata\n");
        ERR_print_errors_fp(stderr);
    }
    
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pub_key);
    
    return (ret == 1) ? 1 : 0; 
}


// --- Derivazione della Chiave Simmetrica ---
int derive_symmetric_key(const unsigned char *shared_secret, size_t secret_len, unsigned char *symmetric_key) {
    // Usiamo SHA-256 per "schiacciare" il segreto condiviso in una chiave robusta a 256 bit (32 byte)
    return calculate_sha256(shared_secret, secret_len, symmetric_key);
}

// --- Cifratura Autenticata (AES-256-GCM con AAD) ---
int encrypt_aes_gcm(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *aad, int aad_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len, ciphertext_len;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) return -1;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) return -1;

    // Aggiunta dell'Additional Authenticated Data (AAD)
    if (aad && aad_len > 0) {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return -1;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) return -1;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// --- Hashing Password con PBKDF2-HMAC-SHA256 ---
int hash_password_pbkdf2(const char *password, const unsigned char *salt, size_t salt_len, unsigned char *hash_out, size_t hash_len) {
    if (PKCS5_PBKDF2_HMAC(password, (int)strlen(password), salt, (int)salt_len, 100000, EVP_sha256(), (int)hash_len, hash_out) != 1) {
        fprintf(stderr, "Errore: PBKDF2 fallita\n");
        return -1;
    }
    return 0;
}

// --- Conversione Byte -> Hex ---
void bytes_to_hex(const unsigned char *bytes, size_t len, char *hex_out) {
    for (size_t i = 0; i < len; i++)
        sprintf(hex_out + i * 2, "%02x", bytes[i]);
    hex_out[len * 2] = '\0';
}

// --- Conversione Hex -> Byte ---
int hex_to_bytes(const char *hex, size_t hex_len, unsigned char *bytes_out) {
    if (hex_len % 2 != 0) return -1;
    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        if (sscanf(hex + i * 2, "%02x", &byte) != 1) return -1;
        bytes_out[i] = (unsigned char)byte;
    }
    return 0;
}

// --- Decifratura Autenticata (AES-256-GCM con AAD) ---
int decrypt_aes_gcm(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *aad, int aad_len,
                    const unsigned char *tag, const unsigned char *key, const unsigned char *iv,
                    unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len, plaintext_len, ret;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) return -1;
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) return -1;

    // Aggiunta dell'Additional Authenticated Data (AAD)
    if (aad && aad_len > 0) {
        if (1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) return -1;
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return -1;
    plaintext_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag)) return -1;
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        fprintf(stderr, "Allarme: Verifica integrità AES-GCM fallita (Tag o AAD non validi).\n");
        return -1; 
    }
}