#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <stddef.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// Calcola l'hash SHA-256 di un buffer di dati
int calculate_sha256(const unsigned char *data, size_t data_len, unsigned char *hash_out);

// Firma un buffer di dati usando la chiave privata specificata
int sign_data(const unsigned char *data, size_t data_len, const char *priv_key_path, unsigned char *sig_out, size_t *sig_len);

// Verifica la firma di un buffer usando la chiave pubblica specificata
int verify_signature(const unsigned char *data, size_t data_len, const unsigned char *signature, size_t sig_len, const char *pub_key_path);

// Genera una coppia di chiavi effimere per ECDHE (Curve P-256)
EVP_PKEY* generate_ephemeral_key(void);

// Esporta la chiave pubblica in un buffer di byte per spedirla sul socket
int export_public_key(EVP_PKEY *pkey, unsigned char *buffer, size_t *len);

// Importa una chiave pubblica ricevuta dal socket
EVP_PKEY* import_public_key(const unsigned char *buffer, size_t len);

// Deriva il segreto condiviso (Shared Secret)
int derive_shared_secret(EVP_PKEY *my_key, EVP_PKEY *peer_pub_key, unsigned char *secret_out, size_t *secret_len);

// Genera un Nonce casuale (per prevenire i Replay Attacks)
int generate_nonce(unsigned char *nonce, size_t len);

// Deriva una chiave simmetrica a 256 bit (32 byte) dal segreto condiviso DH
int derive_symmetric_key(const unsigned char *shared_secret, size_t secret_len, unsigned char *symmetric_key);

// Cifra i dati usando AES-256-GCM e genera il tag di integrità
int encrypt_aes_gcm(const unsigned char *plaintext, int plaintext_len,
                    const unsigned char *aad, int aad_len,
                    const unsigned char *key, const unsigned char *iv,
                    unsigned char *ciphertext, unsigned char *tag);

// Decifra e autentica i dati. Restituisce -1 se i dati sono stati manomessi.
int decrypt_aes_gcm(const unsigned char *ciphertext, int ciphertext_len,
                    const unsigned char *aad, int aad_len,
                    const unsigned char *tag, const unsigned char *key, const unsigned char *iv,
                    unsigned char *plaintext);

#endif // CRYPTO_UTILS_H