#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <time.h>



// --- Costanti per AES-GCM ---
#define AES_KEY_SIZE 32  // 256 bit
#define AES_IV_SIZE 12   // 96 bit (standard per GCM)
#define AES_TAG_SIZE 16  // 128 bit

// --- Costanti Generali ---
#define MAX_USERNAME_LEN 32
#define MAX_PASSWORD_LEN 32
#define HASH_SIZE 32        // Dimensione fissa per SHA-256 (256 bit = 32 byte)
#define MAX_SIGNATURE_LEN 256 // Dimensione massima ipotetica per una firma RSA a 2048 bit

// --- Costanti per la Crittografia ---
#define MAX_DH_PUBKEY_LEN 1024 // Dimensione massima per una chiave pubblica esportata
#define NONCE_SIZE 32          // 32 byte casuali per prevenire Replay Attacks


// --- Codici Operativi (OpCodes) ---
// Identificano il tipo di richiesta che il client sta facendo al server
typedef enum {
    OP_BALANCE = 1,
    OP_TIMESTAMP = 2,
    OP_HANDSHAKE_SERVER = 3, // Il server invia la sua chiave DH pubblica firmata
    OP_HANDSHAKE_CLIENT = 4, // Il client invia la sua chiave DH pubblica
    OP_AUTH = 5,             // Il client invia le credenziali
    OP_RECHARGE = 6,         // Il client chiede altri crediti
    OP_ERROR = 99
} OpCode;


// --- Busta per Messaggi Cifrati (Secure Channel) ---
typedef struct {
    unsigned char iv[AES_IV_SIZE];   
    unsigned char tag[AES_TAG_SIZE]; 
    uint32_t sequence_number;       
    uint32_t ciphertext_len;         
} SecureHeader;


// --- Strutture per il Canale Sicuro ---

// 1. Il Server si presenta al Client
typedef struct {
    unsigned char dh_pubkey[MAX_DH_PUBKEY_LEN]; // Chiave pubblica effimera del server
    size_t dh_pubkey_len;
    unsigned char nonce[NONCE_SIZE];            // Numero casuale (No-Replay)
    unsigned char signature[MAX_SIGNATURE_LEN]; // Firma su (dh_pubkey || nonce) usando privKc
    size_t signature_len;
} ServerHandshake;

// 2. Il Client risponde al Server
typedef struct {
    unsigned char dh_pubkey[MAX_DH_PUBKEY_LEN]; // Chiave pubblica effimera del client
    size_t dh_pubkey_len;
    unsigned char nonce[NONCE_SIZE]; // Echo del nonce del server (challenge-response)
} ClientHandshake;

// 3. Autenticazione dell'utente (viaggerà già CIFRATA)
typedef struct {
    char username[MAX_USERNAME_LEN];
    char password[MAX_PASSWORD_LEN];
} AuthRequest;




// --- Strutture Dati Applicative ---

// Richiesta di Timestamp
typedef struct {
    OpCode opcode;          
    unsigned char hash[HASH_SIZE]; 
} TimestampRequest;

// Risposta di Timestamp
typedef struct {
    unsigned char hash[HASH_SIZE];
    time_t timestamp;       
    unsigned char signature[MAX_SIGNATURE_LEN]; 
    size_t signature_len;   
} TimestampResponse;

// Risposta per l'operazione Balance
typedef struct {
    int consumed_timestamps; 
    int remaining_timestamps; 
} BalanceResponse;

// Struttura di Errore Generico
typedef struct {
    OpCode opcode;          
    char message[128];      
} ErrorResponse;

#endif // PROTOCOL_H