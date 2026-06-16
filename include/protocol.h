#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>
#include <time.h>

// --- Costanti Generali ---
#define MAX_USERNAME_LEN 32
#define MAX_PASSWORD_LEN 32
#define HASH_SIZE 32        // Dimensione fissa per SHA-256 (256 bit = 32 byte)
#define MAX_SIGNATURE_LEN 256 // Dimensione massima ipotetica per una firma RSA a 2048 bit

// --- Codici Operativi (OpCodes) ---
// Identificano il tipo di richiesta che il client sta facendo al server
typedef enum {
    OP_BALANCE = 1,
    OP_TIMESTAMP = 2,
    OP_ERROR = 99
} OpCode;

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