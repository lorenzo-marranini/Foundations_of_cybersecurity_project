#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "../include/protocol.h"
#include "../include/crypto_utils.h"
#include "../include/net_utils.h"
#include "../include/db_utils.h"

#define PORT 8080


void handle_client(int client_fd) {
    printf("\n[Server] Nuovo client connesso. Inizio Handshake crittografico...\n");

    // ==========================================
    // FASE 1: HANDSHAKE (Invariato)
    // ==========================================
    EVP_PKEY *server_dh_key = generate_ephemeral_key();
    ServerHandshake sh_msg;
    export_public_key(server_dh_key, sh_msg.dh_pubkey, &sh_msg.dh_pubkey_len);
    generate_nonce(sh_msg.nonce, NONCE_SIZE);

    size_t data_to_sign_len = sh_msg.dh_pubkey_len + NONCE_SIZE;
    unsigned char *data_to_sign = malloc(data_to_sign_len);
    memcpy(data_to_sign, sh_msg.dh_pubkey, sh_msg.dh_pubkey_len);
    memcpy(data_to_sign + sh_msg.dh_pubkey_len, sh_msg.nonce, NONCE_SIZE);

    if (sign_data(data_to_sign, data_to_sign_len, "keys/server_conn_priv.pem", sh_msg.signature, &sh_msg.signature_len) < 0) {
        free(data_to_sign); EVP_PKEY_free(server_dh_key); close(client_fd); return;
    }
    free(data_to_sign);

    OpCode op_sh = OP_HANDSHAKE_SERVER;
    send_full(client_fd, &op_sh, sizeof(OpCode));
    send_full(client_fd, &sh_msg, sizeof(ServerHandshake));

    OpCode op_client;
    if (recv_full(client_fd, &op_client, sizeof(OpCode)) <= 0 || op_client != OP_HANDSHAKE_CLIENT) {
        EVP_PKEY_free(server_dh_key); close(client_fd); return;
    }

    ClientHandshake ch_msg;
    recv_full(client_fd, &ch_msg, sizeof(ClientHandshake));

    EVP_PKEY *client_pub_key = import_public_key(ch_msg.dh_pubkey, ch_msg.dh_pubkey_len);
    unsigned char shared_secret[256]; 
    size_t shared_secret_len;
    
    if (derive_shared_secret(server_dh_key, client_pub_key, shared_secret, &shared_secret_len) != 0) {
        EVP_PKEY_free(server_dh_key); EVP_PKEY_free(client_pub_key); close(client_fd); return;
    }
    EVP_PKEY_free(server_dh_key); EVP_PKEY_free(client_pub_key);

    // ==========================================
    // FASE 2: AUTENTICAZIONE CIFRATA
    // ==========================================
    unsigned char aes_key[AES_KEY_SIZE];
    derive_symmetric_key(shared_secret, shared_secret_len, aes_key); // Creiamo la chiave AES

    // INIZIALIZZAZIONE CONTATORI
    uint32_t tx_seq = 1;
    uint32_t rx_seq = 1;
    
    printf("[Server] Canale sicuro stabilito. In attesa delle credenziali...\n");

    AuthRequest auth_req;
    if (recv_secure(client_fd, &auth_req, sizeof(AuthRequest), aes_key, &rx_seq) <= 0) {
        printf("[Server] Errore di decifratura o connessione chiusa durante il login.\n");
        close(client_fd);
        return;
    }

    User session_user;
    OpCode auth_response;

    if (authenticate_user(auth_req.username, auth_req.password, &session_user)) {
        printf("[Server] Autenticazione riuscita per l'utente: %s\n", session_user.username);
        auth_response = OP_AUTH; 
    } else {
        printf("[Server] Autenticazione fallita per l'utente: %s\n", auth_req.username);
        auth_response = OP_ERROR; 
    }

    send_secure(client_fd, &auth_response, sizeof(OpCode), aes_key, &tx_seq);

    if (auth_response == OP_ERROR) {
        close(client_fd);
        return; // Disconnettiamo se le credenziali sono errate
    }

    // ==========================================
    // FASE 3: GESTIONE RICHIESTE (Tutto tramite recv_secure/send_secure)
    // ==========================================
    OpCode opcode;
    while (1) {
        if (recv_secure(client_fd, &opcode, sizeof(OpCode), aes_key, &rx_seq) <= 0) {
            printf("[Server] Client disconnesso o errore di integrita'.\n");
            break; 
        }
        // RICHIESTA SALDO
        if (opcode == OP_BALANCE) {
            BalanceResponse res;
            res.consumed_timestamps = session_user.consumed;
            res.remaining_timestamps = session_user.total - session_user.consumed;
            send_secure(client_fd, &res, sizeof(BalanceResponse), aes_key, &tx_seq);
        } 
        // RICHIESTA TIMESTAMP
        else if (opcode == OP_TIMESTAMP) {
            TimestampRequest req;
            recv_secure(client_fd, req.hash, HASH_SIZE, aes_key, &rx_seq);

            if (session_user.consumed >= session_user.total) {
                OpCode err_code = OP_ERROR;
                ErrorResponse err;
                err.opcode = OP_ERROR;
                strncpy(err.message, "Crediti esauriti.", sizeof(err.message));
                send_secure(client_fd, &err_code, sizeof(OpCode), aes_key, &tx_seq);
                send_secure(client_fd, &err, sizeof(ErrorResponse), aes_key, &tx_seq);
            } else {
                TimestampResponse res;
                memcpy(res.hash, req.hash, HASH_SIZE);
                res.timestamp = time(NULL);

                size_t data_to_sign_len = HASH_SIZE + sizeof(time_t);
                unsigned char data_to_sign[HASH_SIZE + sizeof(time_t)];
                memcpy(data_to_sign, res.hash, HASH_SIZE);
                memcpy(data_to_sign + HASH_SIZE, &res.timestamp, sizeof(time_t));

                sign_data(data_to_sign, data_to_sign_len, "keys/server_ts_priv.pem", res.signature, &res.signature_len);

                session_user.consumed++;
                update_user_consumed(session_user.username, session_user.consumed);

                OpCode success_code = OP_TIMESTAMP;
                send_secure(client_fd, &success_code, sizeof(OpCode), aes_key, &tx_seq);
                send_secure(client_fd, &res, sizeof(TimestampResponse), aes_key, &tx_seq);
            }
        } 
        // RICARICA CREDITI
        else if (opcode == OP_RECHARGE) {
            int amount_to_add = 0;
            // Riceviamo quanti crediti vuole acquistare
            recv_secure(client_fd, &amount_to_add, sizeof(int), aes_key, &rx_seq);

            if (amount_to_add > 0) {
                // Aggiorniamo in memoria
                session_user.total += amount_to_add;
                
                // Salviamo nel DB
                add_user_credits(session_user.username, amount_to_add);
                
                printf("[Server] Ricarica di %d crediti effettuata per %s.\n", amount_to_add, session_user.username);
                
                OpCode success = OP_RECHARGE;
                send_secure(client_fd, &success, sizeof(OpCode), aes_key, &tx_seq);
                // Rimandiamo indietro il nuovo totale aggiornato
                send_secure(client_fd, &session_user.total, sizeof(int), aes_key, &tx_seq);
            } else {
                OpCode err = OP_ERROR;
                send_secure(client_fd, &err, sizeof(OpCode), aes_key, &tx_seq);
            }
        }
        else {
            break;
        }
    } 
    close(client_fd);
    printf("[Server] Connessione chiusa.\n");
}

int main() {
    int server_fd = setup_server(PORT);
    if (server_fd < 0) return EXIT_FAILURE;
    printf("[Server] In ascolto sulla porta %d...\n", PORT);
    while (1) {
        struct sockaddr_in client_addr; socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd >= 0) handle_client(client_fd);
    }
    return 0;
}