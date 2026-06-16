#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../include/protocol.h"
#include "../include/net_utils.h"
#include "../include/crypto_utils.h"

#define SERVER_IP "127.0.0.1"
#define PORT 8080

void print_menu() {
    printf("\n=== TSS Client ===\n");
    printf("1. Saldo (Balance)\n");
    printf("2. Timestamp File\n");
    printf("3. Ricarica Crediti\n");
    printf("0. Esci\n");
    printf("Scelta: ");
}

int main() {
    int sockfd = connect_to_server(SERVER_IP, PORT);
    if (sockfd < 0) return EXIT_FAILURE;

    // ==========================================
    // FASE 1: HANDSHAKE (Invariato)
    // ==========================================
    OpCode op;
    if (recv_full(sockfd, &op, sizeof(OpCode)) <= 0 || op != OP_HANDSHAKE_SERVER) return EXIT_FAILURE;

    ServerHandshake sh_msg;
    recv_full(sockfd, &sh_msg, sizeof(ServerHandshake));

    size_t data_to_verify_len = sh_msg.dh_pubkey_len + NONCE_SIZE;
    unsigned char *data_to_verify = malloc(data_to_verify_len);
    memcpy(data_to_verify, sh_msg.dh_pubkey, sh_msg.dh_pubkey_len);
    memcpy(data_to_verify + sh_msg.dh_pubkey_len, sh_msg.nonce, NONCE_SIZE);

    if (verify_signature(data_to_verify, data_to_verify_len, sh_msg.signature, sh_msg.signature_len, "keys/server_conn_pub.pem") != 1) {
        printf("[Client] Firma server NON VALIDA!\n"); free(data_to_verify); return EXIT_FAILURE;
    }
    free(data_to_verify);

    EVP_PKEY *client_dh_key = generate_ephemeral_key();
    ClientHandshake ch_msg;
    export_public_key(client_dh_key, ch_msg.dh_pubkey, &ch_msg.dh_pubkey_len);

    OpCode op_client = OP_HANDSHAKE_CLIENT;
    send_full(sockfd, &op_client, sizeof(OpCode));
    send_full(sockfd, &ch_msg, sizeof(ClientHandshake));

    EVP_PKEY *server_pub_key = import_public_key(sh_msg.dh_pubkey, sh_msg.dh_pubkey_len);
    unsigned char shared_secret[256];
    size_t shared_secret_len;

    derive_shared_secret(client_dh_key, server_pub_key, shared_secret, &shared_secret_len);
    EVP_PKEY_free(client_dh_key); EVP_PKEY_free(server_pub_key);

    // ==========================================
    // FASE 2: AUTENTICAZIONE CIFRATA
    // ==========================================
    unsigned char aes_key[AES_KEY_SIZE];
    derive_symmetric_key(shared_secret, shared_secret_len, aes_key);

    // INIZIALIZZAZIONE CONTATORI 
    uint32_t tx_seq = 1;
    uint32_t rx_seq = 1;

    AuthRequest auth_req;
    printf("\n--- Login Sicuro ---\nUsername: ");
    scanf("%31s", auth_req.username);
    printf("Password: ");
    scanf("%31s", auth_req.password);

    // Inviamo le credenziali CIFRATE
    send_secure(sockfd, &auth_req, sizeof(AuthRequest), aes_key, &tx_seq);

    OpCode auth_response;
    if (recv_secure(sockfd, &auth_response, sizeof(OpCode), aes_key, &rx_seq) <= 0 || auth_response == OP_ERROR) {
        printf("[Client] Credenziali Errate o connessione chiusa.\n");
        close(sockfd);
        return EXIT_FAILURE;
    }
    printf("[Client] Login effettuato con successo!\n");

    // ==========================================
    // FASE 3: MENU OPERAZIONI
    // ==========================================
    int choice;
    do {
        print_menu();
        if (scanf("%d", &choice) != 1) { while (getchar() != '\n'); continue; }

        if (choice == 1) {
            // OPERAZIONE RICHIESTA SALDO
            OpCode req_op = OP_BALANCE;
            send_secure(sockfd, &req_op, sizeof(OpCode), aes_key, &tx_seq);

            BalanceResponse res;
            if (recv_secure(sockfd, &res, sizeof(BalanceResponse), aes_key, &rx_seq) > 0) {
                printf("Consumati: %d | Rimanenti: %d\n", res.consumed_timestamps, res.remaining_timestamps);
            }
        } else if (choice == 2) {
            // OPERAZIONE RICHIESTA TIMESTAMP
            char filepath[256];
            printf("File da marcare: ");
            scanf("%255s", filepath);

            FILE *file = fopen(filepath, "rb");
            if (!file) { perror("Errore apertura"); continue; }
            fseek(file, 0, SEEK_END); long filesize = ftell(file); fseek(file, 0, SEEK_SET);
            unsigned char *file_buffer = malloc(filesize);
            fread(file_buffer, 1, filesize, file); fclose(file);

            OpCode req_op = OP_TIMESTAMP;
            send_secure(sockfd, &req_op, sizeof(OpCode), aes_key, &tx_seq);

            TimestampRequest req;
            calculate_sha256(file_buffer, filesize, req.hash);
            free(file_buffer); 
            send_secure(sockfd, req.hash, HASH_SIZE, aes_key, &tx_seq);

            OpCode response_code;
            recv_secure(sockfd, &response_code, sizeof(OpCode), aes_key, &rx_seq);

            if (response_code == OP_ERROR) {
                ErrorResponse err; recv_secure(sockfd, &err, sizeof(ErrorResponse), aes_key, &rx_seq);
                printf("[Errore] %s\n", err.message);
            } else if (response_code == OP_TIMESTAMP) {
                TimestampResponse res; recv_secure(sockfd, &res, sizeof(TimestampResponse), aes_key, &rx_seq);
                
                unsigned char data_to_verify_ts[HASH_SIZE + sizeof(time_t)];
                memcpy(data_to_verify_ts, res.hash, HASH_SIZE);
                memcpy(data_to_verify_ts + HASH_SIZE, &res.timestamp, sizeof(time_t));

                if (verify_signature(data_to_verify_ts, sizeof(data_to_verify_ts), res.signature, res.signature_len, "keys/server_ts_pub.pem") == 1) {
                    printf("[Client] Timestamp VALIDO. Ora: %ld\n", res.timestamp);
                } else {
                    printf("[Client] ATTENZIONE! Firma del timestamp non valida.\n");
                }
            }
        }
        else if ( choice == 3){
            // OPERAZIONE RICARICA
            int amount;
            printf("Quanti crediti vuoi acquistare? ");
            if (scanf("%d", &amount) != 1 || amount <= 0) {
                printf("Quantita' non valida.\n");
                while (getchar() != '\n'); 
                continue;
            }

            // Invia OpCode
            OpCode req_op = OP_RECHARGE;
            send_secure(sockfd, &req_op, sizeof(OpCode), aes_key, &tx_seq);
            
            // Invia la quantità richiesta
            send_secure(sockfd, &amount, sizeof(int), aes_key, &tx_seq);

            // Attendi risposta
            OpCode res_op;
            if (recv_secure(sockfd, &res_op, sizeof(OpCode), aes_key, &rx_seq) > 0) {
                if (res_op == OP_RECHARGE) {
                    int new_total;
                    recv_secure(sockfd, &new_total, sizeof(int), aes_key, &rx_seq);
                    printf("\n[Client] Pagamento simulato con successo!\n");
                    printf("Il tuo nuovo volume totale di crediti e': %d\n", new_total);
                } else {
                    printf("\n[Client] Errore durante la ricarica.\n");
                }
            }
        }
    } while (choice != 0);

    close(sockfd);
    return 0;
}