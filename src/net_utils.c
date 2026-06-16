#include "../include/net_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "../include/protocol.h"
#include "../include/crypto_utils.h"

// --- Configurazione Server ---
int setup_server(int port) {
    int server_fd;
    struct sockaddr_in server_addr;
    int opt = 1;

    // Crea il socket TCP
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Errore: Creazione socket server fallita");
        return -1;
    }

    // Evita l'errore "Address already in use" se riavvii il server velocemente
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Avviso: setsockopt SO_REUSEADDR fallita");
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Accetta connessioni su tutte le interfacce
    server_addr.sin_port = htons(port);

    // Associa il socket alla porta
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Errore: Bind fallita");
        close(server_fd);
        return -1;
    }

    // Mette il server in ascolto (coda di massimo 10 connessioni pendenti)
    if (listen(server_fd, 10) < 0) {
        perror("Errore: Listen fallita");
        close(server_fd);
        return -1;
    }

    return server_fd;
}

// --- Configurazione Client ---
int connect_to_server(const char *ip, int port) {
    int sock_fd;
    struct sockaddr_in server_addr;

    if ((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Errore: Creazione socket client fallita");
        return -1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Converte l'indirizzo IP da stringa a formato binario
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        perror("Errore: Indirizzo IP non valido o non supportato");
        close(sock_fd);
        return -1;
    }

    // Tenta la connessione
    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Errore: Connessione al server fallita");
        close(sock_fd);
        return -1;
    }

    return sock_fd;
}

// --- Invio Robusto ---
ssize_t send_full(int sockfd, const void *buf, size_t len) {
    size_t total_sent = 0;
    const char *buffer = (const char *)buf;

    while (total_sent < len) {
        ssize_t bytes_sent = send(sockfd, buffer + total_sent, len - total_sent, 0);
        if (bytes_sent <= 0) {
            // Errore di rete o connessione chiusa
            return bytes_sent; 
        }
        total_sent += bytes_sent;
    }
    return total_sent;
}

// --- Lettura Robusta ---
ssize_t recv_full(int sockfd, void *buf, size_t len) {
    size_t total_received = 0;
    char *buffer = (char *)buf;

    while (total_received < len) {
        ssize_t bytes_received = recv(sockfd, buffer + total_received, len - total_received, 0);
        if (bytes_received <= 0) {
            // Errore di rete o connessione chiusa dall'altra parte
            return bytes_received; 
        }
        total_received += bytes_received;
    }
    return total_received;
}


// --- Invio Sicuro ---
ssize_t send_secure(int sockfd, const void *data, size_t data_len, const unsigned char *aes_key, uint32_t *tx_seq) {
    SecureHeader header;
    
    // 1. Convertiamo seq e len in formato Network (Big Endian) per la massima compatibilità
    header.sequence_number = htonl(*tx_seq);
    header.ciphertext_len = htonl((uint32_t)data_len);
    
    if (generate_nonce(header.iv, AES_IV_SIZE) != 0) return -1;

    unsigned char *ciphertext = malloc(data_len);
    if (!ciphertext) return -1;

    // 2. Prepariamo l'AAD concatenando i due campi in chiaro della header (8 byte in totale)
    unsigned char aad[8];
    memcpy(aad, &header.sequence_number, 4);
    memcpy(aad + 4, &header.ciphertext_len, 4);

    int c_len = encrypt_aes_gcm((const unsigned char *)data, data_len, aad, sizeof(aad), aes_key, header.iv, ciphertext, header.tag);
    if (c_len < 0) { free(ciphertext); return -1; }

    // 3. Spediamo busta e payload
    if (send_full(sockfd, &header, sizeof(SecureHeader)) <= 0) { free(ciphertext); return -1; }
    ssize_t sent = send_full(sockfd, ciphertext, c_len);
    free(ciphertext);

    // 4. Incrementiamo il contatore di trasmissione
    (*tx_seq)++;
    return sent;
}

// --- Ricezione Sicura ---
ssize_t recv_secure(int sockfd, void *buffer, size_t max_len, const unsigned char *aes_key, uint32_t *expected_rx_seq) {
    SecureHeader header;

    if (recv_full(sockfd, &header, sizeof(SecureHeader)) <= 0) return -1;

    // 1. Riconvertiamo seq e len nel formato Host (processore locale)
    uint32_t seq_host = ntohl(header.sequence_number);
    uint32_t len_host = ntohl(header.ciphertext_len);

    // 2. CONTROLLO ANTI-REPLAY
    // Se il sequence number non è esattamente quello che ci aspettiamo, è un attacco o un desync!
    if (seq_host != *expected_rx_seq) {
        fprintf(stderr, "\n[!!! MINACCIA RILEVATA !!!] Replay Attack o pacchetto fuori sequenza! Atteso: %u, Ricevuto: %u\n", *expected_rx_seq, seq_host);
        return -1;
    }

    if (len_host > max_len) return -1;

    unsigned char *ciphertext = malloc(len_host);
    if (!ciphertext) return -1;
    if (recv_full(sockfd, ciphertext, len_host) <= 0) { free(ciphertext); return -1; }

    // 3. Ricostruiamo lo stesso AAD per permettere la decifratura
    unsigned char aad[8];
    memcpy(aad, &header.sequence_number, 4);
    memcpy(aad + 4, &header.ciphertext_len, 4);

    int plaintext_len = decrypt_aes_gcm(ciphertext, len_host, aad, sizeof(aad), header.tag, aes_key, header.iv, (unsigned char *)buffer);
    free(ciphertext);

    if (plaintext_len < 0) return -1;

    // 4. Se la decifratura va a buon fine, il pacchetto è autentico. Incrementiamo il contatore atteso!
    (*expected_rx_seq)++;
    return plaintext_len;
}