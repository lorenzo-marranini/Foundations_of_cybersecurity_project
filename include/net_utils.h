#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>

// Avvia un server TCP in ascolto su una porta specifica e restituisce il socket_fd
int setup_server(int port);

// Connette il client a un server specificato da IP e porta e restituisce il socket_fd
int connect_to_server(const char *ip, int port);

// Assicura che tutti i 'len' byte vengano inviati sul socket
ssize_t send_full(int sockfd, const void *buf, size_t len);

// Assicura che esattamente 'len' byte vengano letti dal socket
ssize_t recv_full(int sockfd, void *buf, size_t len);

// Invia dati cifrati e autenticati tramite AES-256-GCM
ssize_t send_secure(int sockfd, const void *data, size_t data_len, const unsigned char *aes_key, uint32_t *tx_seq);

// Riceve e decifra dati, verificandone l'integrità. Restituisce la lunghezza in chiaro o -1 in caso di manomissione.
ssize_t recv_secure(int sockfd, void *buffer, size_t max_len, const unsigned char *aes_key, uint32_t *expected_rx_seq);

#endif // NET_UTILS_H