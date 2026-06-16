# Compilatore e flag di compilazione
CC = gcc
CFLAGS = -Wall -Wextra -g -I./include
# Librerie da linkare (OpenSSL per crittografia, pthreads se serviranno thread)
LDFLAGS = -lssl -lcrypto -lpthread

# Cartelle
SRC_DIR = src

# File sorgente condivisi
COMMON_SRCS = $(SRC_DIR)/crypto_utils.c $(SRC_DIR)/net_utils.c $(SRC_DIR)/cJSON.c $(SRC_DIR)/db_utils.c

# Target di default: compila tutto
all: server client reset_db

# Regola per compilare il server
server: $(SRC_DIR)/server.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Regola per compilare il client
client: $(SRC_DIR)/client.c $(COMMON_SRCS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Regola per resettare il DB Users
reset_db:
	@echo "--- Ripristino database in corso ---"
	cp db/users_backup.json db/users.json
	@chmod 644 db/users.json
	@echo "--- Database resettato ai valori iniziali ---"

# Regola per pulire i file compilati
clean:
	rm -f server client