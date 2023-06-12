#ifndef SECUREBANK_CLIENT_H
#define SECUREBANK_CLIENT_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <termios.h>
#include <ctype.h>
#include <dirent.h>

#define PORT	 8080               // Server's port
#define COMMANDS 5                  // Number of commands available
#define MAX_TRANSACTIONS 1000       // Max Number of transactions
#define COMMAND_PREFIX '!'          // Prefix of commands
#define BUFFER_SIZE 1024
#define MAX_KEY_SIZE 2048
#define HMAC_SIZE 32
#define NONCE_SIZE 16


/* Server's structure */
struct server_info {
    EVP_PKEY* serverPublicKey;
    int server_sock;
};

/* Transaction Structure */
typedef struct {
    int transaction_id;
    char account_number[20];
    double amount;
    time_t timestamp;
    // Altri campi pertinenti
} Transaction;

/* Transaction Table */
typedef struct {
    Transaction* transactions;
    int transaction_count;
    // Altri campi della tabella hash
} TransactionTable;


/* User Informations */
typedef struct {
    int port;
    char nome[BUFFER_SIZE];
    char cognome[BUFFER_SIZE];
    char username[BUFFER_SIZE];
    char password[BUFFER_SIZE];
    float balance;
    EVP_PKEY **pubKey;
    TransactionTable transaction_table;
} PeerInfo;

typedef int (*cmd_executor)(char* arg);

/* File Descriptor */
fd_set master;
fd_set read_fds;
int fdmax;

/* Server Descriptor */
struct server_info *server;
int server_sock = 0;
EVP_PKEY* serverPublicKey = NULL;

/* Diffie-Hellman parameters */
unsigned char* shared_secret;

/* If the communication is encrypted */
int crypted = 0;

/* If user is registered */
int registered = 0;

/* Number of transactions done by the user */
int numTransaction = 0;

/* Paths to private/public key */
const unsigned char pathPrivK[BUFFER_SIZE];
const unsigned char pathPubK[BUFFER_SIZE];

PeerInfo *mySelf;

unsigned char keyStore[BUFFER_SIZE];

const char* valid_cmds[] = {"sendMoney", "showBalance", "deposit","history", "stop"};

const char* help_msg =
        "\n\n   ****************************************** HOME ******************************************\n\n"
        "\t!sendMoney           <DEST> <AMOUNT>     --> invia il denaro all'utente dest di amount con la virgola\n"
        "\t!showBalance                             --> aggiunge una tupla al register corrente\n"
        "\t!deposit             <AMOUNT>            --> ricarica il conto\n"
        "\t!history                                 --> visualizza la storia passata delle transazioni\n"
        "\t!stop                                    --> disconnette il peer dal network\n\n\n";



#endif //SECUREBANK_CLIENT_H