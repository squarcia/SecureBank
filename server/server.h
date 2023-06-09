#ifndef SECUREBANK_SERVER_H
#define SECUREBANK_SERVER_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <dirent.h>

#define PORT	    8080
#define MAX_KEY_SIZE 2048
#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024
#define HMAC_SIZE 32
#define NONCE_SIZE 16
#define COMMANDS 5
#define COMMAND_PREFIX '!'

/* User Informations */
typedef struct peerInfo {
    int socket;
    char nome[1024];
    char cognome[1024];
    char username[1024];
    char password[1024];
    float balance;

    EVP_PKEY **pubKey;
} PeerInfo;

typedef struct {
    PeerInfo* value;
    struct Entry* next;
} Entry;

typedef struct {
    Entry* head;
} EntryList;

typedef int (*cmd_executor)(char* arg);

/* Paths to Private/Public keys */
unsigned char pathPubK[1024];
unsigned char pathPrivK[1024];

/* List of the users registered */
EntryList *peerList;

/* Diffie-Hellman Parameters */
unsigned char* shared_secret;

/* If the communication is encrypted */
int crypted = 0;



#endif //SECUREBANK_SERVER_H
