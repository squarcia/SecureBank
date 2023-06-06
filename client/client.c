#define MAXLINE 1024
#define PORT	 8080
#define COMMANDS 6
#define MAX_TRANSACTIONS 1000
#define COMMAND_PREFIX '!'
#define DELIM " "
#define BUFFER_SIZE 1024
#define KEY_LENGTH 16
#define BUFFER_SIZE 1024
#define MAX_KEY_SIZE 2048
#define HMAC_SIZE 32
#define NONCE_SIZE 16

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
#include <dirent.h>


struct register_info {

    char data[1024];
    char filename[1024];
    int chiuso;
    struct register_info *next;
};

struct peer_info {
    int port;
    struct register_info *register_list;
    char dataRemota[1024];

    double amount;
    char *recipient;

    int left_peer;
    int right_peer;
};

struct user {
    char *name;
    char *surname;
    char *username;
    char *password;
};

struct server_info {
    EVP_PKEY* serverPublicKey;
    struct sockaddr_in serv_addr;
    int server_sock;
};

struct socket_info {
    int socket;
    int peer_left;
};

struct map {
    int peer;
    char **dates_sent;
    char **dates_received;

    int sent;
    int received;
};

typedef struct {
    int transaction_id;
    char account_number[20];
    double amount;
    time_t timestamp;
    // Altri campi pertinenti
} Transaction;

typedef struct {
    Transaction* transactions;
    int transaction_count;
    // Altri campi della tabella hash
} TransactionTable;

typedef struct {
    int port;
    char dataRemota[1024];
    char nome[1024];
    char cognome[1024];
    char username[1024];
    char password[1024];
    float balance;
    EVP_PKEY **pubKey;
    TransactionTable transaction_table;
} PeerInfo;


typedef int (*cmd_executor)(char* arg, struct peer_info *peer);


int numRegister = 0;
int registered = 0;


/* Verifica di connessione al server */
int started;

/* Verifica la login al server */
int logged;

/* File Descriptor */
fd_set master;
fd_set read_fds;
int fdmax;

int server_sock = 0;

/* Diffie-Hellman parameters */
unsigned char* shared_secret;

/* Socket */
int listener;
int newfd;

int crypted = 0;
int registered;

int periodoAnalisi;

EVP_PKEY* serverPublicKey;

const unsigned char pathPrivK[1024];
const unsigned char pathPubK[1024];

PeerInfo *mySelf;

/* Conta il numero di register creati */
int numRegister;

/* Verifica se è stata inviata o meno la richiesta di FLOODING */
int canCalculate;

/* Variabile per gestione entry*/
struct map **entry_engine;

/* Variabile che mi traccia il numero di peers aggiunti  */
int numPeers;

const char *types[] = {"TAMPONE", "NUOVO_CASO"};

const char* valid_cmds[] = {"register", "login", "start", "add", "get", "stop"};

const char* help_msg =
        "\n\n   ****************************************** PEER ******************************************\n\n"
        "\t!register    <DS_addr> <DS_port>          --> effettua la registrazione al network\n"
        "\t!login       <DS_addr> <DS_port>          --> effettua il login al network\n"
        "\t!start       <DS_addr> <DS_port>          --> effettua la connessione al network\n"
        "\t!add         <type> <quantity>            --> aggiunge una tupla al register corrente\n"
        "\t!get         <aggr> <type> <period>       --> effettua una richiesta di elaborazione\n"
        "\t!stop                                     --> disconnette il peer dal network\n\n\n";

void getData(char *buffer, int giorno_dopo) {
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    sprintf(buffer, "%d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday + giorno_dopo);
}

void getHour(char *buffer) {
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    sprintf(buffer, "%02d\n", tm.tm_hour);
}


void inserisciRegistro(struct register_info *item, struct peer_info *peer) {

    struct register_info *current_node = peer->register_list;

    if (current_node == NULL) {

        peer->register_list = item;
    }else {

        while(current_node->next != NULL) {
            current_node = current_node->next;
        }
        current_node->next = item;
    }

    numRegister++;
}

void add(int port, const char* dataRemota, const char* nome, const char* cognome, const char* username, const char* password, float balance) {

    strncpy(mySelf->nome, nome, sizeof(mySelf->nome));
    strncpy(mySelf->cognome, cognome, sizeof(mySelf->cognome));
    strncpy(mySelf->username, username, sizeof(mySelf->username));
    strncpy(mySelf->password, password, sizeof(mySelf->password));
    mySelf->balance = balance;
    printf("Nuovo peer aggiunto con successo\n");
}

void addTransaction(Transaction transaction) {
    if (mySelf->transaction_table.transaction_count >= MAX_TRANSACTIONS) {
        printf("Numero massimo di transazioni raggiunto\n");
        return;
    }

    // Aggiungi la transazione alla tabella hash delle transazioni
    mySelf->transaction_table.transactions[mySelf->transaction_table.transaction_count] = transaction;
    mySelf->transaction_table.transaction_count++;

    printf("Nuova transazione aggiunta con successo\n");
}

Transaction* getTransaction(int transaction_id) {
    for (int i = 0; i < mySelf->transaction_table.transaction_count; i++) {
        if (mySelf->transaction_table.transactions[i].transaction_id == transaction_id) {
            return &mySelf->transaction_table.transactions[i];
        }
    }
}

void printDate(time_t currentTime) {

    // Converti il timestamp in una struttura tm
    struct tm* timeinfo = localtime(&currentTime);

    // Formatta la data nel formato desiderato
    char formattedTime[50];
    strftime(formattedTime, sizeof(formattedTime), "%Y-%m-%d %H:%M:%S", timeinfo);

    // Stampa la data formattata
    printf("Data e ora correnti: %s\n", formattedTime);
}


void printAllTransactions(const TransactionTable * object) {
    printf("Transazioni dell'oggetto:\n");

    for (int i = 0; i < object->transaction_count; i++) {
        const Transaction* transaction = &(object->transactions[i]);

        printf("Transazione %d:\n", i+1);
        printf("ID: %s\n", transaction->account_number);
        printf("Amount: %f€\n", transaction->amount);
        printDate(transaction->timestamp);

        printf("\n");
    }
}

Transaction createTransaction(int trans_id, const char* account_num, float amount) {

    // Creazione e inserimento di una nuova transazione
    Transaction newTransaction;
    newTransaction.transaction_id = mySelf->transaction_table.transaction_count;
    strcpy(newTransaction.account_number, "ABC123");
    newTransaction.amount = 500.0;

    // Imposta la data di oggi come timestamp
    time_t currentTime = time(NULL);
    newTransaction.timestamp = currentTime;

    return newTransaction;
}

void verifyTime(struct peer_info *peer, int chiusura_forzata) {

    char *hour, *data, *today, *filename;
    int hours = 0;

    struct register_info *register_item;
    struct register_info *current_node = peer->register_list;

    /* Allocazione */
    hour = (char *) malloc(MAXLINE);
    data = (char *) malloc(MAXLINE);
    filename = (char *) malloc(MAXLINE);
    today = (char *) malloc(MAXLINE);

    register_item = (struct register_info *) malloc(sizeof(struct register_info));

    /* Pulizia */
    memset(hour, 0, MAXLINE);
    memset(data, 0, MAXLINE);
    memset(filename, 0, MAXLINE);
    memset(register_item, 0, sizeof(struct register_info));

    /* Ricavo ora corrente */
    getHour(hour);
    hours = atoi(hour);

    getData(today, 0);

    while (current_node->next != NULL) {
        current_node = current_node->next;
    }

    /* Il register corrente viene chiuso nei seguenti casi:

        1)      Sono passate le 18:00 del giorno corrente
        2)      Il DS ha richiesto la chiusura immediata

    */

    if ((strcmp(current_node->data, today) == 0 && hours >= 00) || chiusura_forzata) {

        printf("\t\t\t\t      [  REGISTER CHIUSO  ]\n\n");

        /* Mi ricavo la data del prossimo register */
        getData(data, numRegister);

        /* Serializzo */
        sprintf(filename, "register/%s_%d.txt", data, peer->port);

        strcpy(register_item->filename, filename);
        strcpy(register_item->data, data);

        fopen(filename, "a+");

        register_item->chiuso = 0;
        register_item->next = NULL;

        /* Chiudo register corrente */
        current_node->chiuso = 1;

        inserisciRegistro(register_item, peer);

        printf("\t\t\t\t   [  NUOVO REGISTER APERTO  ]\n\n\n\n");
    }
}

void print_hex(const unsigned char* data, size_t data_len, const unsigned char* title) {

    printf("%s:\t", title);

    for (size_t i = 0; i < data_len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

void sendPublicKeyWith4(int socket, EVP_PKEY* publicKey) {
    // Ottieni la dimensione del buffer necessario per la serializzazione
    int bufferSize = i2d_PUBKEY(publicKey, NULL);
    if (bufferSize < 0) {
        perror("Failed to get buffer size for public key");
        return;
    }

    // Alloca il buffer per la serializzazione
    unsigned char* buffer = (unsigned char*)malloc(bufferSize + 1);
    if (buffer == NULL) {
        perror("Failed to allocate memory for public key serialization");
        return;
    }

    // Serializza la chiave pubblica nel buffer
    unsigned char* bufferPtr = buffer + 1;  // Sposta il puntatore in avanti di un byte
    int result = i2d_PUBKEY(publicKey, &bufferPtr);
    if (result < 0) {
        perror("Failed to serialize public key");
        free(buffer);
        return;
    }

    // Assegna il valore 4 al primo byte del buffer
    buffer[0] = '4';

    // Invia i dati della chiave pubblica sul socket
    result = send(socket, buffer, bufferSize + 1, 0);
    if (result < 0) {
        perror("Failed to send public key");
        free(buffer);
        return;
    }

    free(buffer);
}


void printEvpKey(EVP_PKEY *key) {
    printf("CISONO\n");
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        // Error handling
        return;
    }

    if (!PEM_write_bio_PUBKEY(bio, key)) {
        // Error handling
        BIO_free(bio);
        return;
    }

    char *KeyStr = NULL;
    long KeyLen = BIO_get_mem_data(bio, &KeyStr);
    if (KeyLen > 0) {
        printf("Public Key:\n%s\n", KeyStr);
    }

    BIO_free(bio);
}

void printPrivateKey(const EVP_PKEY* privateKey) {
    if (privateKey == NULL) {
        printf("Invalid private key\n");
        return;
    }

    BIO* bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        printf("Error creating BIO\n");
        return;
    }

    if (!PEM_write_bio_PrivateKey(bio, privateKey, NULL, NULL, 0, NULL, NULL)) {
        printf("Error writing private key\n");
        BIO_free(bio);
        return;
    }

    char buffer[1024];
    int bytesRead;
    while ((bytesRead = BIO_gets(bio, buffer, sizeof(buffer))) > 0) {
        printf("%s", buffer);
    }

    BIO_free(bio);
}


EVP_PKEY* readPublicKeyFromPEM(const char* filename) {
    EVP_PKEY* publicKey = NULL;
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open file");
        return NULL;
    }

    PEM_read_PUBKEY(file, &publicKey, NULL, NULL);

    fclose(file);
    return publicKey;
}

EVP_PKEY* readPrivateKeyFromPEM(const char* filename) {
    EVP_PKEY* privateKey = NULL;
    FILE* file = fopen(filename, "r");
    if (file == NULL) {
        perror("Failed to open file");
        return NULL;
    }

    privateKey = PEM_read_PrivateKey(file, NULL, NULL, NULL);

    fclose(file);
    return privateKey;
}


EVP_PKEY* generate_keypair(const char* private_key_file, const char* public_key_file) {
    EVP_PKEY* keypair = NULL;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    FILE* private_key_fp = NULL;
    FILE* public_key_fp = NULL;

    if (ctx == NULL) {
        fprintf(stderr, "Failed to create EVP_PKEY_CTX\n");
        return NULL;
    }

    // Initialize the key generation context
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        fprintf(stderr, "Failed to initialize EVP_PKEY_CTX\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // Set the RSA key size
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        fprintf(stderr, "Failed to set RSA key size\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    // Generate the key pair
    if (EVP_PKEY_keygen(ctx, &keypair) <= 0) {
        fprintf(stderr, "Failed to generate key pair\n");
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);

    // Save the private key to file
    private_key_fp = fopen(private_key_file, "wb");
    if (private_key_fp == NULL) {
        fprintf(stderr, "Failed to open private key file\n");
        EVP_PKEY_free(keypair);
        return NULL;
    }
    if (PEM_write_PrivateKey(private_key_fp, keypair, NULL, NULL, 0, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to write private key\n");
        EVP_PKEY_free(keypair);
        fclose(private_key_fp);
        return NULL;
    }
    fclose(private_key_fp);

    // Save the public key to file
    public_key_fp = fopen(public_key_file, "wb");
    if (public_key_fp == NULL) {
        fprintf(stderr, "Failed to open public key file\n");
        EVP_PKEY_free(keypair);
        return NULL;
    }
    if (PEM_write_PUBKEY(public_key_fp, keypair) != 1) {
        fprintf(stderr, "Failed to write public key\n");
        EVP_PKEY_free(keypair);
        fclose(public_key_fp);
        return NULL;
    }
    fclose(public_key_fp);

    EVP_PKEY* server_pubkey = readPublicKeyFromPEM(public_key_file);
    if (server_pubkey == NULL) {
        printf("Failed to read public key from file\n");
        return NULL;
    }

    EVP_PKEY* server_privkey = readPrivateKeyFromPEM(private_key_file);
    if (server_privkey == NULL) {
        printf("Failed to read private key from file\n");
        return NULL;
    }

    // printPrivateKey(server_privkey);

    return keypair;
}
/*
int verify_signature(const unsigned char* message, size_t message_length, const unsigned char* signature, size_t signature_length) {
    // Calcola l'hash del messaggio originale
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(message, message_length, hash);

    // Crea un contesto di verifica della firma
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        perror("Failed to create signature verification context");
        return 0;
    }

    // Inizializza il contesto di verifica della firma con la chiave pubblica
    if (EVP_VerifyInit(ctx, EVP_sha256()) != 1) {
        perror("Failed to initialize signature verification context");
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    // Aggiungi l'hash del messaggio al contesto di verifica della firma
    if (EVP_VerifyUpdate(ctx, hash, SHA256_DIGEST_LENGTH) != 1) {
        perror("Failed to update signature verification context");
        EVP_MD_CTX_free(ctx);
        return 0;
    }

    printEvpKey(serverPublicKey);

    // Verifica la firma utilizzando la chiave pubblica
    int result = EVP_VerifyFinal(ctx, signature, signature_length, serverPublicKey);

    // Pulisci il contesto di verifica della firma
    EVP_MD_CTX_free(ctx);

    return result;
}
 */
/*
int receive_signed_message(int socket, unsigned char** message, size_t* message_length, unsigned char** signature, size_t* signature_length) {

    int result;

    // Dimensione massima del buffer per il messaggio firmato
    size_t max_length = BUFFER_SIZE + 256;

    // Alloca un buffer per il messaggio firmato
    unsigned char* signed_message = (unsigned char*)malloc(max_length);
    if (signed_message == NULL) {
        perror("Failed to allocate memory for signed message");
        return -1;
    }

    // Ricevi il messaggio firmato dal socket
    ssize_t bytes_received = recv(socket, signed_message, max_length, 0);
    if (bytes_received < 0) {
        perror("Failed to receive signed message");
        free(signed_message);
        return -1;
    }

    // Assegna la lunghezza totale del messaggio firmato
    size_t total_length = (size_t)bytes_received;

    // Assegna la lunghezza della firma (supponendo che sia fissa)
    *signature_length = 256;

    // Assegna la lunghezza del messaggio
    *message_length = total_length - *signature_length;

    // Alloca il buffer per la firma
    *signature = (unsigned char*)malloc(*signature_length);
    if (*signature == NULL) {
        perror("Failed to allocate memory for signature");
        free(signed_message);
        return -1;
    }

    // Alloca il buffer per il messaggio
    *message = (unsigned char*)malloc(*message_length);
    if (*message == NULL) {
        perror("Failed to allocate memory for message");
        free(*signature);
        free(signed_message);
        return -1;
    }

    // Copia la firma dal messaggio firmato
    memcpy(*signature, signed_message, *signature_length);

    // Copia il messaggio dal messaggio firmato
    memcpy(*message, signed_message + *signature_length, *message_length);

    print_hex(*message, *message_length, "ENCRYPTED MESSAGE");

    result = verify_signature(*message, *message_length, *signature, *signature_length);

    return result;
}
*/


// Funzione per verificare la firma di un messaggio
int verify_signature(const unsigned char* message, size_t message_length, const unsigned char* signature, size_t signature_length,  EVP_PKEY* public_key) {

    // Crea il contesto per la verifica della firma
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        perror("Failed to create EVP_MD_CTX");
        EVP_PKEY_free(public_key);
        return -1;
    }

    // Inizializza il contesto con la chiave pubblica
    int result = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, public_key);
    if (result != 1) {
        perror("Failed to initialize EVP_DigestVerifyInit");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(public_key);
        return -1;
    }

    // Verifica la firma del messaggio
    result = EVP_DigestVerify(ctx, signature, signature_length, message, message_length);
    if (result != 1) {
        printf("Signature verification failed\n");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(public_key);
        return -1;
    }

    printf("Signature verification succeeded\n");

    // Pulizia delle risorse
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(public_key);

    return 1;
}


int receive_signed_message(int socket, unsigned char** message, size_t* message_length, unsigned char** signature, size_t* signature_length, const char* public_key_path) {
    int result;

    // Dimensione massima del buffer per il messaggio firmato
    size_t max_length = BUFFER_SIZE + 256;

    // Alloca un buffer per il messaggio firmato
    unsigned char* signed_message = (unsigned char*)malloc(max_length);
    if (signed_message == NULL) {
        perror("Failed to allocate memory for signed message");
        return -1;
    }

    // Ricevi il messaggio firmato dal socket
    ssize_t bytes_received = recv(socket, signed_message, max_length, 0);
    if (bytes_received < 0) {
        perror("Failed to receive signed message");
        free(signed_message);
        return -1;
    }

    // Assegna la lunghezza totale del messaggio firmato
    size_t total_length = (size_t)bytes_received;

    // Assegna la lunghezza della firma (supponendo che sia fissa)
    *signature_length = 256;

    // Assegna la lunghezza del messaggio
    *message_length = total_length - *signature_length;

    // Alloca il buffer per la firma
    *signature = (unsigned char*)malloc(*signature_length);
    if (*signature == NULL) {
        perror("Failed to allocate memory for signature");
        free(signed_message);
        return -1;
    }

    // Alloca il buffer per il messaggio
    *message = (unsigned char*)malloc(*message_length);
    if (*message == NULL) {
        perror("Failed to allocate memory for message");
        free(*signature);
        free(signed_message);
        return -1;
    }

    // Copia la firma dal messaggio firmato
    memcpy(*signature, signed_message, *signature_length);

    // Copia il messaggio dal messaggio firmato
    memcpy(*message, signed_message + *signature_length, *message_length);

    // Verifica la firma del messaggio
    result = verify_signature(*message, *message_length, *signature, *signature_length, public_key_path);

    printf("\nResult: %d", result);


    // Libera la memoria
    free(signed_message);

    return result;
}


int register_executor() {

    char *nome,
            *cognome,
            *username,
            *password;

    int balance = 0;
    char answer;

    nome = malloc(sizeof(char) * 20);
    printf("Nome:[] ");
    scanf("%s", nome);

    cognome = malloc(sizeof(char)*20);
    printf("Cognome:[] ");
    scanf("%s", cognome);

    username = malloc(sizeof(char)*20);
    printf("Username:[] ");
    scanf("%s", username);

    password = malloc(sizeof(char)*30);
    printf("Password:[] ");
    scanf("%s", password);

    printf("Nome: %s\nCognome: %s\nUsername: %s\nPassword: %sBalance: %d\n", nome, cognome, username, password, balance);

    printf("Are the information correct? (Y/n) ");
    scanf("%s", &answer);

    char folderpath[256];

    if (strcmp("Y", &answer) == 0 || strcmp("y", &answer) == 0) {

        memcpy(mySelf->nome, nome, strlen(nome) + 1);
        memcpy(mySelf->cognome, cognome, strlen(cognome) + 1);
        memcpy(mySelf->username, username, strlen(username) + 1);
        memcpy(mySelf->password, password, strlen(password) + 1);

        /* Scrivere il testo cifrato su file */
        /* Per ora lo scrivamo senza cifratura, DA MODIFICARE*/
        const char *directory = "../client/registered";
        const char *filename = username;

        // Concatenate the directory and filename to form the full file path

        snprintf(folderpath, sizeof(folderpath), "%s/%s", directory, filename);

        printf("FOLDERPATH: %s\n", folderpath);

        int result = mkdir(folderpath, 0777);

        if (result == 0)
        {
            printf("Directory created successfully: %s\n", directory);
        }
        else
        {
            fprintf(stderr, "Error creating the directory.\n");
            return -1;
        }

        char filepath[256];
        snprintf(filepath, sizeof(filepath), "%s/%s", folderpath, filename);

        // Determina la dimensione del buffer necessaria
        int buffer_size = snprintf(NULL, 0, "%s:%s:%s:%s", nome, cognome, username, password);
        if (buffer_size < 0)
        {
            fprintf(stderr, "Errore durante la determinazione della dimensione del buffer.\n");
            return -1;
        }

        // Incrementa la dimensione per includere il carattere terminatore di stringa
        buffer_size++;

        // Alloca il buffer dinamicamente
        char *buffer = (char *)malloc(buffer_size * sizeof(char));
        if (buffer == NULL)
        {
            fprintf(stderr, "Errore durante l'allocazione del buffer.\n");
            return -1;
        }

        // Scrivi la stringa formattata nel buffer
        result = snprintf(buffer, buffer_size, "%s:%s:%s:%s", nome, cognome, username, password);
        if (result < 0 || result >= buffer_size)
        {
            fprintf(stderr, "Errore durante la scrittura nel buffer.\n");
            free(buffer);
            return -1;
        }

        if (result < 0 || result >= buffer_size)
        {
            fprintf(stderr, "Errore durante la scrittura nel buffer.\n");
            free(buffer);
            return -1;
        }

        // Apri il file in modalità scrittura
        FILE *file = fopen(filepath, "w");
        if (file == NULL)
        {
            fprintf(stderr, "Impossibile aprire il file %s.\n", filename);
            return -1;
        }

        // Scrivi il testo sul file
        if (fputs(buffer, file) == EOF)
        {
            fprintf(stderr, "Errore durante la scrittura sul file %s.\n", filename);
            fclose(file);
            return -1;
        }

        // Chiudi il file
        fclose(file);

        printf("Il testo è stato scritto su file con successo.\n");
    }

    // Genero la mia coppia di chiavi private e pubbliche

    snprintf(pathPrivK, sizeof(pathPrivK), "%s/%s", folderpath, "private_key");
    snprintf(pathPubK, sizeof(pathPubK), "%s/%s", folderpath, "public_key");

    generate_keypair(pathPrivK, pathPubK);
}

struct user* readInformationsUser(const char* filename) {

    // Apri il file in modalità lettura
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        fprintf(stderr, "Impossibile aprire il file %s.\n", filename);
        return NULL;
    }

    // Leggi il file riga per riga utilizzando fgets
    char buffer[256];
    fgets(buffer, sizeof(buffer), file);

    const char delimiter[] = ":";

    // Tokenize the string
    //char *token = strtok(buffer, delimiter);

    struct user *usr = (struct user*)malloc(sizeof(struct user));

    usr->name = strtok(buffer, delimiter);
    usr->surname = strtok(NULL, delimiter);
    usr->username = strtok(NULL, delimiter);
    usr->password = strtok(NULL, delimiter);

    memcpy(mySelf->nome, usr->name, strlen(usr->name) + 1);
    memcpy(mySelf->cognome, usr->surname, strlen(usr->surname) + 1);
    memcpy(mySelf->username, usr->username, strlen(usr->username) + 1);
    memcpy(mySelf->password, usr->password, strlen(usr->password) + 1);

    printf("%s\n", mySelf->password);

    // Chiudi il file
    fclose(file);

    return usr;
}

int checkExistingUser(const char* username, const char* pwd) {

    const char* directoryPath = "../client/registered"; // Specifica il percorso della cartella
    const char* searchString = username; // Stringa da confrontare con i nomi dei file

    char path[1024];
    snprintf(path, sizeof(path), "%s/%s/%s", directoryPath, username, username);
    printf("PATH: %s\n", path);

    FILE* file = fopen(path, "r");
    if (file == NULL) {
        perror("Errore nell'apertura del file");
        return 0;
    }

    // Leggi il file riga per riga utilizzando fgets
    char buffer[256];
    fgets(buffer, sizeof(buffer), file);

    const char delimiter[] = ":";

    strncpy(mySelf->nome, strtok(buffer, delimiter), BUFFER_SIZE);
    strncpy(mySelf->cognome, strtok(NULL, delimiter), BUFFER_SIZE);
    strncpy(mySelf->username, strtok(NULL, delimiter), BUFFER_SIZE);
    strncpy(mySelf->password, strtok(NULL, delimiter), BUFFER_SIZE);

    printf("Name: %s\n", mySelf->nome);
    printf("Surname: %s\n", mySelf->cognome);
    printf("Username: %s\n", mySelf->username);
    printf("Password: %s\n", mySelf->password);

    if (!strcmp(username, mySelf->username) && !strcmp(pwd, mySelf->password)) {
        printf("Informazioni corrette, grant access\n");
        // Chiudi il file
        fclose(file);
        return 1;
    }
}



void print_help(){
    printf("%s", help_msg);
}

int _parse_command(char* line, size_t line_len, char** cmd, char** arg){
    if (line[line_len - 1] == '\n'){
        line[line_len - 1] = 0;
        --line_len;
    }

    if (line_len == 1)
        return -1;

    /* line + 1 excludes '!' */
    *cmd = strtok(line + 1, " ");
    *arg = (*cmd + strlen(*cmd) + 1);
    return 0;
}


void sendMessage(int socket, unsigned char *buffer, int buffer_len)
{
    int bytes_sent = send(socket, buffer, buffer_len, 0);
    if (bytes_sent < 0)
    {
        perror("Error sending message");
        exit(1);
    }
}

void handle_error(const char* error_message) {
    fprintf(stderr, "Error occurred: %s\n", error_message);
    exit(1);
}

EVP_PKEY* convertToPublicKey(unsigned char* buffer, int bufferSize) {
    // Alloca un puntatore temporaneo per il buffer
    unsigned char* bufferPtr = buffer;

    // Converte i dati del buffer nella chiave pubblica
    EVP_PKEY* publicKey = d2i_PUBKEY(NULL, (const unsigned char**)&bufferPtr, bufferSize);
    if (publicKey == NULL) {
        perror("Failed to convert data to public key");
        return NULL;
    }

    return publicKey;
}


void calculate_hmac(const unsigned char* data, size_t data_len, const unsigned char* key, size_t key_len, unsigned char* hmac) {
    HMAC_CTX* ctx = HMAC_CTX_new();
    if (ctx == NULL) {
        handle_error("Failed to create HMAC context");
    }

    if (HMAC_Init_ex(ctx, shared_secret, strlen(shared_secret), EVP_sha256(), NULL) != 1) {
        handle_error("Failed to initialize HMAC");
    }

    //print_hex(data, data_len, "INSIDE HMAC CALC");

    if (HMAC_Update(ctx, data, data_len) != 1) {
        handle_error("Failed to update HMAC");
    }

    unsigned int hmac_len = HMAC_SIZE;
    if (HMAC_Final(ctx, hmac, &hmac_len) != 1) {
        handle_error("Failed to finalize HMAC");
    }

    //print_hex(hmac, hmac_len, "HMAC FINAL");

    HMAC_CTX_free(ctx);
}

size_t encrypt_message(const unsigned char* plaintext, size_t plaintext_len, unsigned char* ciphertext) {
    // Generate a random IV
    unsigned char iv[16];
    if (RAND_bytes(iv, 16) != 1) {
        handle_error("Failed to generate IV");
    }
    //print_hex(iv, 16, "IV");
    // Generate a random nonce
    unsigned char nonce[16];
    if (RAND_bytes(nonce, 16) != 1) {
        handle_error("Failed to generate nonce");
    }
    //print_hex(nonce, 16, "NONCE");
    // Create an encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        handle_error("Failed to create encryption context");
    }

    // Initialize the encryption operation with the IV
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, shared_secret, iv) != 1) {
        handle_error("Failed to initialize encryption operation");
    }

    // Provide the plaintext to be encrypted
    int ciphertext_len;
    if (EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext, plaintext_len) != 1) {
        handle_error("Failed to encrypt plaintext");
    }

    // Finalize the encryption operation
    int final_len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len) != 1) {
        handle_error("Failed to finalize encryption operation");
    }
    ciphertext_len += final_len;

    // Calculate HMAC for the ciphertext
    unsigned char hmac[32];
    //print_hex(ciphertext, ciphertext_len, "CIPHERTEXT");
    calculate_hmac(ciphertext, ciphertext_len, shared_secret, strlen(shared_secret), hmac);
    //print_hex(hmac, 32, "HMAC");

    // Prepare the final message by concatenating IV, nonce, ciphertext, and HMAC
    memcpy(ciphertext + ciphertext_len, iv, AES_BLOCK_SIZE);
    ciphertext_len += 16;
    memcpy(ciphertext + ciphertext_len, nonce, NONCE_SIZE);
    ciphertext_len += 16;
    memcpy(ciphertext + ciphertext_len, hmac, HMAC_SIZE);
    ciphertext_len += 32;

    // Clean up the encryption context
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int extract_values(const unsigned char* ciphertext, size_t ciphertext_len, unsigned char* iv, unsigned char* nonce, unsigned char* hmac, const unsigned char* key, size_t key_len) {
    size_t iv_offset = ciphertext_len - 16 - NONCE_SIZE - HMAC_SIZE;
    size_t nonce_offset = ciphertext_len - NONCE_SIZE - HMAC_SIZE;
    size_t hmac_offset = ciphertext_len - HMAC_SIZE;

    memcpy(iv, ciphertext + iv_offset, 16);
    //print_hex(iv, 16, "IV Val");
    memcpy(nonce, ciphertext + nonce_offset, NONCE_SIZE);
    //print_hex(nonce, NONCE_SIZE, "NONCE Val");
    memcpy(hmac, ciphertext + hmac_offset, HMAC_SIZE);

    unsigned char* ciphertext_only = (unsigned char*)malloc(ciphertext_len - 64);
    memcpy(ciphertext_only, ciphertext, ciphertext_len - 64);
    //print_hex(ciphertext_only, strlen(ciphertext_only), "CIPHERTEXT_ONLY");

    // Calculate the expected HMAC of the ciphertext
    unsigned char expected_hmac[32];
    calculate_hmac(ciphertext_only, ciphertext_len - 64, key, key_len, expected_hmac);

    //print_hex(hmac, 32, "HMAC");
    //print_hex(expected_hmac, 32, "EXPECTED HMAC");

    // Confronto tra l'HMAC ricevuto e l'HMAC calcolato
    int result = 0;
    if (strlen(hmac) == strlen(expected_hmac)) {
        result = CRYPTO_memcmp(hmac, expected_hmac, strlen(hmac));
    }

    return result;
}

size_t decrypt_message(const unsigned char* ciphertext, size_t ciphertext_len, unsigned char* plaintext) {

    //print_hex(ciphertext, ciphertext_len, "ENCRYPTED_TEXT");

    // Extract the IV from the ciphertext
    unsigned char iv[16];
    // Extract the nonce from the ciphertext
    unsigned char nonce[16];
    // Extract the HMAC from the ciphertext
    unsigned char hmac[32];

    int res = extract_values(ciphertext, ciphertext_len, iv, nonce, hmac, shared_secret, strlen(shared_secret));
    if (res != 0) {
        handle_error("HMAC NON VALIDO");
    }

    // Create a decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        handle_error("Failed to create decryption context");
    }

    // Initialize the decryption operation with the IV
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, shared_secret, iv) != 1) {
        handle_error("Failed to initialize decryption operation");
    }

    // Provide the ciphertext to be decrypted
    int plaintext_len;
    if (EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len - 16 - 16 - 32) != 1) {
        handle_error("Failed to decrypt ciphertext");
    }

    // Finalize the decryption operation
    int final_len;
    if (EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &final_len) != 1) {
        handle_error("Failed to finalize decryption operation");
    }
    plaintext_len += final_len;

    // Clean up the decryption context
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void updateBalance() {

    // send request to receive updated balance
    // Message to be sent
    const char* msg = "7";
    size_t msg_len = strlen(msg);

    // Buffer to hold the encrypted message
    unsigned char en_message[1024];
    size_t en_message_len;

    // Encrypt the message
    en_message_len = encrypt_message((const unsigned char*)msg, msg_len, en_message);

    sendMessage(server_sock, en_message, en_message_len);

    sleep(2);

    // Ricevi il messaggio firmato
    unsigned char* rec;
    size_t rec_l;
    unsigned char* rec_s;
    size_t rec_s_l;
    unsigned char* decrypted_message;

    int signatureValid = receive_signed_message(server_sock, &rec, &rec_l, &rec_s, &rec_s_l, serverPublicKey);

    print_hex(rec_s, rec_s_l, "SIGNATURE RESPONSE");
    printf("DOPO FIRMA: %d", signatureValid);

    if (signatureValid) {

        printf("The message is correctly signed!\n\n");

        // Decrypt the message
        int decrypted_message_len = decrypt_message(rec, rec_l, decrypted_message);

        // Print the decrypted message
        printf("Balance updated: %s\n", decrypted_message);
    }

}

void seeBalance() {
    updateBalance();
    printf("Balance: %f", mySelf->balance);
}

int stop_executor(char* arg, struct peer_info *peer) {

    //seeBalance();
    printAllTransactions(&mySelf->transaction_table);

}


DH* create_dh_params()
{
    DH* dh = DH_new();
    if (dh == NULL) {
        handle_error("Failed to create DH object");
    }

    // Set the prime (p)
    BIGNUM* p = BN_new();
    if (!BN_hex2bn(&p, "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                       "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF")) {
        handle_error("Failed to set prime (p)");
    }

    // Set the generator (g)
    BIGNUM* g = BN_new();
    if (!BN_set_word(g, 2)) {
        handle_error("Failed to set generator (g)");
    }

    // Set the prime (p) and generator (g) for DH object
    if (!DH_set0_pqg(dh, p, NULL, g)) {
        handle_error("Failed to set DH parameters");
    }

    return dh;
}

void send_signed_message(int socket, const unsigned char* message, size_t message_length, const unsigned char* signature, size_t signature_length) {
    // Calcola la dimensione totale del buffer per il messaggio firmato
    size_t total_length = message_length + signature_length;

    // Alloca un buffer per il messaggio firmato
    unsigned char* signed_message = (unsigned char*)malloc(total_length);
    if (signed_message == NULL) {
        perror("Failed to allocate memory for signed message");
        return;
    }

    // Copia la firma nel buffer del messaggio firmato
    memcpy(signed_message, signature, signature_length);

    // Copia il messaggio nel buffer del messaggio firmato
    memcpy(signed_message + signature_length, message, message_length);

    // Invia il messaggio firmato sul socket
    ssize_t bytes_sent = send(socket, signed_message, total_length, 0);
    if (bytes_sent < 0) {
        perror("Failed to send signed message");
    }

    // Libera la memoria allocata per il messaggio firmato
    free(signed_message);
}
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

int sign_message(const unsigned char* message, size_t message_length, const char* private_key_path, unsigned char** signature, size_t* signature_length) {
    // Carica la chiave privata da un file PEM
    FILE* private_key_file = fopen(private_key_path, "rb");
    if (private_key_file == NULL) {
        perror("Failed to open private key file");
        return -1;
    }

    EVP_PKEY* private_key = PEM_read_PrivateKey(private_key_file, NULL, NULL, NULL);
    fclose(private_key_file);
    if (private_key == NULL) {
        perror("Failed to read private key");
        return -1;
    }

    // Crea il contesto per la firma
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        perror("Failed to create signature context");
        EVP_PKEY_free(private_key);
        return -1;
    }

    // Inizializza il contesto per la firma con la chiave privata
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, private_key) != 1) {
        perror("Failed to initialize signature");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }

    // Firma il messaggio
    if (EVP_DigestSignUpdate(ctx, message, message_length) != 1) {
        perror("Failed to update signature");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }

    // Ottieni la dimensione della firma
    if (EVP_DigestSignFinal(ctx, NULL, signature_length) != 1) {
        perror("Failed to get signature length");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }

    // Alloca il buffer per la firma
    *signature = (unsigned char*)malloc(*signature_length);
    if (*signature == NULL) {
        perror("Failed to allocate memory for signature");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }

    // Esegui la firma effettiva
    if (EVP_DigestSignFinal(ctx, *signature, signature_length) != 1) {
        perror("Failed to sign message");
        free(*signature);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }

    // Liberare le risorse
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(private_key);

    return 0;
}



/*
ssize_t signMessage(const unsigned char* encrypted_message, size_t encrypted_message_len, unsigned char* signature) {

    EVP_PKEY *privKey = readPrivateKeyFromPEM(pathPrivK);

    printPrivateKey(privKey);

    // Calcola l'hash del messaggio cifrato

    unsigned char message_hash[SHA256_DIGEST_LENGTH];
    SHA256(encrypted_message, encrypted_message_len, message_hash);

    // Crea un contesto di firma
    EVP_MD_CTX* sign_ctx = EVP_MD_CTX_new();
    if (sign_ctx == NULL) {
        fprintf(stderr, "Errore nella creazione del contesto di firma\n");
        EVP_PKEY_free(privKey);
        return 0;
    }

    // Inizializza l'operazione di firma
    if (EVP_DigestSignInit(sign_ctx, NULL, EVP_sha256(), NULL, privKey) != 1) {
        fprintf(stderr, "Errore nell'inizializzazione dell'operazione di firma\n");
        EVP_PKEY_free(privKey);
        EVP_MD_CTX_free(sign_ctx);
        return 0;
    }

    // Aggiungi l'hash del messaggio cifrato all'operazione di firma
    if (EVP_DigestSignUpdate(sign_ctx, message_hash, SHA256_DIGEST_LENGTH) != 1) {
        fprintf(stderr, "Errore nell'aggiunta dell'hash al contesto di firma\n");
        EVP_PKEY_free(privKey);
        EVP_MD_CTX_free(sign_ctx);
        return 0;
    }

    // Determina la dimensione della firma digitale
    size_t signature_size;
    if (EVP_DigestSignFinal(sign_ctx, NULL, &signature_size) != 1) {
        fprintf(stderr, "Errore nel calcolo della dimensione della firma\n");
        EVP_PKEY_free(privKey);
        EVP_MD_CTX_free(sign_ctx);
        return 0;
    }

    // Alloca memoria per la firma digitale
    if (signature == NULL) {
        fprintf(stderr, "Errore nell'allocazione di memoria per la firma\n");
        EVP_PKEY_free(privKey);
        EVP_MD_CTX_free(sign_ctx);
        return 0;
    }

    // Esegui la firma digitale
    if (EVP_DigestSignFinal(sign_ctx, signature, &signature_size) != 1) {
        fprintf(stderr, "Errore nella firma digitale\n");
        EVP_PKEY_free(privKey);
        EVP_MD_CTX_free(sign_ctx);
        return 0;
    }

    print_hex(signature, signature_size, "SIGNATURE");

    return signature_size;
}
*/
int saveTransaction(unsigned char* received, ssize_t rec_len, unsigned char* transaction) {

    unsigned char decrypted_message[1024];
    size_t decrypted_message_len;

    decrypted_message_len = decrypt_message(received, rec_len, decrypted_message);
    printf("Msg: %s", decrypted_message);

    if(!strcmp(decrypted_message, "OK Va bene")) {

        char* name = NULL;
        char* amount = NULL;

        // Primo token
        char* token = strtok(transaction, " ");
        if (token != NULL) {
            name = strdup(token);
        }

        // Secondo token
        token = strtok(NULL, " ");
        if (token != NULL) {
            amount = strdup(token);
        }

        // Stampa dei token ottenuti
        printf("Token1: %s\n", name);
        printf("Token2: %s\n", amount);

        int amountOfMoney = atoi(amount);

        Transaction t = createTransaction(0, name, amountOfMoney);
        addTransaction(t);
        printf("TRANSAZIONE SALVATA CON SUCCESSO!\n\n");
        return 1;

    } else {
        printf("TRANSAZIONE FALLITA!\n\n");
        return -1;
    }
}

void sendPublicKey(int socket, EVP_PKEY* publicKey) {


    // Ottieni la dimensione del buffer necessario per la serializzazione
    int bufferSize = i2d_PUBKEY(publicKey, NULL);
    if (bufferSize < 0) {
        perror("Failed to get buffer size for public key");
        return;
    }

    // Alloca il buffer per la serializzazione
    unsigned char* buffer = (unsigned char*)malloc(bufferSize);
    if (buffer == NULL) {
        perror("Failed to allocate memory for public key serialization");
        return;
    }

    // Serializza la chiave pubblica nel buffer
    unsigned char* bufferPtr = buffer;
    int result = i2d_PUBKEY(publicKey, &bufferPtr);
    if (result < 0) {
        perror("Failed to serialize public key");
        free(buffer);
        return;
    }

    // Invia i dati della chiave pubblica sul socket
    result = send(socket, buffer, bufferSize, 0);
    if (result < 0) {
        perror("Failed to send public key");
        free(buffer);
        return;
    }

    free(buffer);
}

// Funzione per inviare soldi a un'altra persona
int start_executor(char* message, struct peer_info *peer) {

    // Message to be sent
    unsigned char* msg = "9";
    size_t msg_len = strlen(msg);

    // Buffer to hold the encrypted message
    unsigned char en_message[1024];
    size_t en_message_len;

    // Encrypt the message
    en_message_len = encrypt_message(msg, msg_len, en_message);

    sendMessage(server_sock, en_message, en_message_len);

    sleep(2);

    // Message to be sent
    size_t message_len = strlen(message);

    // Buffer to hold the encrypted message
    unsigned char encrypted_message[1024];
    size_t encrypted_message_len;

    // Encrypt the message
    encrypted_message_len = encrypt_message((const unsigned char*)message, message_len, encrypted_message);

    // Variabili per la firma
    unsigned char* signature = NULL;
    size_t signature_length = 0;

    // Firma il messaggio
    int result = sign_message(encrypted_message, encrypted_message_len, pathPrivK, &signature, &signature_length);
    if (result != 0) {
        fprintf(stderr, "Failed to sign the message\n");
        return 1;
    }
    print_hex(signature, signature_length, "FIRMA");

    send_signed_message(server_sock, encrypted_message, encrypted_message_len, signature, signature_length);


    // Ricevi il messaggio firmato
    unsigned char* rec;
    size_t rec_l;
    unsigned char* rec_s;
    size_t rec_s_l;
    printf("\n\n\nReceive public key\n\n\n");
    printEvpKey(serverPublicKey);
    int signatureValid = receive_signed_message(server_sock, &rec, &rec_l, &rec_s, &rec_s_l, serverPublicKey);

    print_hex(rec_s, rec_s_l, "SIGNATURE RESPONSE");
    printf("DOPO FIRMA: %d", signatureValid);

    int r = saveTransaction(rec, rec_l, message);

    if (r == 1) {
        Transaction *t1 = getTransaction(0);
        printDate(t1->timestamp);
    }

    return 1;

}

void initializePaths() {

    char folderpath[256];

    const char *directory = "../client/registered";
    const char *filename = mySelf->username;

    snprintf(folderpath, sizeof(folderpath), "%s/%s", directory, filename);

    snprintf(pathPrivK, sizeof(pathPrivK), "%s/%s", folderpath, "private_key");
    snprintf(pathPubK, sizeof(pathPubK), "%s/%s", folderpath, "public_key");

    //EVP_PKEY *privKey = readPrivateKeyFromPEM(pathPrivK);

    //printPrivateKey(privKey);

    mySelf->pubKey = readPublicKeyFromPEM(pathPubK);
    printEvpKey((EVP_PKEY *) mySelf->pubKey);
}

// Funzione per inviare soldi a un'altra persona
int ssend(char* message, int socket) {

    // Message to be sent
    size_t message_len = strlen(message);

    // Buffer to hold the encrypted message
    unsigned char encrypted_message[1024];
    size_t encrypted_message_len;

    // Encrypt the message
    encrypted_message_len = encrypt_message((const unsigned char*)message, message_len, encrypted_message);

    print_hex(encrypted_message, encrypted_message_len, "ENCRYPTED MESSAGE");
    sleep(2);

    unsigned char *signature = BIO_f_null;
    size_t signature_size;
    //signature_size = signMessage(encrypted_message, encrypted_message_len, signature);
    print_hex(signature, signature_size, "SIGNATURE");
    // Invia il messaggio firmato
    send_signed_message(socket, encrypted_message, encrypted_message_len, signature, signature_size);
}

int add_executor() {

    EVP_PKEY *privKey = readPrivateKeyFromPEM(pathPrivK);

    // Message to be sent
    const char* msg = "8";
    size_t msg_len = strlen(msg);

    // Buffer to hold the encrypted message
    unsigned char en_message[1024];
    size_t en_message_len;

    // Encrypt the message
    en_message_len = encrypt_message((const unsigned char*)msg, msg_len, en_message);

    sendMessage(server_sock, en_message, en_message_len);

    sleep(5);

    // Calcola la lunghezza totale della stringa da inviare
    int stringLength = snprintf(NULL, 0, "%s:%s:%s:%s:%f", mySelf->nome, mySelf->cognome,
                                mySelf->username, mySelf->password, mySelf->balance);

    // Alloca memoria per la stringa risultante
    char* message = malloc((stringLength + 1) * sizeof(char));

    // Costruisci la stringa formattata
    sprintf(message, "%s:%s:%s:%s:%f", mySelf->nome, mySelf->cognome,
            mySelf->username, mySelf->password, mySelf->balance);


    // Buffer to hold the encrypted message
    unsigned char encrypted_message[1024];
    size_t encrypted_message_len;

    // Encrypt the message
    encrypted_message_len = encrypt_message((const unsigned char*)message, stringLength, encrypted_message);

    unsigned char* signature;
    size_t signature_size;
    //signature_size = signMessage(encrypted_message, encrypted_message_len, signature);

    // Invia il messaggio firmato
    send_signed_message(server_sock, encrypted_message, encrypted_message_len, signature, signature_size);
}

int login_executor(char* arg, struct peer_info *peer) {

    const char delimiter[] = " ";
    char *username = strtok(arg, delimiter);
    char *password = strtok(NULL, delimiter);

    if (checkExistingUser(username, username)) {
        printf("\nInformation retrieved successfully\n");
        logged = 1;
        initializePaths();
    }
}

int get_executor() {

    unsigned char* diffieMessage = "2Diffie";
    sendMessage(server_sock, diffieMessage, strlen(diffieMessage));

    // Start diffie hellman exchange

    // Create DH parameters
    DH* dh = create_dh_params();

    // Generate private and public keys
    if (!DH_generate_key(dh)) {
        handle_error("Failed to generate DH keys");
    }

    // Send public key (pub_key) to the server

    // Get the public key
    const BIGNUM* client_pub_key = NULL;
    DH_get0_key(dh, &client_pub_key, NULL);

    // Convert the public key to a byte array
    size_t client_pub_key_len = BN_num_bytes(client_pub_key);
    unsigned char* client_pub_key_data = (unsigned char*)malloc(client_pub_key_len);
    if (client_pub_key_data == NULL) {
        handle_error("Failed to allocate memory for public key data");
    }

    BN_bn2bin(client_pub_key, client_pub_key_data);

    // Send the public key to the server
    if (send(server_sock, client_pub_key_data, client_pub_key_len, 0) == -1) {
        handle_error("Failed to send public key to server");
    }

    // Receive the server's public key (server_pub_key)

    unsigned char server_pub_key_data[MAX_KEY_SIZE];  // Adjust the buffer size accordingly
    int server_received_len = recv(server_sock, server_pub_key_data, sizeof(server_pub_key_data), 0);
    if (server_received_len <= 0) {
        handle_error("Failed to receive public key from server");
    }

    // Create a BIGNUM from the received public key data
    BIGNUM* server_pub_key = BN_bin2bn(server_pub_key_data, server_received_len, NULL);
    if (server_pub_key == NULL) {
        handle_error("Failed to create BIGNUM from public key data");
    }

    // Set the received public key in the DH object
    DH_set0_key(dh, server_pub_key, NULL);

    // Compute the shared secret
    shared_secret = (unsigned char*)malloc(DH_size(dh));
    if (shared_secret == NULL) {
        handle_error("Failed to allocate memory for shared secret");
    }
    int shared_secret_len = DH_compute_key(shared_secret, server_pub_key, dh);

    // Print the shared secret
    printf("Shared Secret: ");
    for (size_t i = 0; i < shared_secret_len; i++) {
        printf("%02X", shared_secret[i]);
    }
    printf("\n");

    // Use the shared secret for further communication

    // Buffer to hold the encrypted message
    unsigned char encrypted_message[1024];

    // Buffer to hold the decrypted message
    unsigned char decrypted_message[1024];
    size_t decrypted_message_len;

    size_t encrypted_message_len = recv(server_sock, encrypted_message, sizeof(encrypted_message), 0);

    // Decrypt the message
    decrypted_message_len = decrypt_message(encrypted_message, encrypted_message_len, decrypted_message);

    // Print the decrypted message
    printf("Decrypted Message: %.*s\n", (int)decrypted_message_len, decrypted_message);

}


int verifySelfSignedCertificate(const char* certFile) {
    // Load the self-signed certificate from file
    FILE* fp = fopen(certFile, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open certificate file\n");
        return 0;
    }
    X509* cert = PEM_read_X509(fp, NULL, NULL, NULL);
    fclose(fp);

    if (cert == NULL) {
        fprintf(stderr, "Failed to read certificate\n");
        return 0;
    }

    // Create a certificate store and add the self-signed certificate to it
    X509_STORE* store = X509_STORE_new();
    if (store == NULL) {
        fprintf(stderr, "Failed to create certificate store\n");
        X509_free(cert);
        return 0;
    }

    if (X509_STORE_add_cert(store, cert) != 1) {
        fprintf(stderr, "Failed to add certificate to store\n");
        X509_free(cert);
        X509_STORE_free(store);
        return 0;
    }

    // Create a verification context and initialize it with the store, certificate, and no chain
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "Failed to create verification context\n");
        X509_free(cert);
        X509_STORE_free(store);
        return 0;
    }

    X509_STORE_CTX_init(ctx, store, cert, NULL);

    // Perform the certificate verification
    int result = X509_verify_cert(ctx);
    if (result != 1) {
        fprintf(stderr, "Certificate verification failed\n");
    } else {
        printf("Certificate verification succeeded\n");
    }

    // Cleanup
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);

    return result;
}

// Funzione per nascondere l'input dell'utente
void hideInput() {
    struct termios term;
    tcgetattr(fileno(stdin), &term);
    term.c_lflag &= ~ECHO;
    tcsetattr(fileno(stdin), TCSANOW, &term);
}

// Funzione per mostrare l'input dell'utente
void showInput() {
    struct termios term;
    tcgetattr(fileno(stdin), &term);
    term.c_lflag |= ECHO;
    tcsetattr(fileno(stdin), TCSANOW, &term);
}

void sendEncryptedPublicKey(int socket, EVP_PKEY* publicKey) {
    // Get the public key size
    int publicKeySize = i2d_PUBKEY(publicKey, NULL);
    if (publicKeySize < 0) {
        perror("Failed to get public key size");
        return;
    }

    // Allocate memory for the public key buffer
    unsigned char* publicKeyBuffer = (unsigned char*)malloc(publicKeySize);
    if (publicKeyBuffer == NULL) {
        perror("Failed to allocate memory for public key");
        return;
    }

    // Serialize the public key into the buffer
    unsigned char* publicKeyPtr = publicKeyBuffer;
    int result = i2d_PUBKEY(publicKey, &publicKeyPtr);
    if (result < 0) {
        perror("Failed to serialize public key");
        free(publicKeyBuffer);
        return;
    }

    // Encrypt the public key
    unsigned char encryptedPublicKey[1024];  // Adjust the buffer size as needed
    size_t encryptedSize = encrypt_message(publicKeyBuffer, publicKeySize, encryptedPublicKey);

    // Send the encrypted public key over the socket
    result = send(socket, encryptedPublicKey, encryptedSize, 0);
    if (result < 0) {
        perror("Failed to send encrypted public key");
        free(publicKeyBuffer);
        return;
    }

    printf("Bytes sent: %d", result);

    free(publicKeyBuffer);
}


void sendPubKey() {
    // Invio la mia public key al server cifrata
    // Message to be sent
    const char* msg = "6";
    size_t msg_len = strlen(msg);

    // Buffer to hold the encrypted message
    unsigned char en_message[1024];
    size_t en_message_len;

    // Encrypt the message
    en_message_len = encrypt_message((const unsigned char*)msg, msg_len, en_message);

    sendMessage(server_sock, en_message, en_message_len);

    sleep(5);

    EVP_PKEY *pubKey = readPublicKeyFromPEM(pathPubK);

    // Converti la chiave pubblica del server in formato PEM
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pubKey);

    // Ottieni i dati dalla memoria BIO
    char* pubkey_data;
    size_t pubkey_len = BIO_get_mem_data(bio, &pubkey_data);

    sendEncryptedPublicKey(server_sock, pubKey);
    printf("Public key sent!\n %s", pubkey_data);

}

void startEngine(struct peer_info *peer, struct register_info *register_item, struct server_info *server) {

    unsigned char *message;
    char buffer[BUFFER_SIZE] = {0};
    int valread;
    struct sockaddr_in serv_addr;

    /* Allocazione memoria */
    peer = (struct peer_info *) malloc(sizeof(struct peer_info));
    register_item = (struct register_info *) malloc(sizeof(struct register_info));
    peer->register_list = (struct register_info *) malloc(sizeof(struct register_info));

    /* Allocazione memoria per server informazioni */
    server = (struct server_info *) malloc(sizeof(struct server_info));

    /* Inizializzazione */
    peer->register_list = NULL;
    peer->port = 1024;

    // Allocazione della variabile PeerInfo
    mySelf = malloc(sizeof(PeerInfo));
    if (mySelf == NULL) {
        perror("Errore nell'allocazione di PeerInfo");
        return;
    }
    // Inizializza la tabella hash delle transazioni
    mySelf->transaction_table.transactions = malloc(MAX_TRANSACTIONS * sizeof(Transaction));
    mySelf->transaction_table.transaction_count = 0;

    // Creazione del socket
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Errore nella creazione del socket");
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Conversione dell'indirizzo IP da stringa a formato binario
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Indirizzo non valido / errore di conversione");
        return;
    }

    // Connessione al server
    if (connect(server_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connessione fallita");
        return;
    }

    server->serv_addr = serv_addr;
    server->server_sock = server_sock;

    /* Verify the identity of the server */
    verifySelfSignedCertificate("../server/certificate.pem");


    // Verifico che il peer sia registrato
    char answer;
    printf("Sei registrato correttamente? [Y/n] ");
    scanf(" %c", &answer);

    if (answer == 'Y' || answer == 'y') {
        printf("Prego loggarsi correttamente\n");

        char username[50];
        char password[50];

        printf("Inserisci il nome utente: ");
        scanf("%s", username);

        printf("Inserisci la password: ");
        hideInput(); // Nascondi l'input dell'utente
        scanf("%s", password);
        showInput(); // Mostra di nuovo l'input dell'utente

        printf("\nNome utente: %s\n", username);
        printf("Password: %s\n", password);

        // Concatenazione di username e password con uno spazio
        char credentials[100];
        strcpy(credentials, username);
        strcat(credentials, " ");
        strcat(credentials, password);

        printf("Credentials: %s", credentials);

        login_executor(credentials, peer);
        registered = 1;

    } else if (answer == 'N' || answer == 'n') {
        printf("Per favore registrati.\n");
        register_executor();
    } else {
        printf("Risposta non valida.\n");
    }

    // Calcola la lunghezza totale della stringa da inviare
    int stringLength = snprintf(NULL, 0, "1:%s", mySelf->nome);

    // Alloca memoria per la stringa risultante
    message = malloc((stringLength + 1) * sizeof(char));

    // Costruisci la stringa formattata
    sprintf(message, "1:%s", mySelf->nome);

    // Invio del messaggio al server
    send(server->server_sock, message, stringLength, 0);

    /* Ricezione della chiave pubblica */
    // Ricevi i dati della chiave pubblica dal server tramite il socket
    unsigned char receivedBuffer[BUFFER_SIZE];  // Definisci la dimensione massima del buffer
    int receivedSize = recv(server->server_sock, receivedBuffer, sizeof(receivedBuffer), 0);
    //int receivedSize = read(server_sock, receivedBuffer, BUFFER_SIZE);
    if (receivedSize <= 0) {
        perror("Failed to receive public key");
        return;
    }

    // Converti i dati ricevuti nella chiave pubblica del server
    serverPublicKey = convertToPublicKey(receivedBuffer, receivedSize);
    if (serverPublicKey == NULL) {
        printf("Failed to convert received data to public key\n");
        return;
    }

    printEvpKey(serverPublicKey);

    sleep(5);

    get_executor();

    sendPubKey();

}

cmd_executor executors[] = {
        *register_executor,
        *login_executor,
        *start_executor,
        *add_executor,
        *get_executor,
        *stop_executor
};

int process_command(const char* cmd, char* arg, struct peer_info *peer) {

    int i, ris;

    for (i = 0; i < COMMANDS; ++i){
        if (strcmp(cmd, valid_cmds[i]) == 0){
            ris = executors[i](arg, peer);
            if (ris == -2){
                perror("Errore di comunicazione con il server");
                return -1;
            }
            return ris;
        }
    }

    /* Invalid command */
    printf("Error: comando non trovato\n");
    return 1;
}

int _handle_cmd(struct peer_info *peer) {

    char* buf = NULL;
    size_t buf_len = 0;
    char* cmd = NULL;
    char* arg = NULL;
    int ris;

    buf_len = getline(&buf, &buf_len, stdin);

    if (buf_len > 0 && buf[0] != COMMAND_PREFIX) {
        printf("Errore: i comandi devono iniziare con '%c'\n", COMMAND_PREFIX);
        free(buf);
        return -1;
    }

    if (_parse_command(buf, buf_len, &cmd, &arg) == -1) {
        /* line contains only '!' */
        printf("Errore: comando non specificato\n");
        free(buf);
        return -1;
    }
    /*

    if (strlen(arg) == 0 && strcmp(cmd, "stop") != 0) {
        printf("\n\n\n\t\t***** COMANDO NON VALIDO: INSERIMENTO PARAMETRI NECESSARIO. *****\n\n\n");
        return -1;
    }

    if (!started && strcmp(cmd, "start") != 0) {
        printf("\n\n\n\t\t***** COMANDO NON VALIDO: CONNESSIONE AL SERVER RICHIESTA. *****\n\n\n");
        return -1;
    }
    */

    ris = process_command(cmd, arg, peer);
    free(buf);
    return ris;
}

int main() {

    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    int ret, i, addrlen, listener, left, right;
    char *token, *signal;

    struct peer_info *peer;
    struct register_info *register_item;
    struct server_info *server;

    /* Buffer di ricezione/appoggio/appoggio */
    char bufferRicezione[MAXLINE],
            bufferCopy[MAXLINE],
            bufferNeighbor[MAXLINE];

    /* Struttura indirizzo server/client */
    struct sockaddr_in my_addr, cl_addr;

    startEngine((struct peer_info *) &peer, (struct register_info *) &register_item, server);

    /* Reset dei descrittori */
    FD_ZERO(&master);
    FD_ZERO(&read_fds);

    /* Aggiungo il File Descriptor dello STD-INPUT ai socket monitorati */
    FD_SET(STDIN_FILENO, &master);
    FD_SET(server_sock, &master);

    fdmax = (server_sock > STDIN_FILENO) ? server_sock : STDIN_FILENO;

    while(1) {

        print_help();

        read_fds = master;

        select(fdmax + 1, &read_fds, NULL, NULL, NULL);
        for (i=0; i<=fdmax; i++) {

            if(FD_ISSET(i, &read_fds)) {

                if (i == STDIN_FILENO) {
                    _handle_cmd(peer);
                }
            }
        }
    }
}
