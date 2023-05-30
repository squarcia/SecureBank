#define MAXLINE 1024
#define PORT	 8080
#define COMMANDS 6


#define COMMAND_PREFIX '!'
#define DELIM " "
#define DELIM_NEIGHBOR ":"

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
#include <dirent.h>
#include <openssl/aes.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#define BUFFER_SIZE 1024
#define KEY_LENGTH 16
#define BUFFER_SIZE 1024
#define MAX_KEY_SIZE 2048
#define MAX_MESSAGE_SIZE 1460
#define HMAC_SIZE 32
#define IV_SIZE 16

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

typedef int (*cmd_executor)(char* arg, struct peer_info *peer);


int numRegister = 0;


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

int periodoAnalisi;

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

int add_executor(char* arg, struct peer_info *peer) {

    char *token, *quantity, *type;
    char *entry;
    char *date;
    FILE *fp;

    struct register_info *temp = peer->register_list;

    printf("\n\n\n\t\t\t  **********   ADD EXECUTOR RUNNING   **********\n\n");

    /* Verifico se posso inserire la nuova entry nel register corrente */
    verifyTime(peer, 0);

    /* Scorro fino all'ultimo elemento della lista */
    while (temp->next!= NULL)
        temp = temp->next;

    /* Ricavo il tipo */
    token=strtok(arg, DELIM);
    type = token;

    /* Ricavo la quantità */
    token=strtok(NULL, DELIM);
    quantity = token;

    /* Confronto il tipo inserito con le due costanti TAMPONE e NUOVO_CASO */
    if (strcmp(type, types[0]) != 0 && strcmp(type, types[1]) != 0) {
        printf("Errore, tipo non valido!");
        return -1;
    }

    printf("  TYPE :        [  %s  ]\n\n", type);
    printf("  QUANTITY :    [  %s  ]\n\n", quantity);

    /* Allocazione memoria */
    entry = (char *) malloc(MAXLINE);
    date = (char *) malloc(MAXLINE);

    /* Pulizia */
    memset(entry, 0, MAXLINE);
    memset(date, 0, MAXLINE);

    /* Mi ricavo la data in base al numero di register già inseriti */
    getData(date, numRegister - 1);

    printf("  DATA :        [  %s  ]\n\n", date);
    printf("  FILE :        [  %s  ]\n\n", temp->filename);

    /* Serializzazione */
    sprintf(entry, "%s,%s,%s.\n",date, type, quantity);

    /* Gestione del file */
    fp = fopen(temp->filename, "a+");
    fprintf(fp, "%s", entry);
    fclose(fp);

    printf("\n\n\t\t\t       [  NUOVO ENTRY INSERITA CON SUCCESSO!  ]\n\n");

    /* Deallocazione */
    free(entry);
    free(date);

    return 0;
}


int stop_executor(char* arg, struct peer_info *peer) {
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

    if (strcmp("Y", &answer) == 0 || strcmp("y", &answer) == 0) {

        /* Scrivere il testo cifrato su file */
        /* Per ora lo scrivamo senza cifratura, DA MODIFICARE*/

        const char *directory = "./registered";
        const char *filename = username;

        // Concatenate the directory and filename to form the full file path
        char folderpath[256];
        snprintf(folderpath, sizeof(folderpath), "%s/%s", directory, filename);

        printf("FOLDERPATH: %s", folderpath);

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

    printf("%s\n", usr->password);

    // Chiudi il file
    fclose(file);

    return usr;
}

int checkExistingUser(const char* username, const char* pwd) {

    const char* directoryPath = "./registered"; // Specifica il percorso della cartella
    const char* searchString = username; // Stringa da confrontare con i nomi dei file

    DIR* directory = opendir(directoryPath);
    if (directory == NULL) {
        printf("Impossibile aprire la directory.\n");
        return 1;
    }

    struct dirent* entry;
    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_type == DT_REG) { // Controlla solo i file regolari
            if (strcmp(entry->d_name, searchString) == 0) {
                printf("\nTrovato il file corrispondente: %s\n", entry->d_name);

                /* Read the informations of the user */
                struct user *existingUser = readInformationsUser(entry->d_name);

                if (strcmp(existingUser->password, pwd) == 0) {
                    printf("Password corretta, welcome!\n");

                }

                return 1;
            }
        }
    }

    closedir(directory);

    return 0;

}

int login_executor(char* arg, struct peer_info *peer) {

    const char delimiter[] = " ";
    char *username = strtok(arg, delimiter);
    char *password = strtok(NULL, delimiter);

    if (checkExistingUser(username, password)) {
        printf("\nInformation retrieved successfully\n");
        logged = 1;
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

void handle_error() {
    fprintf(stderr, "Error occurred\n");
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

    if (HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), NULL) != 1) {
        handle_error("Failed to initialize HMAC");
    }

    if (HMAC_Update(ctx, data, data_len) != 1) {
        handle_error("Failed to update HMAC");
    }

    unsigned int hmac_len = HMAC_SIZE;
    if (HMAC_Final(ctx, hmac, &hmac_len) != 1) {
        handle_error("Failed to finalize HMAC");
    }

    HMAC_CTX_free(ctx);
}

size_t encrypt_message(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* key, size_t key_len, unsigned char* ciphertext) {
    // Generate a random IV
    unsigned char iv[AES_BLOCK_SIZE];
    if (RAND_bytes(iv, AES_BLOCK_SIZE) != 1) {
        handle_error("Failed to generate IV");
    }

    // Create an encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        handle_error("Failed to create encryption context");
    }

    // Initialize the encryption operation with the IV
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
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

    // Clean up the encryption context
    EVP_CIPHER_CTX_free(ctx);

    // Calculate HMAC for the ciphertext
    unsigned char hmac[HMAC_SIZE];
    calculate_hmac(ciphertext, ciphertext_len, key, key_len, hmac);

    // Prepare the final message by concatenating IV, ciphertext, and HMAC
    memcpy(ciphertext + ciphertext_len, iv, AES_BLOCK_SIZE);
    ciphertext_len += AES_BLOCK_SIZE;
    memcpy(ciphertext + ciphertext_len, hmac, HMAC_SIZE);
    ciphertext_len += HMAC_SIZE;

    return ciphertext_len;
}

size_t decrypt_message(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* key, size_t key_len, unsigned char* plaintext) {
    // Extract the IV from the ciphertext
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, ciphertext + ciphertext_len - IV_SIZE - HMAC_SIZE, IV_SIZE);

    // Extract the HMAC from the ciphertext
    unsigned char hmac[HMAC_SIZE];
    memcpy(hmac, ciphertext + ciphertext_len - HMAC_SIZE, HMAC_SIZE);

    // Calculate the expected HMAC of the ciphertext
    unsigned char expected_hmac[HMAC_SIZE];
    calculate_hmac(ciphertext, ciphertext_len - IV_SIZE - HMAC_SIZE, key, key_len, expected_hmac);

    // Verify the HMAC
    if (memcmp(hmac, expected_hmac, HMAC_SIZE) != 0) {
        handle_error("HMAC verification failed");
    }

    // Create a decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        handle_error("Failed to create decryption context");
    }

    // Initialize the decryption operation with the IV
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        handle_error("Failed to initialize decryption operation");
    }

    // Provide the ciphertext to be decrypted
    int plaintext_len;
    if (EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len - IV_SIZE - HMAC_SIZE) != 1) {
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

int get_executor() {

    unsigned char* diffieMessage = "2:Diffie";
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
    decrypted_message_len = decrypt_message(encrypted_message, encrypted_message_len, shared_secret, strlen((const char*)shared_secret), decrypted_message);

    // Print the decrypted message
    printf("Decrypted Message: %.*s\n", (int)decrypted_message_len, decrypted_message);

}

void generateIV(unsigned char* iv, size_t iv_len) {

    if (RAND_bytes(iv, iv_len) != 1) {
        perror("Failed to generate random IV");
        exit(EXIT_FAILURE);
    }
}

int start_executor(char* arg, struct peer_info *peer) {
    return 1;
}

void printEvpKey(EVP_PKEY *key) {
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

    char *pubKeyStr = NULL;
    long pubKeyLen = BIO_get_mem_data(bio, &pubKeyStr);
    if (pubKeyLen > 0) {
        printf("Public Key:\n%s\n", pubKeyStr);
    }

    BIO_free(bio);
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

void startEngine(struct peer_info *peer, struct register_info *register_item, struct server_info *server) {

    char *message = "1:[ PEER CONNESSO CORRETTAMENTE ]";
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

    // Invio del messaggio al server
    send(server->server_sock, message, strlen(message), 0);

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
    EVP_PKEY* serverPublicKey = convertToPublicKey(receivedBuffer, receivedSize);
    if (serverPublicKey == NULL) {
        printf("Failed to convert received data to public key\n");
        return;
    }

    printEvpKey(serverPublicKey);
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
                } else {
                    printf("\n\n\n\n\t\t\t\t   [  RICEZIONE IN CORSO...  ]\n\n");
                    read(i, bufferRicezione, BUFFER_SIZE);

                    if (crypted == 1) {

                        unsigned char iv[KEY_LENGTH] = {0};
                        unsigned char plaintext[BUFFER_SIZE];
                        // decryptMessage(bufferRicezione, strlen(bufferRicezione), shared_secret, iv, plaintext);
                        printf("Plaintext arrived: %s, Dimension: %d", plaintext, strlen(plaintext));
                        strcpy(bufferNeighbor, plaintext);
                    } else {
                        strcpy(bufferNeighbor, bufferRicezione);
                    }

                    if (atoi(bufferNeighbor) == 22) {

                        printf("\n\t\t    SEI IL PRIMO PEER DEL NETWORK. PER ORA NON HAI NEIGHBORS.\n\n");
                        break;
                    }

                    if (atoi(bufferNeighbor) == 11) {
                        break;
                    }
                }
            }
        }
    }

}
