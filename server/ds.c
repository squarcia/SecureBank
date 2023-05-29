// Server side implementation of UDP client-server model
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/dh.h>

#define PORT	    8080
#define MAXLINE     1024
#define MAX_KEY_SIZE 2048
#define MAX_MESSAGE_SIZE 1460
#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024

#define COMMANDS 5
#define COMMAND_PREFIX '!'

struct register_info {
    FILE *registro;
    char data[1024];
    char filename[1024];
    int chiuso;
    struct register_info *next;
};

struct peer_info {

    int port;
    char dataRemota[1024];

    struct register_info *register_list;

    struct peer_info *left_peer;
    struct peer_info *right_peer;
};

struct peer_list {

    struct peer_info *peer;
    struct peer_list *next;
};

struct socket_info {

    struct peer_info *peer;
    int socket;
    struct socket_info *next;
};

typedef int (*cmd_executor)(char* arg);

int global_peers_number = 0;
struct peer_list *peer_list = NULL;

int crypted = 0;

/* Diffie-Hellman Parameters */
unsigned char* shared_secret;

const char* valid_cmds[] = {"help", "showpeers", "showneighbor", "close", "esc"};

const char* help_msg =
    "\n\n****************************************** DS COVID ******************************************\n\n"
    "               !help                  --> mostra il significato dei comandi e ciò che fanno\n"
    "               !showpeers             --> mostra l’elenco dei peer connessi alla rete\n"
    "               !showneighbor  <peer>  --> mostra i neighbor di un peer\n"
    "               !close <peer>          --> chiude il register di un peer\n"
    "               !esc                   --> termina il DS\n";


const char* help_verbose_msg =
    "\n\n\t=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=  HELP COMMAND SECTION =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n\n"
    "\tSHOWPEERS:\t\t Mostra l'elenco completo dei peers connessi alla rete in modalità verbose\n\n"
    "\tSHOWNEIGHBOR:\t\t Mostra i neighbor di un peer passato come parametro."
    "\n\t\t\t\t Se non viene passato nessun parametro vengono mostrati"
    "\n\t\t\t\t i neighbor di ogni peer. \n\n"
    "\tCLOSE:\t\t\t provoca la chiusura del register del peer specificato come parametro.\n\n"
    "\tESC:\t\t\t termina il DS. La terminazione del DS causa la terminazione"
    "\n\t\t\t\t di tutti i peer."
    "\n\t\t\t\t Opzionalmente, prima di chiudersi, i peer possono salvare"
    "\n\t\t\t\t le loro informazioni su un file,"
    "\n\t\t\t\t ricaricato nel momento in cui un peer torna a far parte del network.\n\n";

int help_executor(char* arg) {
    printf("%s", help_verbose_msg);
    return 0;
}

void handle_error() {
    fprintf(stderr, "Error occurred\n");
    exit(1);
}

// Function to encrypt a message using AES-CBC with the shared secret as the key
size_t encrypt_message(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* key, size_t key_len, unsigned char* ciphertext) {
    // Create an encryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        handle_error("Failed to create encryption context");
    }

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1) {
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

    return ciphertext_len;
}

// Function to decrypt a ciphertext using AES-CBC with the shared secret as the key
size_t decrypt_message(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* key, size_t key_len, unsigned char* plaintext) {
    // Create a decryption context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        handle_error("Failed to create decryption context");
    }

    // Initialize the decryption operation
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, NULL) != 1) {
        handle_error("Failed to initialize decryption operation");
    }

    // Provide the ciphertext to be decrypted
    int plaintext_len;
    if (EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext, ciphertext_len) != 1) {
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


void sendMessage(int socket, unsigned char *buffer, int buffer_len)
{
    int bytes_sent = send(socket, buffer, buffer_len, 0);
    if (bytes_sent < 0)
    {
        perror("Error sending message");
        exit(1);
    }
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

void diffieHellman(int client_socket) {

    // Create DH parameters
    DH* dh = create_dh_params();

    // Generate private and public keys
    if (!DH_generate_key(dh)) {
        handle_error("Failed to generate DH keys");
    }

    // Send public key (pub_key) to the client

    // Get the public key
    const BIGNUM* server_pub_key = NULL;
    DH_get0_key(dh, &server_pub_key, NULL);

    // Convert the public key to a byte array
    size_t server_pub_key_len = BN_num_bytes(server_pub_key);
    unsigned char* server_pub_key_data = (unsigned char*)malloc(server_pub_key_len);
    if (server_pub_key_data == NULL) {
        handle_error("Failed to allocate memory for public key data");
    }

    BN_bn2bin(server_pub_key, server_pub_key_data);

    // Send the public key to the client
    if (send(client_socket, server_pub_key_data, server_pub_key_len, 0) == -1) {
        handle_error("Failed to send public key to client");
    }

    // Receive the client's public key (client_pub_key)

    // Receive the public key from the client
    unsigned char client_pub_key_data[MAX_KEY_SIZE];  // Adjust the buffer size accordingly
    int client_received_len = recv(client_socket, client_pub_key_data, sizeof(client_pub_key_data), 0);
    if (client_received_len <= 0) {
        handle_error("Failed to receive public key from client");
    }

    // Create a BIGNUM from the received public key data
    BIGNUM* client_pub_key = BN_bin2bn(client_pub_key_data, client_received_len, NULL);
    if (client_pub_key == NULL) {
        handle_error("Failed to create BIGNUM from public key data");
    }

    // Set the received public key in the DH object
    DH_set0_key(dh, client_pub_key, NULL);

    // Compute the shared secret
    shared_secret = (unsigned char*)malloc(DH_size(dh));
    if (shared_secret == NULL) {
        handle_error("Failed to allocate memory for shared secret");
    }

    int shared_secret_len = DH_compute_key(shared_secret, client_pub_key, dh);

    // Print the shared secret
    printf("Shared Secret: ");
    for (size_t i = 0; i < shared_secret_len; i++) {
        printf("%02X", shared_secret[i]);
    }
    printf("\n");


    // Use the shared secret for further communication


    // Encrypt the message
    const char* message = "Hello, client!";
    unsigned char encrypted_message[MAX_MESSAGE_SIZE];  // Adjust the buffer size accordingly
    size_t encrypted_message_len = encrypt_message(message, strlen(message), shared_secret, shared_secret_len, encrypted_message);
    if (encrypted_message_len <= 0) {
        handle_error("Failed to encrypt message");
    }

    // Send the encrypted message to the client
    if (send(client_socket, encrypted_message, encrypted_message_len, 0) == -1) {
        handle_error("Failed to send encrypted message to client");
    }


    // Clean up
    DH_free(dh);
}

int showpeers_executor(char* arg) {

    struct peer_list *current_node = peer_list;

    printf("\n\n\n\t\t\t\tI PEER CONNESSI AL NETWORK SONO : \n\n");

    if (current_node == NULL) {
        printf("\t\t\t\t[  NESSUN PEER CONNESSO ALLA RETE  ]\n\n");
        return 0;
    }

   	while (current_node != NULL) {

        printf("\n\t\t\t\t\tPEER [  %d  ] \n", current_node->peer->port);
        current_node = current_node->next;
    }
    printf("\n\n\n\n\n\t\t\t\t    ( IN ORDINE DI ARRIVO ) \n\n\n\n\n");

    return 0;
}

int showneighbor_executor(char* arg) {

    int port = atoi(arg);
    int trovato = 0;

    struct peer_list *current_node = peer_list;

   	while (current_node != NULL) {
        if (current_node->peer->port == port) {
            trovato = 1;
            break;
        }

        current_node = current_node->next;
    }


    if (!trovato) {
        printf("\n\n\n\t\t\t\t[  PEER NON PRESENTE NEL NETWORK  ]\n\n");
        return -1;
    }

    if (global_peers_number == 1) {
        printf("\n\n\n\t\t\t     [  IL PEER NON HA ANCORA NEIGHBORS  ]\n\n");
        return -1;
    }

    printf("\n\n\n\t\t\t\tI NEIGHBOR DEL PEER SONO : \n\n");
    printf("\n\t\t\t\t    PEER [  %d  ] \n", current_node->peer->port);
    printf("\n\n\n\t\tNEIGHBOR_LEFT [  %d  ]\t\tNEIGHBOR_RIGHT [  %d  ]  \n\n", current_node->peer->left_peer->port, current_node->peer->right_peer->port);

    return 0;
}

int esc_executor(char* arg) {

    printf("\n\n\n\t\t\t\t  [  DS SERVER IN CHIUSURA...  ]\n\n");

    return 0;
}

int close_executor(char* arg) {

    printf("\n\n\n\t\t\t\t   [  CHIUSURA REGISTER INVIATA  ]\n\n");

    return 0;
}

void print_help() {
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

cmd_executor executors[] = {
    *help_executor,
    *showpeers_executor,
    *showneighbor_executor,
    *close_executor,
    *esc_executor
};

int process_command(const char* cmd, char* arg) {

    int i, ris;

    for (i = 0; i < COMMANDS; ++i){
        if (strcmp(cmd, valid_cmds[i]) == 0){
            ris = executors[i](arg);
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

int _handle_cmd() {

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

    ris = process_command(cmd, arg);
    free(buf);
    return ris;
}


int main() {
    int master_socket, new_socket, client_sockets[MAX_CLIENTS];
    int max_clients = MAX_CLIENTS;
    int activity, valread, sd;
    int max_sd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    char *response;

    /* Buffer di ricezione/appoggio/appoggio */
    char bufferRicezione[MAXLINE],
         bufferCopy[MAXLINE],
         bufferNeighbor[MAXLINE];

    char *token;

    // Set di socket attivi
    fd_set readfds;

    // Creazione del master socket
    if ((master_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Errore nella creazione del socket");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    int reuse = 1;
    if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
        // Handle error
    }

    // Binding del socket all'indirizzo e alla porta
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Errore nel binding del socket");
        exit(EXIT_FAILURE);
    }

    // In attesa di connessioni in entrata
    if (listen(master_socket, 3) < 0) {
        perror("Errore nella listen");
        exit(EXIT_FAILURE);
    }

    // Inizializzazione degli array di socket
    for (int i = 0; i < max_clients; i++) {
        client_sockets[i] = 0;
    }

    // Accettazione di connessioni in entrata e gestione delle richieste
    // SERVER IN ASCOLTO SULLA PORTA 8080
    while (1) {

        print_help();
        // Pulizia del set di socket attivi
        FD_ZERO(&readfds);

        // Aggiunta del master socket al set
        FD_SET(master_socket, &readfds);
        max_sd = master_socket;

        // Aggiunta dei client socket al set
        for (int i = 0; i < max_clients; i++) {
            sd = client_sockets[i];

            // Se il socket è valido, aggiungilo al set
            if (sd > 0) {
                FD_SET(sd, &readfds);
            }

            // Aggiornamento del valore massimo del socket
            if (sd > max_sd) {
                max_sd = sd;
            }
        }

        // Attende l'attività su uno dei socket
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0)) {
            perror("Errore nella select");
            exit(EXIT_FAILURE);
        }

        // Se c'è attività sul master socket, è una nuova connessione
        if (FD_ISSET(master_socket, &readfds)) {
            if ((new_socket = accept(master_socket, (struct sockaddr *) &address, (socklen_t *) &addrlen)) < 0) {
                perror("Errore nell'accettazione della connessione");
                exit(EXIT_FAILURE);
            }

            // Aggiungi il nuovo socket al set dei client
            for (int i = 0; i < max_clients; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    break;
                }
            }
        }

        // Controlla gli input in arrivo da altri socket
        for (int i = 0; i < max_clients; i++) {
            sd = client_sockets[i];

            if (FD_ISSET(sd, &readfds)) {
                // Controllo se è una chiusura del socket
                if ((read(sd, buffer, BUFFER_SIZE)) == 0) {
                    // Il client ha chiuso la connessione
                    close(sd);
                    client_sockets[i] = 0;
                } else {
                    // Lettura dei dati inviati dal client
                    printf("\n\n\n\n\t\t\t\t   [  MESSAGGIO DAL CLIENT (%d)  ]\n\n", sd);
                    /* Verifico che sia un segnale da parte del server DS */

                    strtok(buffer, ":");
                    //printf("\nBuffer: %s", buffer);

                    /* SIGNAL 1: Il server comunica che questo è il primo peer del network */
                    if (atoi(buffer) == 1) {

                        printf("\n\n\t\t\t\t    [ NUOVO PEER NELLA RETE ]\n\n");
                        response = "\n\n\t\t\t\t    [ CONNECTED SUCCESSFULLY ]\n\n";
                        // Invio della risposta al client
                        send(sd, response, strlen(response), 0);
                        break;
                    }


                    /* SIGNAL 2: Il server comunica che questo è il primo peer del network */
                    if (atoi(buffer) == 2) {

                        printf("\n\n\t\t\t\t    [ DIFFIE-HELLMAN EXCHANGE ]\n\n");
                        diffieHellman(sd);
                        crypted = 1;
                        break;
                    }

                    if (atoi(buffer) == 3) {
                        break;
                    }

                }
            }
        }
    }
}

