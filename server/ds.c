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

#define PORT	    8080
#define MAXLINE     1024
#define MAX_KEY_SIZE 2048
#define MAX_CLIENTS 5
#define BUFFER_SIZE 1024
#define HMAC_SIZE 32
#define NONCE_SIZE 16
#define TABLE_SIZE 100

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

typedef int (*cmd_executor)(char* arg);

int global_peers_number = 0;
struct peer_list *peer_list = NULL;

int crypted = 0;

typedef struct peerInfo {
    int port;
    char dataRemota[1024];

    char nome[1024];
    char cognome[1024];
    char username[1024];
    char password[1024];
    float balance[1024];

    EVP_PKEY **pubKey;
} PeerInfo;

typedef struct {
    int key;
    char username[1024];
    PeerInfo* value;
} Entry;

typedef struct {
    Entry* entries[TABLE_SIZE];
} HashTable;

EVP_PKEY *privateKey;

HashTable hashTable;

unsigned char pathPubK[1024];
unsigned char pathPrivK[1024];

// Funzione di hash semplice
int hash(int key) {
    return key % TABLE_SIZE;
}

// Inizializza la tabella hash
void initializeHashTable(HashTable* hashTable) {
    for (int i = 0; i < TABLE_SIZE; i++) {
        hashTable->entries[i] = NULL;
    }
}

// Inserisci un elemento nella tabella hash
void insert(HashTable* hashTable, int key, const char* username, PeerInfo* value) {
    int index = hash(key);

    // Crea una nuova entry
    Entry* newEntry = malloc(sizeof(Entry));
    newEntry->key = key;
    newEntry->value = value;
    memcpy(newEntry->username, username, strlen(username));

    // Inserisci la nuova entry nella posizione corrispondente
    hashTable->entries[index] = newEntry;
}

// Recupera un elemento dalla tabella hash
PeerInfo* get(HashTable* hashTable, int key) {
    int index = hash(key);

    // Cerca l'elemento nella posizione corrispondente
    Entry* entry = hashTable->entries[index];
    if (entry != NULL && entry->key == key) {
        return entry->value;
    }

    // Elemento non trovato
    return NULL;
}

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

void handle_error(const char* error_message) {
    fprintf(stderr, "Error occurred: %s\n", error_message);
    exit(1);
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

void generate_public_key() {
    X509* cert = NULL;
    EVP_PKEY* pubkey = NULL;
    BIO* pubkey_bio = NULL;
    FILE* pubkey_file = NULL;

    // Load server's certificate from file
    FILE* cert_file = fopen("../server/certificate.pem", "r");
    if (cert_file == NULL) {
        fprintf(stderr, "Error opening certificate file.\n");
        goto cleanup;
    }
    cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
    fclose(cert_file);
    if (cert == NULL) {
        fprintf(stderr, "Error loading certificate.\n");
        goto cleanup;
    }

    // Extract public key from the certificate
    pubkey = X509_get_pubkey(cert);
    if (pubkey == NULL) {
        fprintf(stderr, "Error extracting public key.\n");
        goto cleanup;
    }

    // Convert public key to PEM format
    pubkey_bio = BIO_new(BIO_s_mem());
    if (pubkey_bio == NULL) {
        fprintf(stderr, "Error creating BIO for public key.\n");
        goto cleanup;
    }
    if (PEM_write_bio_PUBKEY(pubkey_bio, pubkey) != 1) {
        fprintf(stderr, "Error writing public key to BIO.\n");
        goto cleanup;
    }

    // Store public key in a file
    pubkey_file = fopen("../server/public_key.pem", "w");
    if (pubkey_file == NULL) {
        fprintf(stderr, "Error opening public key file.\n");
        goto cleanup;
    }
    char buffer[4096];
    int len;
    while ((len = BIO_read(pubkey_bio, buffer, sizeof(buffer))) > 0) {
        fwrite(buffer, 1, len, pubkey_file);
    }

    printf("Public key saved to public_key.pem\n");

    cleanup:
    if (pubkey_file) fclose(pubkey_file);
    if (pubkey_bio) BIO_free(pubkey_bio);
    if (pubkey) EVP_PKEY_free(pubkey);
    if (cert) X509_free(cert);
}

// Function to generate a self-signed certificate
X509* generateSelfSignedCertificate(EVP_PKEY* privateKey)
{
    X509* cert = X509_new();

    // Set certificate version
    X509_set_version(cert, 2);

    // Generate random serial number for the certificate
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    // Set certificate validity period
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // 1 year validity

    // Set the subject name of the certificate (e.g., common name, organization, etc.)
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"Example Certificate", -1, -1, 0);

    // Set the issuer name to be the same as the subject name for a self-signed certificate
    X509_set_issuer_name(cert, name);

    // Set the public key of the certificate
    X509_set_pubkey(cert, privateKey);

    // Sign the certificate with the private key
    X509_sign(cert, privateKey, EVP_sha256());

    return cert;
}

int generate_private_key_and_certificate() {

    // Generate a new RSA private key
    EVP_PKEY* privateKey = EVP_PKEY_new();
    RSA* rsaKey = RSA_generate_key(2048, RSA_F4, NULL, NULL);
    EVP_PKEY_assign_RSA(privateKey, rsaKey);

    // Generate a self-signed certificate using the private key
    X509* certificate = generateSelfSignedCertificate(privateKey);

    // Write the private key to a file
    FILE* privateKeyFile = fopen("../server/private_key.pem", "wb");
    PEM_write_PrivateKey(privateKeyFile, privateKey, NULL, NULL, 0, NULL, NULL);
    fclose(privateKeyFile);

    // Write the certificate to a file
    FILE* certificateFile = fopen("../server/certificate.pem", "wb");
    PEM_write_X509(certificateFile, certificate);
    fclose(certificateFile);

    // Cleanup
    EVP_PKEY_free(privateKey);
    X509_free(certificate);
    EVP_cleanup();
}

void initializePaths() {

    const char *directory = "../server";

    snprintf(pathPrivK, sizeof(pathPrivK), "%s/%s", directory, "private_key.pem");
    snprintf(pathPubK, sizeof(pathPubK), "%s/%s", directory, "public_key.pem");

    printf("%s\n\n", pathPrivK);

    //EVP_PKEY *privKey = readPrivateKeyFromPEM(pathPrivK);

    privateKey = readPrivateKeyFromPEM(pathPrivK);

    //printPrivateKey(privateKey);
}

void print_hex(const unsigned char* data, size_t data_len, const unsigned char* title) {

    printf("%s:\t", title);

    for (size_t i = 0; i < data_len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
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

    // Message to be sent
    const char* message = "Hello, client!";
    size_t message_len = strlen(message);

    // Buffer to hold the encrypted message
    unsigned char encrypted_message[1024];
    size_t encrypted_message_len;

    // Buffer to hold the decrypted message
    unsigned char decrypted_message[1024];
    size_t decrypted_message_len;


    // Encrypt the message
    encrypted_message_len = encrypt_message((const unsigned char*)message, message_len, encrypted_message);

    //print_hex(encrypted_message, encrypted_message_len, "Encrypted Text");

    sendMessage(client_socket, encrypted_message, encrypted_message_len);

    // Clean up
    DH_free(dh);
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

    printf("Sign size: %d", signature_size);

    // Alloca memoria per la firma digitale
    signature = (unsigned char*)malloc(signature_size);
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

    return signature_size;
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

int verify_signature(const unsigned char* message, size_t message_length, const unsigned char* signature, size_t signature_length, EVP_PKEY* public_key) {
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

    // Verifica la firma utilizzando la chiave pubblica
    int result = EVP_VerifyFinal(ctx, signature, signature_length, public_key);

    // Pulisci il contesto di verifica della firma
    EVP_MD_CTX_free(ctx);

    return result;
}

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

    PeerInfo* retrievedPeer = get(&hashTable, socket);
   // printf("Message: %s\n Firma: %s\n", *message, *signature);
    printEvpKey((EVP_PKEY *) retrievedPeer->pubKey);
    result = verify_signature(*message, *message_length, *signature, *signature_length, (EVP_PKEY *)retrievedPeer->pubKey);

    return result;
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
    signature_size = signMessage(encrypted_message, encrypted_message_len, signature);
    print_hex(signature, signature_size, "SIGNATURE");
    // Invia il messaggio firmato
    send_signed_message(socket, encrypted_message, encrypted_message_len, signature, signature_size);
}

void elaborateTransaction(unsigned char *message, int sd) {

    char* delimiter = " ";

    char* token1 = NULL;
    char* token2 = NULL;

    // Primo token
    char* token = strtok(message, delimiter);
    if (token != NULL) {
        token1 = strdup(token);
    }

    // Secondo token
    token = strtok(NULL, delimiter);
    if (token != NULL) {
        token2 = strdup(token);
    }

    // Stampa dei token ottenuti
    printf("Token1: %s\n", token1);
    printf("Token2: %s\n", token2);

    // Deallocazione della memoria
    free(token1);
    free(token2);


    // check user exists

    // invia messaggio positivo
    ssend("OK Va bene", sd);
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




int main() {
    int master_socket, new_socket, client_sockets[MAX_CLIENTS];
    int max_clients = MAX_CLIENTS;
    int activity, valread, sd;
    int max_sd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    char *response;
    int numBytesRead;

    /* Buffer di ricezione/appoggio/appoggio */
    char bufferRicezione[MAXLINE],
            bufferCopy[MAXLINE],
            bufferNeighbor[MAXLINE];

    char *token;

    // Set di socket attivi
    fd_set readfds;

    // Genero la private key e il certificato del server
    generate_private_key_and_certificate();
    generate_public_key();

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

    initializeHashTable(&hashTable);
    initializePaths();

    //generate_keypair(pathPrivK, pathPubK);

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
                if ((numBytesRead = recv(sd, buffer, BUFFER_SIZE, 0)) == 0) {
                    // Il client ha chiuso la connessione
                    close(sd);
                    client_sockets[i] = 0;
                } else {
                    // Lettura dei dati inviati dal client
                    printf("\n\n\n\n\t\t\t\t   [  MESSAGGIO DAL CLIENT (%d)  ]\n\n", sd);

                    if (crypted) {
                        printf("Crypted\n");

                        // Buffer to hold the decrypted message
                        unsigned char decrypted_message[1024];
                        size_t decrypted_message_len;

                        // Decrypt the message
                        decrypted_message_len = decrypt_message(buffer, numBytesRead, decrypted_message);

                        // Print the decrypted message
                        printf("Decrypted Message: %s\n", decrypted_message);

                        /* Verifico che sia un segnale da parte del server DS */
                        memcpy(buffer, decrypted_message, decrypted_message_len);
                    }

                    char destination;  // Variabile di destinazione per il primo byte

                    // Copia il primo byte dalla stringa di origine alla variabile di destinazione
                    memcpy(&destination, buffer, 1);

                    // Stampa il primo byte
                    printf("Primo byte: %c\n", destination);

                    /* Verifico che sia un segnale da parte del server DS */
                    //memcpy(bufferCopy, buffer, numBytesRead);
                    //strtok(buffer, ":");

                    /* SIGNAL 1: Il server comunica che questo è il primo peer del network */
                    if (atoi(&destination) == 1) {

                        printf("\n\n\t\t\t\t    [ NUOVO PEER NELLA RETE ]\n\n");
                        response = "\n\n\t\t\t\t    [ CONNECTED SUCCESSFULLY ]\n\n";

                        // Invio la chiave pubblica in modo che il client possa verificare la mia identità
                        const char* publicKeyFile = "../server/public_key.pem";
                        EVP_PKEY* server_pubkey = readPublicKeyFromPEM(publicKeyFile);
                        if (server_pubkey == NULL) {
                            printf("Failed to read public key from file\n");
                            return 1;
                        }

                        // Converti la chiave pubblica del server in formato PEM
                        BIO* bio = BIO_new(BIO_s_mem());
                        PEM_write_bio_PUBKEY(bio, server_pubkey);

                        // Ottieni i dati dalla memoria BIO
                        char* pubkey_data;
                        size_t pubkey_len = BIO_get_mem_data(bio, &pubkey_data);

                        sendPublicKey(sd, server_pubkey);
                        printf("Public key sent!\n %s", pubkey_data);

                        printf("Aggiungo un nuovo utente");
                        // Creazione e inizializzazione di una struttura PeerInfo
                        PeerInfo* peer = malloc(sizeof(PeerInfo));
                        peer->port = 8080;

                        strcpy(peer->dataRemota, "Dati remoti");

                        // Inserisci l'elemento nella tabella hash
                        insert(&hashTable, sd,"Adelmo", peer);

                        // Invio della risposta al client
                        //send(sd, response, strlen(response), 0);
                        break;
                    } else if (atoi(&destination) == 2) {
                        /* SIGNAL 2: Il server comunica che questo è il primo peer del network */
                        printf("\n\n\t\t\t\t    [ DIFFIE-HELLMAN EXCHANGE ]\n\n");
                        diffieHellman(sd);
                        crypted = 1;
                        break;
                    } else if (atoi(&destination) == 3) {



                        // Recupera l'elemento dalla tabella hash
                        PeerInfo* retrievedPeer = get(&hashTable, sd);
                        if (retrievedPeer != NULL) {
                            printf("Elemento trovato:\n");
                            printf("Porta: %d\n", retrievedPeer->port);
                            printf("Dati remoti: %s\n", retrievedPeer->dataRemota);
                        } else {
                            printf("Elemento non trovato\n");
                        }
                        break;
                    } else if (atoi(&destination) == 8) {


                    } else if (atoi(&destination) == 9) {

                        printf("MESSAGGIO FIRMATO\n");
                        // Ricevi il messaggio firmato
                        unsigned char* received_message;
                        size_t received_message_length;
                        unsigned char* received_signature;
                        size_t received_signature_length;
                        unsigned char decrypted_message[1024];
                        size_t decrypted_message_len;

                        int signatureValid = receive_signed_message(sd, &received_message, &received_message_length, &received_signature, &received_signature_length);

                        if (signatureValid) {

                            printf("The message is correctly signed!\n\n");

                            // Decrypt the message
                            decrypted_message_len = decrypt_message(received_message, received_message_length, decrypted_message);

                            // Print the decrypted message
                            printf("Decrypted Message: %.*s\n", (int)decrypted_message_len, decrypted_message);
                        }

                        elaborateTransaction(decrypted_message, sd);

                        break;
                    }else {
                        printf("Public Key!\n");

                        // Converti i dati ricevuti nella chiave pubblica del server
                        EVP_PKEY *serverPublicKey = convertToPublicKey(buffer, sizeof(buffer));
                        if (serverPublicKey == NULL) {
                            printf("Failed to convert received data to public key\n");
                        }

                        printEvpKey(serverPublicKey);

                        // Recupera l'elemento dalla tabella hash
                        PeerInfo* retrievedPeer = get(&hashTable, sd);
                        if (retrievedPeer != NULL) {
                            printf("Elemento trovato:\n");
                            printf("Porta: %d\n", retrievedPeer->port);
                            printf("Dati remoti: %s\n", retrievedPeer->dataRemota);
                            retrievedPeer->pubKey = serverPublicKey;
                            printEvpKey(retrievedPeer->pubKey);
                        } else {
                            printf("Elemento non trovato\n");
                        }
                        break;
                    }
                }
            }
        }
    }
}


