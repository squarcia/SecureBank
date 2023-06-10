#include "server_protocol.h"

const char* valid_cmds[] = { "showUsers",  "esc"};

const char* help_msg =
        "\n\n****************************************** SECURE BANK ******************************************\n\n"
        "               !showUsers             --> mostra l’elenco dei peer registrati alla banca\n"
        "               !esc                   --> termina il server\n";

Entry* createEntry(PeerInfo* value) {
    Entry* entry = (Entry*)malloc(sizeof(Entry));
    entry->value = value;
    entry->next = NULL;
    return entry;
}

EntryList* createEntryList() {
    EntryList* list = (EntryList*)malloc(sizeof(EntryList));
    list->head = NULL;
    return list;
}

void insertEntry(EntryList* list, PeerInfo* value) {
    Entry* newEntry = createEntry(value);
    newEntry->next = (struct Entry *) list->head;
    list->head = newEntry;
}

Entry* findEntryByUsername(EntryList* list, const char* username) {
    Entry* current = list->head;
    while (current != NULL) {
        if (strcmp(current->value->username, username) == 0) {
            return current;
        }
        current = (Entry *) current->next;
    }
    return NULL; // Elemento non trovato
}

void printEntryList(EntryList* list) {
    printf("\t\t\t\t\t     %-15s | %-10s\n", "Username", "Balance");
    printf("\t\t\t\t\t     -----------------------\n");

    Entry* current = list->head;
    while (current != NULL) {
        printf("\t\t\t\t\t     %-15s | %.2f€\n", current->value->username, current->value->balance);
        current = (Entry*)current->next;
    }
}


Entry* findEntryByKey(EntryList* list, int key) {
    Entry* current = list->head;
    while (current != NULL) {
        if (current->value->socket == key) {
            return current;
        }
        current = (Entry *) current->next;
    }
    return NULL; // Elemento non trovato
}

void removeEntryByKey(EntryList* list, int key) {
    Entry* current = list->head;
    Entry* prev = NULL;

    // Trova l'elemento da rimuovere e tiene traccia del nodo precedente
    while (current != NULL) {
        if (current->value->socket == key) {
            break;
        }
        prev = current;
        current = (Entry*)current->next;
    }

    // Se l'elemento è stato trovato, rimuovilo dalla lista
    if (current != NULL) {
        // Se l'elemento da rimuovere è la testa della lista
        if (prev == NULL) {
            list->head = (Entry*)current->next;
        } else {
            prev->next = current->next;
        }

        free(current); // Dealloca la memoria dell'elemento rimosso
    }
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

void loadSharedSecretFromFile(unsigned char* keyStore, const char* keyPath) {
    FILE* file = fopen(keyPath, "rb");
    if (file == NULL) {
        fprintf(stderr, "Impossibile aprire il file per la lettura\n");
        exit(1);
    }

    size_t bytesRead = fread(keyStore, 1, 256, file);

    fclose(file);
}


void generateRandomIV(unsigned char *iv, int iv_len) {
    if (RAND_bytes(iv, iv_len) != 1) {
        fprintf(stderr, "Errore durante la generazione dell'IV casuale.\n");
        exit(1);
    }
}


void encryptFile(unsigned char* ciphertext_file, char *string, unsigned char *keyStore) {

    // Genera IV casuale
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    generateRandomIV(iv, iv_len);

    // Apri file di testo cifrato
    FILE* cipher_file = fopen(ciphertext_file, "wb");
    if (!cipher_file) {
        fprintf(stderr, "Errore: impossibile aprire il file '%s' (nessun permesso?)\n", ciphertext_file);
        exit(1);
    }

    // Scrivi IV sul file cifrato
    fwrite(iv, 1, iv_len, cipher_file);

    // Crea e inizializza il contesto di crittografia
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Errore: EVP_CIPHER_CTX_new ha restituito NULL\n");
        exit(1);
    }

    // Inizializza l'operazione di crittografia
    int ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keyStore, iv);
    if (ret != 1) {
        fprintf(stderr, "Errore: EncryptInit Failed\n");
        exit(1);
    }

    // Buffer per i dati di input e output
    //unsigned char in_buf[] = "CIAO";
    unsigned char out_buf[1024 + EVP_MAX_BLOCK_LENGTH];

    int num_bytes_written;

    // Crittografa i dati
    ret = EVP_EncryptUpdate(ctx, out_buf, &num_bytes_written, string, strlen(string) - 1);
    if (ret != 1) {
        fprintf(stderr, "Errore: EncryptUpdate Failed\n");
        exit(1);
    }

    fwrite(out_buf, 1, num_bytes_written, cipher_file);

    // Finalizza l'operazione di crittografia
    ret = EVP_EncryptFinal_ex(ctx, out_buf, &num_bytes_written);
    if (ret != 1) {
        fprintf(stderr, "Errore: EncryptFinal Failed\n");
        exit(1);
    }

    fwrite(out_buf, 1, num_bytes_written, cipher_file);

    // Dealloca il contesto di crittografia
    EVP_CIPHER_CTX_free(ctx);

    // Chiudi il file
    fclose(cipher_file);
}

unsigned char* decryptFile(const char* ciphertext_file, unsigned char* keyStore) {
    // Apri il file cifrato
    FILE* cipher_file = fopen(ciphertext_file, "rb");
    if (!cipher_file) {
        fprintf(stderr, "Errore: impossibile aprire il file '%s' (il file non esiste?)\n", ciphertext_file);
        exit(1);
    }

    // Leggi IV dal file cifrato
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    fread(iv, 1, iv_len, cipher_file);

    // Crea e inizializza il contesto di decrittografia
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Errore: EVP_CIPHER_CTX_new ha restituito NULL\n");
        exit(1);
    }

    // Inizializza l'operazione di decrittografia
    int ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keyStore, iv);
    if (ret != 1) {
        fprintf(stderr, "Errore: DecryptInit Failed\n");
        exit(1);
    }

    // Buffer per i dati di input e output
    unsigned char in_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char out_buf[BUFFER_SIZE];
    unsigned char* decrypted_data = NULL;
    size_t decrypted_size = 0;

    int num_bytes_read, num_bytes_written;

    // Ciclo di decrittografia
    while ((num_bytes_read = fread(in_buf, 1, sizeof(in_buf), cipher_file)) > 0) {
        ret = EVP_DecryptUpdate(ctx, out_buf, &num_bytes_written, in_buf, num_bytes_read);
        if (ret != 1) {
            fprintf(stderr, "Errore: DecryptUpdate Failed\n");
            exit(1);
        }

        // Espandi il buffer per la stringa decrittografata
        size_t new_size = decrypted_size + num_bytes_written;
        unsigned char* new_decrypted_data = realloc(decrypted_data, new_size);
        if (new_decrypted_data == NULL) {
            fprintf(stderr, "Errore: impossibile allocare memoria per la stringa decrittografata\n");
            exit(1);
        }

        // Copia i dati decrittografati nel buffer espanso
        memcpy(new_decrypted_data + decrypted_size, out_buf, num_bytes_written);

        decrypted_data = new_decrypted_data;
        decrypted_size = new_size;
    }

    // Finalizza l'operazione di decrittografia
    ret = EVP_DecryptFinal_ex(ctx, out_buf, &num_bytes_written);
    if (ret != 1) {
        fprintf(stderr, "Errore: DecryptFinal Failed\n");
        exit(1);
    }

    // Espandi il buffer per la stringa decrittografata per includere l'output finale
    size_t new_size = decrypted_size + num_bytes_written;
    unsigned char* new_decrypted_data = realloc(decrypted_data, new_size);
    if (new_decrypted_data == NULL) {
        fprintf(stderr, "Errore: impossibile allocare memoria per la stringa decrittografata\n");
        exit(1);
    }

    // Copia l'output finale nel buffer espanso
    memcpy(new_decrypted_data + decrypted_size, out_buf, num_bytes_written);

    decrypted_data = new_decrypted_data;
    decrypted_size = new_size;

    // Dealloca il contesto di decrittografia
    EVP_CIPHER_CTX_free(ctx);

    // Chiudi il file
    fclose(cipher_file);

    // Restituisci il puntatore alla stringa decrittografata
    return decrypted_data;
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

void generate_private_key_and_certificate() {

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

    HMAC_CTX_free(ctx);
}

size_t encrypt_message(const unsigned char* plaintext, size_t plaintext_len, unsigned char* ciphertext) {
    // Generate a random IV
    unsigned char iv[16];
    if (RAND_bytes(iv, 16) != 1) {
        handle_error("Failed to generate IV");
    }

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
    calculate_hmac(ciphertext, ciphertext_len, shared_secret, strlen(shared_secret), hmac);

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

    // Confronto tra l'HMAC ricevuto e l'HMAC calcolato
    int result = 0;
    if (strlen(hmac) == strlen(expected_hmac)) {
        result = CRYPTO_memcmp(hmac, expected_hmac, strlen(hmac));
    }

    return result;
}

size_t decrypt_message(unsigned char* ciphertext, size_t ciphertext_len, unsigned char* plaintext) {

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
}

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

    return 0;
}

int esc_executor(char* arg) {

    printf("\n\n\n\t\t\t\t  [  SERVER IN CHIUSURA...  ]\n\n");

    return 0;
}

int close_executor(char* arg) {

    printf("\n\n\n\t\t\t\t   [  CHIUSURA REGISTER INVIATA  ]\n\n");

    return 0;
}

void print_help() {
    printf("%s", help_msg);
}

int parse_command(char* line, size_t line_len, char** cmd, char** arg){
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

int showUsers() {
    printEntryList(peerList);
}

cmd_executor executors[] = {
        showUsers,
        close_executor
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

    return 1;
}


int receive_signed_message(int socket, unsigned char** message, size_t* message_length, unsigned char** signature, size_t* signature_length, EVP_PKEY* public_key) {
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
    result = verify_signature(*message, *message_length, *signature, *signature_length, public_key);

    return result;
}

void updateDestBalance(PeerInfo *peer) {
    unsigned char pathInfo[1024];
    unsigned char *folderpath = "../client/registered";
    unsigned char pathKey[1024];
    unsigned char keyStore[1024];

    snprintf(pathKey, sizeof(pathKey), "%s/%s/key.txt", folderpath, peer->username);
    loadSharedSecretFromFile(keyStore, pathKey);

    // Salva info utente
    snprintf(pathInfo, sizeof(pathInfo), "%s/%s/%s", folderpath, peer->username, "info.txt");
    // Cifratura
    char* formattedString = (char*)malloc(5 * 1024 * sizeof(char)); // Assumendo una lunghezza massima di 1024 caratteri per ogni campo
    sprintf(formattedString, "%s:%s:%s:%s:%f", peer->nome, peer->cognome, peer->username, peer->password, peer->balance);
    //printf("Formatted String: %s", formattedString);
    encryptFile(pathInfo, formattedString, keyStore);
}

void elaborateTransaction(unsigned char *username, float amount, int sd) {

    // check user exists
    Entry* dest = findEntryByUsername(peerList, username);
    Entry* mitt = findEntryByKey(peerList, sd);

    if (dest != NULL) {

        dest->value->balance += amount;
        printf("\t\t\t\t\t [*** RECIPIENT BALANCE: %.2f ***]\n\n\n", dest->value->balance);

        mitt->value->balance -= amount;
        printf("\t\t\t\t\t [*** SENDER BALANCE: %.2f ***]\n\n\n", mitt->value->balance);

        // invia messaggio positivo
        unsigned char *response = "OK";
        // Message to be sent
        size_t response_len = strlen(response);

        // Buffer to hold the encrypted message
        unsigned char encrypted_message[1024];
        size_t encrypted_message_len;

        // Encrypt the message
        encrypted_message_len = encrypt_message((const unsigned char*)response, response_len, encrypted_message);

        // Variabili per la firma
        unsigned char* signature = NULL;
        size_t signature_length = 0;

        // Firma il messaggio
        int result = sign_message(encrypted_message, encrypted_message_len, pathPrivK, &signature, &signature_length);
        if (result != 0) {
            fprintf(stderr, "Failed to sign the message\n");
            return;
        }

        send_signed_message(sd, encrypted_message, encrypted_message_len, signature, signature_length);

        // Update balance in .txt file of dest
        updateDestBalance(dest->value);
        updateDestBalance(mitt->value);

    } else {
        printf("\t\t\t\t\t [*** USER DOES NOT EXISTS ***]\n\n\n");
        // invia messaggio negativo
        unsigned char *response = "NOPE Non Va bene";
        // Message to be sent
        size_t response_len = strlen(response);

        // Buffer to hold the encrypted message
        unsigned char encrypted_message[1024];
        size_t encrypted_message_len;

        // Encrypt the message
        encrypted_message_len = encrypt_message((const unsigned char*)response, response_len, encrypted_message);

        // Variabili per la firma
        unsigned char* signature = NULL;
        size_t signature_length = 0;

        // Firma il messaggio
        int result = sign_message(encrypted_message, encrypted_message_len, pathPrivK, &signature, &signature_length);
        if (result != 0) {
            fprintf(stderr, "Failed to sign the message\n");
            return;
        }

        send_signed_message(sd, encrypted_message, encrypted_message_len, signature, signature_length);
    }
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

    return keypair;
}


void readPeerInfoFromFolders(const char* parentFolder) {
    // Apertura del parentFolder
    DIR* dir = opendir(parentFolder);
    if (dir == NULL) {
        perror("Failed to open parent folder");
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        // Ignora le voci "." e ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, ".DS_Store") == 0) {
            continue;
        }

        // Costruzione del percorso completo della sotto-cartella
        char subFolderPath[1024];
        snprintf(subFolderPath, sizeof(subFolderPath), "%s/%s", parentFolder, entry->d_name);
        //printf("Subfolder %s", subFolderPath);

        // Lettura dei file all'interno della sottocartella
        char infoFilePath[1024];
        char publicKeyFilePath[1024];
        unsigned char *pathKey[1024];

        snprintf(infoFilePath, sizeof(infoFilePath), "%s/info.txt", subFolderPath);
        snprintf(publicKeyFilePath, sizeof(publicKeyFilePath), "%s/public_key", subFolderPath);
        snprintf(pathKey, sizeof(pathKey), "%s/key.txt", subFolderPath);

        EVP_PKEY *pubKey = readPublicKeyFromPEM(publicKeyFilePath);

        // Carica info utente
        // Lettura dei dati dai file e inizializzazione del PeerInfo
        unsigned char keyStore[1024];
        loadSharedSecretFromFile(keyStore, pathKey);
        unsigned char *informationsUser;
        informationsUser = decryptFile(infoFilePath, keyStore);
        if (informationsUser == NULL) {
            fprintf(stderr, "Errore: Impossibile decrittare le informazioni dell'utente\n");
            exit(1);
        }

        // Allocazione della variabile PeerInfo
        PeerInfo* peerInfo = malloc(sizeof(PeerInfo));
        if (peerInfo == NULL) {
            fprintf(stderr, "Errore: Impossibile allocare memoria per PeerInfo\n");
            exit(1);
        }

        unsigned char* balance;

        char* token = strtok((char*)informationsUser, ":");
        memcpy(peerInfo->nome, token, strlen(token));

        token = strtok(NULL, ":");
        memcpy(peerInfo->cognome, token, strlen(token));

        token = strtok(NULL, ":");
        memcpy(peerInfo->username, token, strlen(token));

        token = strtok(NULL, ":");
        memcpy(peerInfo->password, token, strlen(token));

        token = strtok(NULL, ":");

        int whole;
        int decimal;

        if (sscanf(token, "%d.%2d", &whole, &decimal) != 2) {
            printf("Errore: Formato non valido.\n");
            return;
        }

        float number = (float)whole + (float)decimal / 100.0;
        peerInfo->balance = number;

        FILE* publicKeyFile = fopen(publicKeyFilePath, "r");

        if (publicKeyFile == NULL) {
            // Errore nell'apertura di uno dei file, passa alla prossima sotto-cartella
            perror("Failed to open file");
            if (publicKeyFile != NULL) fclose(publicKeyFile);
            continue;
        }

        peerInfo->pubKey = pubKey;

        fclose(publicKeyFile);

        insertEntry(peerList, peerInfo);
    }

    // Chiudi la cartella parentFolder
    closedir(dir);
}

int main() {

    int master_socket, new_socket, client_sockets[MAX_CLIENTS];
    int max_clients = MAX_CLIENTS;
    int activity, sd;
    int max_sd;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};
    int numBytesRead;

    // Set di socket attivi
    fd_set readfds;

    // Genero la private key e il certificato del server
    generate_private_key_and_certificate();
    generate_public_key();
    printf("\t\t\t\t\t [*** SERVER CERTIFICATE CREATED ***]\n\n\n");
    printf("\t\t\t\t\t [*** SERVER PRIVATE KEY CREATED ***]\n\n\n");
    printf("\t\t\t\t\t [*** SERVER PUBLIC KEY CREATED ***]\n\n\n");

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

    peerList = createEntryList();
    initializePaths();
    readPeerInfoFromFolders("../client/registered");
    printEntryList(peerList);

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
                    printf("Chiudo la connessione");

                    removeEntryByKey(peerList, sd);

                    close(sd);
                    client_sockets[i] = 0;
                } else {
                    // Lettura dei dati inviati dal client
                    printf("\n\n\n\n\t\t\t\t   [  MESSAGGIO DAL CLIENT (%d)  ]\n\n", sd);

                    if (crypted) {

                        // Buffer to hold the decrypted message
                        unsigned char decrypted_message[1024];
                        size_t decrypted_message_len;

                        // Decrypt the message
                        decrypted_message_len = decrypt_message(buffer, numBytesRead, decrypted_message);

                        /* Verifico che sia un segnale da parte del server DS */
                        memcpy(buffer, decrypted_message, decrypted_message_len);
                    }

                    char destination;  // Variabile di destinazione per il primo byte

                    // Copia il primo byte dalla stringa di origine alla variabile di destinazione
                    memcpy(&destination, buffer, 1);

                    /* SIGNAL 1: Il server comunica che questo è il primo peer del network */
                    if (atoi(&destination) == 1) {

                        printf("\n\n\t\t\t\t    [ NUOVO PEER NELLA RETE ]\n\n");

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
                        printf("\t\t\t\t\t [*** PUBLIC KEY SENT ***]\n\n\n");


                        char *token = strtok(buffer, ":");
                        token = strtok(NULL, ":");

                        Entry* foundEntryByUsername = findEntryByUsername(peerList, token);

                        if (foundEntryByUsername != NULL) {

                            memcpy(foundEntryByUsername->value->username, token, strlen(token));
                            foundEntryByUsername->value->socket = sd;
                        } else {
                            PeerInfo peer1;
                            peer1.socket = sd;
                            strncpy(peer1.username, token, sizeof(peer1.username));
                            insertEntry(peerList, &peer1);
                        }
                        break;

                    } else if (atoi(&destination) == 2) {
                        /* SIGNAL 2: Il server comunica che questo è il primo peer del network */
                        printf("\n\n\t\t\t\t    [ DIFFIE-HELLMAN EXCHANGE ]\n\n");
                        diffieHellman(sd);
                        printf("\t\t\t [*** DIFFIE HELLMAN EXCHANGE COMPLETED ***]\n\n\n");
                        crypted = 1;
                        break;
                    } else if (atoi(&destination) == 7) {

                        printf("\t\t\t\t [*** SENDING UPDATED BALANCE ***]\n\n\n");
                        Entry* foundEntryByUsername = findEntryByKey(peerList, sd);

                        if (foundEntryByUsername != NULL) {

                            unsigned char str[20];

                            printf("\t\t\t\t [*** BALANCE OF %d: %.2f ***]\n\n\n", sd, foundEntryByUsername->value->balance);

                            // Utilizza sprintf per convertire il float in una stringa
                            sprintf(str, "%f", foundEntryByUsername->value->balance);

                            // Message to be sent
                            size_t message_len = strlen(str);

                            // Buffer to hold the encrypted message
                            unsigned char encrypted_message[1024];
                            size_t encrypted_message_len;

                            // Encrypt the message
                            encrypted_message_len = encrypt_message((const unsigned char*)str, message_len, encrypted_message);

                            // Variabili per la firma
                            unsigned char* signature = NULL;
                            size_t signature_length = 0;

                            // Firma il messaggio
                            int result = sign_message(encrypted_message, encrypted_message_len, pathPrivK, &signature, &signature_length);
                            if (result != 0) {
                                fprintf(stderr, "Failed to sign the message\n");
                                return 1;
                            }

                            send_signed_message(sd, encrypted_message, encrypted_message_len, signature, signature_length);
                            printf("\t\t\t\t [*** UPDATED BALANCE SENT ***]\n\n\n");
                        }

                    } else if (atoi(&destination) == 8) {
                        printf("\t\t\t\t\t [*** SALDO ***]\n\n\n");
                        // Ricevi il messaggio firmato
                        unsigned char* rec;
                        size_t rec_l;
                        unsigned char* rec_s;
                        size_t rec_s_l;

                        Entry *e = findEntryByKey(peerList, sd);

                        int signatureValid = receive_signed_message(sd, &rec, &rec_l, &rec_s, &rec_s_l, e->value->pubKey);

                        if (signatureValid) {

                            Entry* foundEntryByUsername = findEntryByKey(peerList, sd);

                            unsigned char decrypted_message[1024];
                            size_t decrypted_message_len;

                            // Decrypt the message
                            decrypted_message_len = decrypt_message(rec, rec_l, decrypted_message);

                            float amount = atof(decrypted_message);
                            foundEntryByUsername->value->balance += amount;
                        }
                    } else if (atoi(&destination) == 9) {

                        printf("\t\t\t\t\t [*** TRANSACTION RECEIVED ***]\n\n\n");
                        // Ricevi il messaggio firmato
                        unsigned char* rec_msg;
                        size_t received_msg_length;

                        unsigned char* received_signature;
                        size_t received_signature_length;

                        unsigned char decr_message[1024];
                        size_t decrypted_message_len;

                        Entry* e = findEntryByKey(peerList, sd);

                        printEvpKey((EVP_PKEY*)e->value->pubKey);

                        int signatureValid = receive_signed_message(sd, &rec_msg, &received_msg_length, &received_signature, &received_signature_length, e->value->pubKey);

                        if (signatureValid) {
                            // Decrypt the message
                            decrypted_message_len = decrypt_message(rec_msg, received_msg_length, decr_message);
                        }

                        free(rec_msg);
                        free(received_signature);

                        char bufferCopy[1024];
                        memcpy(bufferCopy, decr_message, decrypted_message_len);

                        char* delimiter = " ";

                        char* username = NULL;
                        char* stringAmount = NULL;

                        float amount = 0;

                        // Primo token
                        username = strtok(bufferCopy, delimiter);
                        stringAmount = strtok(NULL, delimiter);

                        amount = atof(stringAmount);

                        elaborateTransaction(username, amount, sd);


                        break;
                    } else if (atoi(&destination) == 6){
                        printf("\t\t\t\t [*** CLIENT PUBLIC KEY RECEIVED ***]\n\n\n");

                        unsigned char pubKeyClient[1024];

                        int numBytesPubkey = 0;
                        numBytesPubkey = recv(sd, pubKeyClient, BUFFER_SIZE, 0);

                        // Buffer to hold the decrypted message
                        unsigned char decrypted_pubKey[1024];
                        size_t decrypted_message_len;

                        // Decrypt the message
                        decrypted_message_len = decrypt_message(pubKeyClient, numBytesPubkey, decrypted_pubKey);

                        // Converti i dati ricevuti nella chiave pubblica del server
                        EVP_PKEY *serverPublicKey = convertToPublicKey(decrypted_pubKey, decrypted_message_len);
                        if (serverPublicKey == NULL) {
                            printf("Failed to convert received data to public key\n");
                        }

                        // Recupera l'elemento dalla tabella hash
                        Entry* foundEntryByUsername = findEntryByKey(peerList, sd);
                        if (foundEntryByUsername != NULL) {
                            foundEntryByUsername->value->pubKey = serverPublicKey;
                        } else {
                            printf("\t\t\t\t\t [*** USER NOT FOUND ***]\n\n\n");
                        }
                        break;
                    }
                }
            }
        }
    }
}


