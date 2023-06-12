#include "server_protocol.h"

/**
 * Function that creates a new Entry
 * @param value the PeerInfo value allocated
 * @return
 */
Entry* createEntry(PeerInfo* value) {
    Entry* entry = (Entry*)malloc(sizeof(Entry));
    entry->value = value;
    entry->next = NULL;
    return entry;
}

/**
 * Initialize the Entry list
 * @return
 */
EntryList* createEntryList() {
    EntryList* list = (EntryList*)malloc(sizeof(EntryList));
    list->head = NULL;
    return list;
}

/**
 * Insert the entry on top of the list
 * @param list of entries
 * @param value the new peer to insert
 */
void insertEntry(EntryList* list, PeerInfo* value) {
    Entry* newEntry = createEntry(value);
    newEntry->next = (struct Entry *) list->head;
    list->head = newEntry;
}

/**
 * Finds the user by his/her username
 * @param list where to search
 * @param username of the user to find
 * @return
 */
Entry* findEntryByUsername(EntryList* list, const char* username) {
    Entry* current = list->head;
    while (current != NULL) {
        if (strcmp(current->value->username, username) == 0) {
            return current;
        }
        current = (Entry *) current->next;
    }
    return NULL;
}

/**
 * Finds the user by his/her key
 * @param list where to search
 * @param key of the user to find
 * @return
 */
Entry* findEntryByKey(EntryList* list, int key) {
    Entry* current = list->head;
    while (current != NULL) {
        if (current->value->socket == key) {
            return current;
        }
        current = (Entry *) current->next;
    }
    return NULL;
}

/**
 * Prints the total list of the users registered
 * @param list
 */
void printEntryList(EntryList* list) {
    printf("\t\t\t\t\t     %-15s | %-10s\n", "Username", "Balance");
    printf("\t\t\t\t\t     -----------------------\n");

    Entry* current = list->head;
    while (current != NULL) {
        printf("\t\t\t\t\t     %-15s | %.2f€\n", current->value->username, current->value->balance);
        current = (Entry*)current->next;
    }
}

/**
 * Removes one user from the list
 * @param list where to search
 * @param key to remove
 */
void removeEntryByKey(EntryList* list, int key) {
    Entry* current = list->head;
    Entry* prev = NULL;

    while (current != NULL) {
        if (current->value->socket == key) {
            break;
        }
        prev = current;
        current = (Entry*)current->next;
    }

    if (current != NULL) {
        if (prev == NULL) {
            list->head = (Entry*)current->next;
        } else {
            prev->next = current->next;
        }

        free(current);
    }
}

/**
 * Function that print the error occurred
 * @param error_message the error occurred during the function
 */
void handle_error(const char* error_message) {
    fprintf(stderr, "Error occurred: %s\n", error_message);
    exit(1);
}

/**
 * Function that sends the public key in clear, without encryption
 * @param socket of destination
 * @param publicKey of the current user
 */
void sendPublicKey(int socket, EVP_PKEY* publicKey) {
    int bufferSize = i2d_PUBKEY(publicKey, NULL);
    if (bufferSize < 0) {
        perror("Failed to get buffer size for public key");
        return;
    }

    unsigned char* buffer = (unsigned char*)malloc(bufferSize);
    if (buffer == NULL) {
        perror("Failed to allocate memory for public key serialization");
        return;
    }

    unsigned char* bufferPtr = buffer;
    int result = i2d_PUBKEY(publicKey, &bufferPtr);
    if (result < 0) {
        perror("Failed to serialize public key");
        free(buffer);
        return;
    }

    result = send(socket, buffer, bufferSize, 0);
    if (result < 0) {
        perror("Failed to send public key");
        free(buffer);
        return;
    }

    free(buffer);
}

/**
 * Reads the private key from file
 * @param filename path to the private key
 * @return
 */
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


/**
 * Print on standard output the public key
 * @param key
 */
void printEvpKey(EVP_PKEY *key) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        return;
    }

    if (!PEM_write_bio_PUBKEY(bio, key)) {
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

/**
 * Print on standard output the public key
 * @param privateKey path to private key
 */
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

/**
 * Load the shared secret from file, used to decrypt the information stored at the registration phase
 * and the transactions
 * @param keyStore is the variable that contains the key to decrypt all the files
 * @param keyPath path to key
 */
void loadSharedSecretFromFile(unsigned char* keyStore, const char* keyPath) {
    FILE* file = fopen(keyPath, "rb");
    if (file == NULL) {
        fprintf(stderr, "Impossibile aprire il file per la lettura\n");
        exit(1);
    }

    size_t bytesRead = fread(keyStore, 1, 256, file);

    fclose(file);
}

/**
 * Function that generates the IV (Initialization Vector)
 * @param iv the variabile that will contain the IV
 * @param iv_len the IV length
 */
void generateRandomIV(unsigned char *iv, int iv_len) {
    if (RAND_bytes(iv, iv_len) != 1) {
        fprintf(stderr, "Errore durante la generazione dell'IV casuale.\n");
        exit(1);
    }
}

/**
 * Encrypt the file using the IV. It is used to encrypt the file with the help of keyStore
 * @param ciphertext_file path where will be stored the file
 * @param string the content that will be stored
 * @param keyStore the key used to encrypt
 */
void encryptFile(unsigned char* ciphertext_file, char *string, unsigned char *keyStore) {
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    generateRandomIV(iv, iv_len);

    FILE* cipher_file = fopen(ciphertext_file, "wb");
    if (!cipher_file) {
        fprintf(stderr, "Error: Unable to open file '%s' (no permission?).\n", ciphertext_file);
        exit(1);
    }

    fwrite(iv, 1, iv_len, cipher_file);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_new returned NULL\n");
        exit(1);
    }

    int ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keyStore, iv);
    if (ret != 1) {
        fprintf(stderr, "Error: EncryptInit Failed\n");
        exit(1);
    }

    unsigned char out_buf[1024 + EVP_MAX_BLOCK_LENGTH];
    int num_bytes_written;

    ret = EVP_EncryptUpdate(ctx, out_buf, &num_bytes_written, string, strlen(string) - 1);
    if (ret != 1) {
        fprintf(stderr, "Error: EncryptUpdate Failed\n");
        exit(1);
    }

    fwrite(out_buf, 1, num_bytes_written, cipher_file);

    ret = EVP_EncryptFinal_ex(ctx, out_buf, &num_bytes_written);
    if (ret != 1) {
        fprintf(stderr, "Error: EncryptFinal Failed\n");
        exit(1);
    }

    fwrite(out_buf, 1, num_bytes_written, cipher_file);

    EVP_CIPHER_CTX_free(ctx);
    fclose(cipher_file);
}

/**
 * Decrypt the file using the IV. It is used to decrypt the file with the help of keyStore
 * @param ciphertext_file path to encrypted file
 * @param keyStore key used to decrypt
 * @return
 */
unsigned char* decryptFile(const char* ciphertext_file, unsigned char* keyStore) {
    FILE* cipher_file = fopen(ciphertext_file, "rb");
    if (!cipher_file) {
        fprintf(stderr, "Error: unable to open file '%s' (file does not exist?).\n", ciphertext_file);
        exit(1);
    }

    unsigned char iv[EVP_MAX_IV_LENGTH];
    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    fread(iv, 1, iv_len, cipher_file);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_new returned NULL\n");
        exit(1);
    }

    int ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keyStore, iv);
    if (ret != 1) {
        fprintf(stderr, "Error: DecryptInit Failed\n");
        exit(1);
    }

    unsigned char in_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char out_buf[BUFFER_SIZE];
    unsigned char* decrypted_data = NULL;
    size_t decrypted_size = 0;

    int num_bytes_read, num_bytes_written;

    while ((num_bytes_read = fread(in_buf, 1, sizeof(in_buf), cipher_file)) > 0) {
        ret = EVP_DecryptUpdate(ctx, out_buf, &num_bytes_written, in_buf, num_bytes_read);
        if (ret != 1) {
            fprintf(stderr, "Error: DecryptUpdate Failed\n");
            exit(1);
        }

        size_t new_size = decrypted_size + num_bytes_written;
        unsigned char* new_decrypted_data = realloc(decrypted_data, new_size);
        if (new_decrypted_data == NULL) {
            fprintf(stderr, "Error: unable to allocate memory for decrypted string\n");
            exit(1);
        }

        memcpy(new_decrypted_data + decrypted_size, out_buf, num_bytes_written);

        decrypted_data = new_decrypted_data;
        decrypted_size = new_size;
    }

    ret = EVP_DecryptFinal_ex(ctx, out_buf, &num_bytes_written);
    if (ret != 1) {
        fprintf(stderr, "Error: DecryptFinal Failed\n");
        exit(1);
    }

    size_t new_size = decrypted_size + num_bytes_written;
    unsigned char* new_decrypted_data = realloc(decrypted_data, new_size);
    if (new_decrypted_data == NULL) {
        fprintf(stderr, "Error: unable to allocate memory for decrypted string\n");
        exit(1);
    }

    memcpy(new_decrypted_data + decrypted_size, out_buf, num_bytes_written);

    decrypted_data = new_decrypted_data;
    decrypted_size = new_size;

    EVP_CIPHER_CTX_free(ctx);
    fclose(cipher_file);

    return decrypted_data;
}

/**
 * Converts the buffer in the public key format
 * @param buffer contains the serialized public key
 * @param bufferSize dimension of public key serialized
 * @return public key
 */
EVP_PKEY* convertToPublicKey(unsigned char* buffer, int bufferSize) {
    unsigned char* bufferPtr = buffer;

    EVP_PKEY* publicKey = d2i_PUBKEY(NULL, (const unsigned char**)&bufferPtr, bufferSize);
    if (publicKey == NULL) {
        perror("Failed to convert data to public key");
        return NULL;
    }

    return publicKey;
}

/**
 * Reads the publick key from .pem file
 * @param filename path to public key
 * @return public key
 */
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

/**
 * Generated the public key using the certificate
 */
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

/**
 * Generate the self-signed certificate using the private key
 * @param privateKey of the server
 * @return a new certificate
 */
X509* generateSelfSignedCertificate(EVP_PKEY* privateKey) {
    X509* cert = X509_new();

    X509_set_version(cert, 2);

    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // 1 year validity

    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"Example Certificate", -1, -1, 0);

    X509_set_issuer_name(cert, name);

    X509_set_pubkey(cert, privateKey);

    X509_sign(cert, privateKey, EVP_sha256());

    return cert;
}

/**
 * Function that generate and store the certificate and private key to file
 */
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

/**
 * Function that initialize paths
 */
void initializePaths() {
    const char *directory = "../server";
    snprintf(pathPrivK, sizeof(pathPrivK), "%s/%s", directory, "private_key.pem");
    snprintf(pathPubK, sizeof(pathPubK), "%s/%s", directory, "public_key.pem");
}

/**
 * Function that print data in hexadecimal format
 * @param data to print
 * @param data_len of data
 * @param title what data represent
 */
void print_hex(const unsigned char* data, size_t data_len, const unsigned char* title) {
    printf("%s:\t", title);

    for (size_t i = 0; i < data_len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

/**
 * Function that calculates the HMAC based on the ciphertext
 * @param data the ciphertext calculated before
 * @param data_len the length of ciphertext
 * @param key the shared secret obtained with Diffie-Hellman
 * @param key_len the length of shared secret
 * @param hmac the hmac calculated
 */
void calculate_hmac(const unsigned char* data, size_t data_len, const unsigned char* key, size_t key_len, unsigned char* hmac) {
    HMAC_CTX* ctx = HMAC_CTX_new();
    if (ctx == NULL) {
        handle_error("Failed to create HMAC context");
    }

    if (HMAC_Init_ex(ctx, shared_secret, strlen(shared_secret), EVP_sha256(), NULL) != 1) {
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

/**
 * Function that encrypt a message that will be sent to the server
 * @param plaintext the plaintext to encrypt
 * @param plaintext_len the length of the plaintext
 * @param ciphertext the new ciphertext generated
 * @return
 */
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

/**
 * Function that is used in the receive and that extract the HMAC, IV and NONCE
 * and calculate the length of the ciphertext
 * @param ciphertext the ciphertext
 * @param ciphertext_len the length of ciphertext
 * @param iv the Inizialitazion Vector
 * @param nonce the Nonce
 * @param hmac the HMAC
 * @param key the shared secret of DH
 * @param key_len the length of DH shared secret
 * @return
 */
int extract_values(const unsigned char* ciphertext, size_t ciphertext_len, unsigned char* iv, unsigned char* nonce, unsigned char* hmac, const unsigned char* key, size_t key_len) {
    size_t iv_offset = ciphertext_len - 16 - NONCE_SIZE - HMAC_SIZE;
    size_t nonce_offset = ciphertext_len - NONCE_SIZE - HMAC_SIZE;
    size_t hmac_offset = ciphertext_len - HMAC_SIZE;

    memcpy(iv, ciphertext + iv_offset, 16);
    memcpy(nonce, ciphertext + nonce_offset, NONCE_SIZE);
    memcpy(hmac, ciphertext + hmac_offset, HMAC_SIZE);

    unsigned char* ciphertext_only = (unsigned char*)malloc(ciphertext_len - 64);
    memcpy(ciphertext_only, ciphertext, ciphertext_len - 64);

    // Calculate the expected HMAC of the ciphertext
    unsigned char expected_hmac[32];
    calculate_hmac(ciphertext_only, ciphertext_len - 64, key, key_len, expected_hmac);

    int result = 0;
    if (strlen(hmac) == strlen(expected_hmac)) {
        result = CRYPTO_memcmp(hmac, expected_hmac, strlen(hmac));
    }

    return result;
}

/**
 * Function that decrypt a message, without using the digital signature
 * @param ciphertext to decrypt
 * @param ciphertext_len the length of ciphertext
 * @param plaintext the decrypted text
 * @return
 */
size_t decrypt_message(unsigned char* ciphertext, size_t ciphertext_len, unsigned char* plaintext) {
    // Extract the IV from the ciphertext
    unsigned char iv[16];
    // Extract the nonce from the ciphertext
    unsigned char nonce[16];
    // Extract the HMAC from the ciphertext
    unsigned char hmac[32];

    int res = extract_values(ciphertext, ciphertext_len, iv, nonce, hmac, shared_secret, strlen(shared_secret));
    if (res != 0) {
        handle_error("HMAC NOT VALID");
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

/**
 * Function that simply send a message
 * @param socket the destination socket
 * @param buffer the message
 * @param buffer_len the length of message
 */
void sendMessage(int socket, unsigned char *buffer, int buffer_len) {
    int bytes_sent = send(socket, buffer, buffer_len, 0);
    if (bytes_sent < 0)
    {
        perror("Error sending message");
        exit(1);
    }
}

/**
 * Fix and generate the DH Parameters
 * @return a new DH object containing p and g
 */
DH* create_dh_params() {
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


/**
 * Perform the exchange of public keys and the computation of the shared secret.
 * It follows the algorithm of Diffie-Hellman
 * @param client_socket the socket of the server
 */
void diffieHellman(int client_socket) {
    // Create DH parameters
    DH* dh = create_dh_params();

    // Generate private and public keys
    if (!DH_generate_key(dh)) {
        handle_error("Failed to generate DH keys");
    }

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

    // Message to be sent
    const char* message = "Diffie Hellman exchange done!";
    size_t message_len = strlen(message);

    // Buffer to hold the encrypted message
    unsigned char encrypted_message[1024];
    size_t encrypted_message_len;

    // Buffer to hold the decrypted message
    unsigned char decrypted_message[1024];
    size_t decrypted_message_len;

    // Encrypt the message
    encrypted_message_len = encrypt_message((const unsigned char*)message, message_len, encrypted_message);

    sendMessage(client_socket, encrypted_message, encrypted_message_len);

    // Clean up
    DH_free(dh);
}

/**
 * Function that sends a signed message
 * @param socket the destination socket
 * @param message the encrypted message to sign
 * @param message_length the length of the message to sign
 * @param signature the output signature
 * @param signature_length the output signature length
 */
void send_signed_message(int socket, const unsigned char* message, size_t message_length, const unsigned char* signature, size_t signature_length) {
    size_t total_length = message_length + signature_length;

    unsigned char* signed_message = (unsigned char*)malloc(total_length);
    if (signed_message == NULL) {
        perror("Failed to allocate memory for signed message");
        return;
    }

    memcpy(signed_message, signature, signature_length);
    memcpy(signed_message + signature_length, message, message_length);

    ssize_t bytes_sent = send(socket, signed_message, total_length, 0);
    if (bytes_sent < 0) {
        perror("Failed to send signed message");
    }
}

/**
 * Function that, given a message, sign it
 * @param message to sign
 * @param message_length the message length
 * @param private_key_path the path wehere to read the private key
 * @param signature the new signature generated
 * @param signature_length the new signature length generated
 * @return error or not
 */
int sign_message(const unsigned char* message, size_t message_length, const char* private_key_path, unsigned char** signature, size_t* signature_length) {

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

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        perror("Failed to create signature context");
        EVP_PKEY_free(private_key);
        return -1;
    }

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, private_key) != 1) {
        perror("Failed to initialize signature");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }

    if (EVP_DigestSignUpdate(ctx, message, message_length) != 1) {
        perror("Failed to update signature");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }

    if (EVP_DigestSignFinal(ctx, NULL, signature_length) != 1) {
        perror("Failed to get signature length");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }

    *signature = (unsigned char*)malloc(*signature_length);
    if (*signature == NULL) {
        perror("Failed to allocate memory for signature");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(private_key);
        return -1;
    }

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

/**
 * Function tha prints help menu
 */
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

/**
 * Function that, given a message, will verify the signature inside
 * @param message encrypted
 * @param message_length of the encrypted message
 * @param signature of the message
 * @param signature_length of the signature
 * @param public_key of the server
 * @return error or not
 */
int verify_signature(const unsigned char* message, size_t message_length, const unsigned char* signature, size_t signature_length,  EVP_PKEY* public_key) {

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        perror("Failed to create EVP_MD_CTX");
        EVP_PKEY_free(public_key);
        return -1;
    }

    int result = EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, public_key);
    if (result != 1) {
        perror("Failed to initialize EVP_DigestVerifyInit");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(public_key);
        return -1;
    }

    result = EVP_DigestVerify(ctx, signature, signature_length, message, message_length);
    if (result != 1) {
        printf("Signature verification failed\n");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(public_key);
        return -1;
    }

    return 1;
}

/**
 * Receive signed message and verify the signature
 * @param socket from who receive the signature
 * @param message the message received
 * @param message_length the message length received
 * @param signature the signature take from the message
 * @param signature_length the signature length
 * @param public_key the public key of the server
 * @return error or not
 */
int receive_signed_message(int socket, unsigned char** message, size_t* message_length, unsigned char** signature, size_t* signature_length, EVP_PKEY* public_key) {
    int result;
    size_t max_length = BUFFER_SIZE + 256;

    unsigned char* signed_message = (unsigned char*)malloc(max_length);
    if (signed_message == NULL) {
        perror("Failed to allocate memory for signed message");
        return -1;
    }

    ssize_t bytes_received = recv(socket, signed_message, max_length, 0);
    if (bytes_received < 0) {
        perror("Failed to receive signed message");
        free(signed_message);
        return -1;
    }

    size_t total_length = (size_t)bytes_received;
    *signature_length = 256;
    *message_length = total_length - *signature_length;

    /* Before calculating total_length, a check is added to see if the total size of the message
     * received is less than the expected size of the signature field (*signature_length). If the message is too short,
     * an error is printed and the function returns -1, thus avoiding a potential BUFFER OVERFLOW.
     * */
    if (total_length < *signature_length) {
        fprintf(stderr, "Received message is too short\n");
        free(signed_message);
        return -1;
    }

    *signature = (unsigned char*)malloc(*signature_length);
    if (*signature == NULL) {
        perror("Failed to allocate memory for signature");
        free(signed_message);
        return -1;
    }

    *message = (unsigned char*)malloc(*message_length);
    if (*message == NULL) {
        perror("Failed to allocate memory for message");
        free(*signature);
        free(signed_message);
        return -1;
    }

    memcpy(*signature, signed_message, *signature_length);
    memcpy(*message, signed_message + *signature_length, *message_length);

    result = verify_signature(*message, *message_length, *signature, *signature_length, public_key);

    return result;
}

/**
 * Update the balance of the user, writing on the file the new information about the user
 * @param peer the user
 */
void updateDestBalance(PeerInfo *peer) {
    unsigned char pathInfo[1024];
    unsigned char *folderpath = "../client/registered";
    unsigned char pathKey[1024];
    unsigned char keyStore[1024];

    snprintf(pathKey, sizeof(pathKey), "%s/%s/key.txt", folderpath, peer->username);
    loadSharedSecretFromFile(keyStore, pathKey);
    snprintf(pathInfo, sizeof(pathInfo), "%s/%s/%s", folderpath, peer->username, "info.txt");

    char* formattedString = (char*)malloc(5 * 1024 * sizeof(char)); // Assumendo una lunghezza massima di 1024 caratteri per ogni campo
    sprintf(formattedString, "%s:%s:%s:%s:%f", peer->nome, peer->cognome, peer->username, peer->password, peer->balance);

    encryptFile(pathInfo, formattedString, keyStore);
}

/**
 * Function that verify the transaction is valid and sends back to the user the validity or not of the transaction
 * @param username of destination, used to check if the user exists or not and to update his/her balance
 * @param amount how much money to send
 * @param sd the client socket
 */
void elaborateTransaction(unsigned char *username, float amount, int sd) {
    Entry* dest = findEntryByUsername(peerList, username);
    Entry* mitt = findEntryByKey(peerList, sd);

    if (dest != NULL) {

        dest->value->balance += amount;
        printf("\t\t\t\t\t [*** RECIPIENT BALANCE: %.2f ***]\n\n\n", dest->value->balance);

        mitt->value->balance -= amount;
        printf("\t\t\t\t\t [*** SENDER BALANCE: %.2f ***]\n\n\n", mitt->value->balance);

        unsigned char *response = "OK";
        size_t response_len = strlen(response);

        // Buffer to hold the encrypted message
        unsigned char encrypted_message[1024];
        size_t encrypted_message_len;

        // Encrypt the message
        encrypted_message_len = encrypt_message((const unsigned char*)response, response_len, encrypted_message);

        unsigned char* signature = NULL;
        size_t signature_length = 0;

        int result = sign_message(encrypted_message, encrypted_message_len, pathPrivK, &signature, &signature_length);
        if (result != 0) {
            fprintf(stderr, "Failed to sign the message\n");
            return;
        }

        send_signed_message(sd, encrypted_message, encrypted_message_len, signature, signature_length);

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

        unsigned char* signature = NULL;
        size_t signature_length = 0;

        int result = sign_message(encrypted_message, encrypted_message_len, pathPrivK, &signature, &signature_length);
        if (result != 0) {
            fprintf(stderr, "Failed to sign the message\n");
            return;
        }

        send_signed_message(sd, encrypted_message, encrypted_message_len, signature, signature_length);
    }
}

/**
 * Function used to read at the beginning the information of all users from the file and to store them in the list
 * @param parentFolder folder which contains all the users informations
 */
void readPeerInfoFromFolders(const char* parentFolder) {
    DIR* dir = opendir(parentFolder);
    if (dir == NULL) {
        perror("Failed to open parent folder");
        return;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strcmp(entry->d_name, ".DS_Store") == 0) {
            continue;
        }

        char subFolderPath[1024];
        snprintf(subFolderPath, sizeof(subFolderPath), "%s/%s", parentFolder, entry->d_name);

        char infoFilePath[1024];
        char publicKeyFilePath[1024];
        unsigned char *pathKey[1024];

        snprintf(infoFilePath, sizeof(infoFilePath), "%s/info.txt", subFolderPath);
        snprintf(publicKeyFilePath, sizeof(publicKeyFilePath), "%s/public_key", subFolderPath);
        snprintf(pathKey, sizeof(pathKey), "%s/key.txt", subFolderPath);

        EVP_PKEY *pubKey = readPublicKeyFromPEM(publicKeyFilePath);

        unsigned char keyStore[1024];
        loadSharedSecretFromFile(keyStore, pathKey);
        unsigned char *informationsUser;
        informationsUser = decryptFile(infoFilePath, keyStore);
        if (informationsUser == NULL) {
            fprintf(stderr, "Error: Unable to decrypt user information\n");
            exit(1);
        }

        PeerInfo* peerInfo = malloc(sizeof(PeerInfo));
        if (peerInfo == NULL) {
            fprintf(stderr, "Error: Unable to allocate memory for PeerInfo\n");
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
            printf("Error: Invalid format.\n");
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

    fd_set readfds;

    generate_private_key_and_certificate();
    generate_public_key();
    printf("\t\t\t\t\t [*** SERVER CERTIFICATE CREATED ***]\n\n\n");
    printf("\t\t\t\t\t [*** SERVER PRIVATE KEY CREATED ***]\n\n\n");
    printf("\t\t\t\t\t [*** SERVER PUBLIC KEY CREATED ***]\n\n\n");

    if ((master_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Error in socket creation");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    int reuse = 1;
    if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt(SO_REUSEADDR) failed");
    }

    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Socket binding error");
        exit(EXIT_FAILURE);
    }

    if (listen(master_socket, 3) < 0) {
        perror("Error in the listen");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < max_clients; i++) {
        client_sockets[i] = 0;
    }

    peerList = createEntryList();
    initializePaths();
    readPeerInfoFromFolders("../client/registered");
    printEntryList(peerList);

    while (1) {

        print_help();

        FD_ZERO(&readfds);

        FD_SET(master_socket, &readfds);
        max_sd = master_socket;

        for (int i = 0; i < max_clients; i++) {
            sd = client_sockets[i];

            if (sd > 0) {
                FD_SET(sd, &readfds);
            }

            if (sd > max_sd) {
                max_sd = sd;
            }
        }

        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0)) {
            perror("Error in select");
            exit(EXIT_FAILURE);
        }


        if (FD_ISSET(master_socket, &readfds)) {
            if ((new_socket = accept(master_socket, (struct sockaddr *) &address, (socklen_t *) &addrlen)) < 0) {
                perror("Error accepting connection");
                exit(EXIT_FAILURE);
            }

            for (int i = 0; i < max_clients; i++) {
                if (client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    break;
                }
            }
        }

        for (int i = 0; i < max_clients; i++) {
            sd = client_sockets[i];

            if (FD_ISSET(sd, &readfds)) {

                if ((numBytesRead = recv(sd, buffer, BUFFER_SIZE, 0)) == 0) {

                    printf("\n\n\n\n\t\t\t\t   [  CLIENT (%d) DISCONNECTED ]\n\n", sd);

                    removeEntryByKey(peerList, sd);

                    close(sd);
                    client_sockets[i] = 0;

                } else {
                    printf("\n\n\n\n\t\t\t\t   [  MESSAGE FROM CLIENT (%d)  ]\n\n", sd);

                    if (crypted) {
                        unsigned char decrypted_message[1024];
                        size_t decrypted_message_len;

                        // Decrypt the message
                        decrypted_message_len = decrypt_message(buffer, numBytesRead, decrypted_message);
                        memcpy(buffer, decrypted_message, decrypted_message_len);
                    }

                    char destination;
                    memcpy(&destination, buffer, 1);

                    if (atoi(&destination) == 1) {

                        printf("\n\n\t\t\t\t    [ NEW PEER IN THE NETWORK ]\n\n");

                        const char* publicKeyFile = "../server/public_key.pem";
                        EVP_PKEY* server_pubkey = readPublicKeyFromPEM(publicKeyFile);
                        if (server_pubkey == NULL) {
                            printf("Failed to read public key from file\n");
                            return 1;
                        }

                        BIO* bio = BIO_new(BIO_s_mem());
                        PEM_write_bio_PUBKEY(bio, server_pubkey);

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

                            sprintf(str, "%f", foundEntryByUsername->value->balance);
                            size_t message_len = strlen(str);

                            unsigned char encrypted_message[1024];
                            size_t encrypted_message_len;

                            encrypted_message_len = encrypt_message((const unsigned char*)str, message_len, encrypted_message);

                            unsigned char* signature = NULL;
                            size_t signature_length = 0;

                            int result = sign_message(encrypted_message, encrypted_message_len, pathPrivK, &signature, &signature_length);
                            if (result != 0) {
                                fprintf(stderr, "Failed to sign the message\n");
                                return 1;
                            }

                            send_signed_message(sd, encrypted_message, encrypted_message_len, signature, signature_length);
                            printf("\t\t\t\t [*** UPDATED BALANCE SENT ***]\n\n\n");
                        }
                    } else if (atoi(&destination) == 8) {
                        printf("\t\t\t\t\t [*** BALANCE ***]\n\n\n");

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
                            decrypted_message_len = decrypt_message(rec, rec_l, decrypted_message);

                            float amount = atof(decrypted_message);
                            foundEntryByUsername->value->balance += amount;
                        }
                    } else if (atoi(&destination) == 9) {
                        printf("\t\t\t\t\t [*** TRANSACTION RECEIVED ***]\n\n\n");

                        unsigned char* rec_msg;
                        size_t received_msg_length;

                        unsigned char* received_signature;
                        size_t received_signature_length;

                        unsigned char decr_message[1024];
                        size_t decrypted_message_len;

                        Entry* e = findEntryByKey(peerList, sd);

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

                        EVP_PKEY *serverPublicKey = convertToPublicKey(decrypted_pubKey, decrypted_message_len);
                        if (serverPublicKey == NULL) {
                            printf("Failed to convert received data to public key\n");
                        }

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


