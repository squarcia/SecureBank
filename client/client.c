#include "client_protocol.h"

/**
 * Function that adds a new transaction to the transactions's vector of user
 * @param transaction new transaction to add
 */
void addTransaction(Transaction transaction) {
    if (mySelf->transaction_table.transaction_count >= MAX_TRANSACTIONS) {
        printf("Numero massimo di transazioni raggiunto\n");
        return;
    }

    mySelf->transaction_table.transactions[mySelf->transaction_table.transaction_count] = transaction;
    mySelf->transaction_table.transaction_count++;
}

/**
 * Utility function that, at the bootstrap, initialize the number of transaction done by the users
 * @param directoryPath folder that contains all the transactions
 * @return error or not
 */
int countFilesInDirectory(const char* directoryPath) {
    int fileCount = 0;
    DIR* directory;
    struct dirent* entry;

    directory = opendir(directoryPath);

    if (directory == NULL) {
        perror("Errore durante l'apertura della cartella");
        return -1;
    }

    while ((entry = readdir(directory)) != NULL) {
        if (entry->d_type == DT_REG) {  // Controlla se è un file regolare
            fileCount++;
        }
    }

    closedir(directory);

    return fileCount;
}

/**
 * Function that creates a new transaction
 * @param trans_id new id of transaction
 * @param account_num name of the recipient
 * @param amount of money sent
 * @return
 */
Transaction createTransaction(int trans_id, const char* account_num, float amount) {

    Transaction newTransaction;
    newTransaction.transaction_id = trans_id;
    strcpy(newTransaction.account_number, account_num);
    newTransaction.amount = amount;

    time_t currentTime = time(NULL);
    newTransaction.timestamp = currentTime;

    return newTransaction;
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
 * Print on standard output the public key
 * @param key
 */
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

    char *KeyStr = NULL;
    long KeyLen = BIO_get_mem_data(bio, &KeyStr);
    if (KeyLen > 0) {
        printf("Public Key:\n%s\n", KeyStr);
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

    char buffer[BUFFER_SIZE];
    int bytesRead;
    while ((bytesRead = BIO_gets(bio, buffer, sizeof(buffer))) > 0) {
        printf("%s", buffer);
    }

    BIO_free(bio);
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
 * Function that generates a new pair of public and private keys
 * @param private_key_file to store the new private key
 * @param public_key_file to store the new public key
 * @return the keypair
 */
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

/**
 * Utility function that check if the import typed during the sendMoney() function is valid
 * @param input the import inserted
 * @return error or not
 */
int isFormatValid(const char* input) {

    size_t length = strlen(input);
    for (size_t i = 0; i < length; i++) {
        if (input[i] < '0' || input[i] > '9') {
            return -1;
        }
    }

    float value = atof(input);
    return value < 1000.0;
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
 */
void encryptFile(unsigned char* ciphertext_file, char *string) {

    // Genera IV casuale
    unsigned char iv[EVP_MAX_IV_LENGTH];
    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    generateRandomIV(iv, iv_len);

    // Apri file di testo cifrato
    FILE* cipher_file = fopen(ciphertext_file, "wb");
    if (!cipher_file) {
        fprintf(stderr, "Error: unable to open file '%s' (no permission?).\n", ciphertext_file);
        exit(1);
    }

    // Scrivi IV sul file cifrato
    fwrite(iv, 1, iv_len, cipher_file);

    // Crea e inizializza il contesto di crittografia
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: EVP_CIPHER_CTX_new returned NULL\n");
        exit(1);
    }

    // Inizializza l'operazione di crittografia
    int ret = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, keyStore, iv);
    if (ret != 1) {
        fprintf(stderr, "Error: EncryptInit Failed\n");
        exit(1);
    }

    // Buffer per i dati di input e output
    unsigned char out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];

    int num_bytes_written;

    // Crittografa i dati
    ret = EVP_EncryptUpdate(ctx, out_buf, &num_bytes_written, string, strlen(string) - 1);
    if (ret != 1) {
        fprintf(stderr, "Error: EncryptUpdate Failed\n");
        exit(1);
    }

    fwrite(out_buf, 1, num_bytes_written, cipher_file);

    // Finalizza l'operazione di crittografia
    ret = EVP_EncryptFinal_ex(ctx, out_buf, &num_bytes_written);
    if (ret != 1) {
        fprintf(stderr, "Error: EncryptFinal Failed\n");
        exit(1);
    }

    fwrite(out_buf, 1, num_bytes_written, cipher_file);

    // Dealloca il contesto di crittografia
    EVP_CIPHER_CTX_free(ctx);

    // Chiudi il file
    fclose(cipher_file);
}

/**
 * Decrypt the file using the IV. It is used to decrypt the file with the help of keyStore
 * @param ciphertext_file path to encrypted file
 * @return
 */
unsigned char* decryptFile(const char* ciphertext_file) {

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

    EVP_CIPHER_CTX_free(ctx);

    fclose(cipher_file);

    return decrypted_data;
}

/**
 * Function that saves the key with we encrypt and decrypt the files of informations and transactions
 * @param keyStore the value of the key
 * @param sharedSecretSize the size of key
 * @param keyPath the path where to store the key
 */
void saveSharedSecretToFile(const unsigned char* keyStore, size_t sharedSecretSize, const char* keyPath) {
    FILE* file = fopen(keyPath, "wb");
    if (file == NULL) {
        fprintf(stderr, "Unable to open file for writing\n");
        exit(1);
    }

    size_t bytesWritten = fwrite(keyStore, 1, sharedSecretSize, file);
    if (bytesWritten != sharedSecretSize) {
        fprintf(stderr, "Error when writing the shared secret to the file\n");
        exit(1);
    }

    fclose(file);
}

int loadSharedSecretFromFile(unsigned char* keyStore, const char* keyPath) {
    FILE* file = fopen(keyPath, "rb");
    if (file == NULL) {
        fprintf(stderr, "Unable to open file for reading\n");
        return -1;
    }

    size_t bytesRead = fread(keyStore, 1, 256, file);
    fclose(file);

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
 * @return error or not
 */
int receive_signed_message(int socket, unsigned char** message, size_t* message_length, unsigned char** signature, size_t* signature_length) {
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

    result = verify_signature(*message, *message_length, *signature, *signature_length, server->serverPublicKey);

    return result;
}

/**
 * Function that permits to initialize and create all the files, and that allows to insert the private informations
 * @return
 */
int register_executor() {

    char *nome,
            *cognome,
            *username,
            *password;

    int balance = 0;
    char answer;

    printf("\t\t\t\t\t [*** REGISTRATION SECTION ***]\n");

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
    char filepath[256];
    char transactionpath[256];

    if (strcmp("Y", &answer) == 0 || strcmp("y", &answer) == 0) {

        memcpy(mySelf->nome, nome, strlen(nome) + 1);
        memcpy(mySelf->cognome, cognome, strlen(cognome) + 1);
        memcpy(mySelf->username, username, strlen(username) + 1);
        memcpy(mySelf->password, password, strlen(password) + 1);
        mySelf->balance = 0;

        const char *directory = "../client/registered";
        const char *filename = username;

        snprintf(folderpath, sizeof(folderpath), "%s/%s", directory, filename);
        snprintf(transactionpath, sizeof(transactionpath), "%s/%s/transactions", directory, filename);

        int result = mkdir(folderpath, 0777);

        if (result != 0){
            fprintf(stderr, "Error creating the directory.\n");
            return -1;
        }

        result = mkdir(transactionpath, 0777);

        if (result != 0){
            fprintf(stderr, "Error creating the directory.\n");
            return -1;
        }

        snprintf(filepath, sizeof(filepath), "%s/%s", folderpath, filename);

        // Determina la dimensione del buffer necessaria
        int buffer_size = snprintf(NULL, 0, "%s:%s:%s:%s", nome, cognome, username, password);
        if (buffer_size < 0){
            fprintf(stderr, "Error when determining buffer size.\n");
            return -1;
        }

        buffer_size++;

        char *buffer = (char *)malloc(buffer_size * sizeof(char));
        if (buffer == NULL){
            fprintf(stderr, "Error during buffer allocation.\n");
            return -1;
        }

        result = snprintf(buffer, buffer_size, "%s:%s:%s:%s", nome, cognome, username, password);
        if (result < 0 || result >= buffer_size){
            fprintf(stderr, "Error while writing to buffer.\n");
            free(buffer);
            return -1;
        }

        if (result < 0 || result >= buffer_size){
            fprintf(stderr, "Error while writing to buffer.\n");
            free(buffer);
            return -1;
        }

        FILE *file = fopen(filepath, "w");
        if (file == NULL){
            fprintf(stderr, "Cannot open the file %s.\n", filename);
            return -1;
        }

        if (fputs(buffer, file) == EOF){
            fprintf(stderr, "Error while writing to file %s.\n", filename);
            fclose(file);
            return -1;
        }

        fclose(file);

        printf("\t\t\t\t\t [*** USER REGISTERED CORRECTLY, INFORMATION SAVED! ***]\n");

        registered = 1;
    }

    snprintf(pathPrivK, sizeof(pathPrivK), "%s/%s", folderpath, "private_key");
    snprintf(pathPubK, sizeof(pathPubK), "%s/%s", folderpath, "public_key");

    generate_keypair(pathPrivK, pathPubK);
    printf("\t\t\t\t\t [*** KEY-PAIR GENERATED SUCCESSULLY! ***]\n");

    return 1;
}

/**
 * Function that check if an user really exits and is already in the database
 * @param username to find and check
 * @param pwd to find and check
 * @return
 */
int checkExistingUser(const char* username, const char* pwd) {

    const char* directoryPath = "../client/registered"; // Specifica il percorso della cartella

    char path[BUFFER_SIZE];
    snprintf(path, sizeof(path), "%s/%s/info.txt", directoryPath, username);

    unsigned char pathKey[BUFFER_SIZE];
    snprintf(pathKey, sizeof(pathKey), "%s/%s/key.txt", directoryPath, username);
    int result = loadSharedSecretFromFile(keyStore, pathKey);

    if (result == -1) {
        printf("Username o password errati riprovare...");
        return -1;
    }

    unsigned char *buffer;
    buffer = decryptFile(path);

    const char delimiter[] = ":";
    float balance = 0;

    if (sscanf((char*)buffer, "%[^:]:%[^:]:%[^:]:%[^:]:%f",
               mySelf->nome, mySelf->cognome, mySelf->username,
               mySelf->password, &balance) != 5) {
        // Errore nella lettura dei dati, gestisci l'errore adeguatamente
        perror("Failed to read data from decrypted information");
    }

    mySelf->balance = balance;

    if (!strcmp(username, mySelf->username) && !strcmp(pwd, mySelf->password)) {
        return 1;
    }
}

/**
 * Function that prints the menu
 */
void print_help() {
    printf("%s", help_msg);
}

/**
 * Function that parse the comand typed
 * @param line the line typed
 * @param line_len the line length typed
 * @param cmd the cmd typed
 * @param arg the arguments of the command
 * @return
 */
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

/**
 * Function that simply send a message
 * @param socket the destination socket
 * @param buffer the message
 * @param buffer_len the length of message
 */
void sendMessage(int socket, unsigned char *buffer, int buffer_len){
    int bytes_sent = send(socket, buffer, buffer_len, 0);
    if (bytes_sent < 0)
    {
        perror("Error sending message");
        exit(1);
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
size_t decrypt_message(const unsigned char* ciphertext, size_t ciphertext_len, unsigned char* plaintext) {

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
 * Function that send a message to update the user balance
 */
void updateBalance() {

    // Message to be sent
    unsigned char* msg = "7";
    size_t msg_len = strlen(msg);

    // Buffer to hold the encrypted message
    unsigned char en_message[BUFFER_SIZE];
    size_t en_message_len;

    // Encrypt the message
    en_message_len = encrypt_message(msg, msg_len, en_message);
    sendMessage(server_sock, en_message, en_message_len);

    sleep(2);

    unsigned char* rec;
    size_t rec_l;
    unsigned char* rec_s;
    size_t rec_s_l;

    int signatureValid = receive_signed_message(server_sock, &rec, &rec_l, &rec_s, &rec_s_l);

    if (signatureValid) {

        unsigned char decr_message[BUFFER_SIZE];
        size_t decrypted_message_len;
        printf("\t\t\t\t\t [*** MESSAGE SIGNED CORRECTLY ***]\n\n\n");

        // Decrypt the message
        decrypted_message_len = decrypt_message(rec, rec_l, decr_message);

        float newBalance = atof(decr_message);

        mySelf->balance = newBalance;
        printf("\t\t\t\t\t [*** NEW BALANCE: %.2f € ***]\n\n\n", mySelf->balance);
    }
}

/**
 * Utility function that creates, from a transaction string, a transaction object
 * @param transactionString serialized transaction
 * @return a new transaction object
 */
Transaction createTransactionFromString(const char* transactionString) {
    Transaction transaction;

    sscanf(transactionString, "%d:%19[^:]:%lf:%ld:", &transaction.transaction_id, transaction.account_number, &transaction.amount, &transaction.timestamp);

    return transaction;
}

/**
 * Print all the transactions made by the user
 * @param directoryPath where there are the transactions
 */
void readFilesInDirectory(const char *directoryPath) {
    DIR *dir;
    struct dirent *entry;

    dir = opendir(directoryPath);

    if (dir == NULL) {
        printf("Impossibile aprire la directory %s\n", directoryPath);
        return;
    }

    printf("-------------------------------------------------\n");
    printf("| Transaction ID | Account Number | Amount   |\n");

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char filePath[256];
            strcpy(filePath, directoryPath);
            strcat(filePath, "/");
            strcat(filePath, entry->d_name);


            if (strstr(entry->d_name, ".txt") != NULL) {

                unsigned char *buffer = decryptFile(filePath);
                Transaction t = createTransactionFromString(buffer);
                printf("| %14d | %14s | %8.2f | \n", t.transaction_id, t.account_number, t.amount);
            }
        }
    }
    printf("-------------------------------------------------\n");

    closedir(dir);
}

/**
 * Print the transactions history of the user
 * @return
 */
int history() {
    unsigned char directoryPath[BUFFER_SIZE];
    sprintf(directoryPath, "../client/registered/%s/transactions", mySelf->username);

    readFilesInDirectory(directoryPath);
}

/**
 * Function that stop the user and save the data on file
 * @return
 */
int stop_executor() {

    unsigned char pathInfo[BUFFER_SIZE];
    snprintf(pathInfo, sizeof(pathInfo), "../client/registered/%s/info.txt", mySelf->username);

    char* formattedString = (char*)malloc(5 * BUFFER_SIZE * sizeof(char)); // Assumendo una lunghezza massima di BUFFER_SIZE caratteri per ogni campo
    sprintf(formattedString, "%s:%s:%s:%s:%f", mySelf->nome, mySelf->cognome, mySelf->username, mySelf->password, mySelf->balance);
    encryptFile(pathInfo, formattedString);

    unsigned char *buffer = decryptFile(pathInfo);
    system("clear");
    printf("\t\t\t\t\t ************ [*** GOODBYE! ***] ************ \n\n\n");

    close(server_sock);
    exit(1);
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

/** Function that save the transaction to file
 * @param received the received outcome of the server (if the transaction is good or not)
 * @param rec_len len of received transaction
 * @param transaction the transaction sent to the server
 * @return
 */
int saveTransaction(unsigned char* received, ssize_t rec_len, unsigned char* transaction) {

    unsigned char decrypted_message[BUFFER_SIZE];
    unsigned char transactioEsito[BUFFER_SIZE];
    size_t decrypted_message_len;

    decrypted_message_len = decrypt_message(received, rec_len, decrypted_message);

    memcpy(transactioEsito, decrypted_message, decrypted_message_len);

    if(!strcmp(transactioEsito, "OK")) {

        printf("\t\t\t\t\t [*** TRANSACTION APPROVED, STORING IT... ***]\n\n\n");

        char* name = NULL;
        char* amount = NULL;

        char* token = strtok(transaction, " ");
        if (token != NULL) {
            name = strdup(token);
        }

        token = strtok(NULL, " ");
        if (token != NULL) {
            amount = strdup(token);
        }

        int amountOfMoney = atoi(amount);

        Transaction t = createTransaction(numTransaction, name, amountOfMoney);
        addTransaction(t);

        char transaction_string[256];
        sprintf(transaction_string, "%d:%s:%.2f:%ld",
                numTransaction,
                t.account_number,
                t.amount,
                (long)t.timestamp);

        numTransaction++;

        unsigned char pathTransaction[BUFFER_SIZE];
        snprintf(pathTransaction, sizeof(pathTransaction), "../client/registered/%s/transactions/%d.txt", mySelf->username, t.transaction_id);

        encryptFile(pathTransaction, transaction_string);

        unsigned char* buffer = decryptFile(pathTransaction);

        printf("\t\t\t\t\t [*** TRANSACTION SAVED SUCCESSFULLY ***]\n\n\n");
        return 1;

    } else {
        printf("\t\t\t\t\t [*** TRANSACTION DECLINED ***]\n\n\n");
        return -1;
    }
}

/**
 * Function that allows to deposito some money to the bank account
 * @param amount of money
 * @return
 */
int deposit(char *amount) {

    int importValid = isFormatValid(amount);

    if (importValid == 1) {
        float amountOfMoney = 0;
        amountOfMoney = atof(amount);
        mySelf->balance += amountOfMoney;

        // Message to be sent
        unsigned char* msg = "8";
        size_t msg_len = strlen(msg);

        // Buffer to hold the encrypted message
        unsigned char en_message[BUFFER_SIZE];
        size_t en_message_len;

        // Encrypt the message
        en_message_len = encrypt_message(msg, msg_len, en_message);

        sendMessage(server_sock, en_message, en_message_len);

        sleep(2);

        // Message to be sent
        size_t message_len = strlen(amount);

        // Buffer to hold the encrypted message
        unsigned char encrypted_message[BUFFER_SIZE];
        size_t encrypted_message_len;

        // Encrypt the message
        encrypted_message_len = encrypt_message((const unsigned char*)amount, message_len, encrypted_message);

        unsigned char* signature = NULL;
        size_t signature_length = 0;

        int result = sign_message(encrypted_message, encrypted_message_len, pathPrivK, &signature, &signature_length);
        if (result != 0) {
            fprintf(stderr, "Failed to sign the message\n");
            return 1;
        }

        send_signed_message(server_sock, encrypted_message, encrypted_message_len, signature, signature_length);

        printf("\t\t\t\t\t [*** BALANCE REQUEST SENT TO THE SERVER, THANK YOU ***]\n\n\n");
        return 1;
    } else {
        printf("\t\t\t\t\t [*** INVALID IMPORT, TRY AGAIN ***]\n\n\n");
        return -1;
    }
}

/**
 * Function that send money to another user
 * @param message is in the form <User> <AmountOfMoney>. Will be parsed in the function.
 * @return
 */
int sendMoney(char* message) {

    // Verifico che il saldo sia sufficiente
    char* name = NULL;
    char* amount = NULL;
    unsigned char buffer[BUFFER_SIZE];
    memcpy(buffer, message, strlen(message));

    char* token = strtok(buffer, " ");
    if (token != NULL) {
        name = strdup(token);
    }

    token = strtok(NULL, " ");
    if (token != NULL) {
        amount = strdup(token);
    }

    if (name == NULL || amount == NULL) {
        printf("\t\t\t\t\t [*** PARAMETERS NOT VALID, TRY AGAIN ***]\n\n\n");
        return -1;
    }

    int result = isFormatValid(amount);

    if (result != 1) {
        printf("\t\t\t\t\t [*** INVALID AMOUNT ***]\n\n\n");
        return -1;
    }

    int amountOfMoney = atoi(amount);

    if (amountOfMoney > mySelf->balance) {
        printf("\t\t\t\t\t [*** CREDIT INSUFFICIENT, TRY AGAIN ***]\n\n\n");
        return -1;
    }

    unsigned char* msg = "9";
    size_t msg_len = strlen(msg);

    // Buffer to hold the encrypted message
    unsigned char en_message[BUFFER_SIZE];
    size_t en_message_len;

    // Encrypt the message
    en_message_len = encrypt_message(msg, msg_len, en_message);
    sendMessage(server_sock, en_message, en_message_len);

    sleep(2);

    // Message to be sent
    size_t message_len = strlen(message);

    // Buffer to hold the encrypted message
    unsigned char encrypted_message[BUFFER_SIZE];
    size_t encrypted_message_len;

    encrypted_message_len = encrypt_message((const unsigned char*)message, message_len, encrypted_message);

    unsigned char* signature = NULL;
    size_t signature_length = 0;

    result = sign_message(encrypted_message, encrypted_message_len, pathPrivK, &signature, &signature_length);
    if (result != 0) {
        fprintf(stderr, "Failed to sign the message\n");
        return 1;
    }

    send_signed_message(server_sock, encrypted_message, encrypted_message_len, signature, signature_length);

    printf("\t\t\t\t\t [*** TRANSACTION CREATED, MONEY SENT ***]\n\n\n");

    free(signature);

    unsigned char* rec = NULL;
    size_t rec_l = 0;
    unsigned char* rec_s = NULL;
    size_t rec_s_l = 0;

    int signatureValid = receive_signed_message(server_sock, &rec, &rec_l, &rec_s, &rec_s_l);
    int r = 0;

    if (signatureValid) {
        r = saveTransaction(rec, rec_l, message);

        if (r == 1) {
            updateBalance();
        }
    }

    free(rec_s);
    free(rec);

    return 1;
}

/**
 * Function that initialize paths
 */
void initializePaths() {

    char folderpath[256];

    const char *directory = "../client/registered";
    const char *filename = mySelf->username;

    snprintf(folderpath, sizeof(folderpath), "%s/%s", directory, filename);

    snprintf(pathPrivK, sizeof(pathPrivK), "%s/%s", folderpath, "private_key");
    snprintf(pathPubK, sizeof(pathPubK), "%s/%s", folderpath, "public_key");

    mySelf->pubKey = (EVP_PKEY **) readPublicKeyFromPEM(pathPubK);
}

/**
 * Function that show balance
 * @return
 */
int showBalance() {

    printf("*****************************\n");
    printf("*           %.2f€           *\n", mySelf->balance);
    printf("*****************************\n");
    printf("\n");
}

/**
 * Function that permit to login into the banck account
 * @param arg username and password
 * @return
 */
int login_executor(char* arg) {

    const char delimiter[] = " ";
    char *username = strtok(arg, delimiter);
    char *password = strtok(NULL, delimiter);

    if (checkExistingUser(username, password) == 1) {
        system("clear");  // For Unix/Linux
        printf("\t\t\t\t\t [*** LOGGED CORRECTLY, WELCOME %s ***]\n\n\n", mySelf->username);
        printf("\t\t\t\t\t*****************************\n");
        printf("\t\t\t\t\t*       Informazioni        *\n");
        printf("\t\t\t\t\t*****************************\n");
        printf("\t\t\t\t\t* Nome:     %-15s *\n", mySelf->nome);
        printf("\t\t\t\t\t* Cognome:  %-15s *\n", mySelf->cognome);
        printf("\t\t\t\t\t* Username: %-15s *\n", mySelf->username);
        printf("\t\t\t\t\t* Balance:  %-15.2f *\n", mySelf->balance);
        printf("\t\t\t\t\t*****************************\n");
        sleep(5);
        system("clear");  // For Unix/Linux
        initializePaths();
        return 1;
    }
    return -1;
}

/**
 * Perform the exchange of public keys and the computation of the shared secret.
 * It follows the algorithm of Diffie-Hellman
 */
void diffieHellman() {

    printf("\t\t\t\t\t [*** DIFFIE-HELLMAN EXCHANGE STARTED ***]\n\n\n");

    unsigned char* diffieMessage = "2Diffie";
    sendMessage(server_sock, diffieMessage, strlen(diffieMessage));

    // Create DH parameters
    DH* dh = create_dh_params();

    // Generate private and public keys
    if (!DH_generate_key(dh)) {
        handle_error("Failed to generate DH keys");
    }

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

    printf("\t\t\t\t\t [*** PUBLIC KEY SENT ***]\n\n\n");

    // Receive the server's public key (server_pub_key)
    unsigned char server_pub_key_data[MAX_KEY_SIZE];  // Adjust the buffer size accordingly
    int server_received_len = recv(server_sock, server_pub_key_data, sizeof(server_pub_key_data), 0);
    if (server_received_len <= 0) {
        handle_error("Failed to receive public key from server");
    }

    printf("\t\t\t\t\t [*** SERVER PUBLIC KEY RECEIVED ***]\n\n\n");

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

    printf("\t\t\t\t\t [*** SHARED SECRET COMPUTED SUCCESSFULLY ***]\n\n\n");

    // Use the shared secret for further communication

    // Buffer to hold the encrypted message
    unsigned char encrypted_message[BUFFER_SIZE];

    // Buffer to hold the decrypted message
    unsigned char decrypted_message[BUFFER_SIZE];
    size_t decrypted_message_len;

    size_t encrypted_message_len = recv(server_sock, encrypted_message, sizeof(encrypted_message), 0);

    // Decrypt the message
    decrypted_message_len = decrypt_message(encrypted_message, encrypted_message_len, decrypted_message);
}

/**
 * Function that verify the server's certificate
 * @param certFile where the file is stored (it is supposed that is the CA)
 * @return
 */
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
        fprintf(stderr, "\t\t\t\t\t [*** CERTIFICATE VERIFICATION FAILED ***]\n");
    } else {
        printf("\t\t\t\t\t [*** CERTIFICATE VERIFICATION SUCCEDED ***]\n");
    }

    // Cleanup
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert);

    return result;
}

/**
 * Hide the user input (used on password)
 */
void hideInput() {
    struct termios term;
    tcgetattr(fileno(stdin), &term);
    term.c_lflag &= ~ECHO;
    tcsetattr(fileno(stdin), TCSANOW, &term);
}

/**
 * Show the user input
 */
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
    unsigned char encryptedPublicKey[BUFFER_SIZE];  // Adjust the buffer size as needed
    size_t encryptedSize = encrypt_message(publicKeyBuffer, publicKeySize, encryptedPublicKey);

    // Send the encrypted public key over the socket
    result = send(socket, encryptedPublicKey, encryptedSize, 0);
    if (result < 0) {
        perror("Failed to send encrypted public key");
        free(publicKeyBuffer);
        return;
    }

    free(publicKeyBuffer);
}


void sendPubKey() {
    const char* msg = "6";
    size_t msg_len = strlen(msg);

    // Buffer to hold the encrypted message
    unsigned char en_message[BUFFER_SIZE];
    size_t en_message_len;

    // Encrypt the message
    en_message_len = encrypt_message((const unsigned char*)msg, msg_len, en_message);

    sendMessage(server_sock, en_message, en_message_len);

    sleep(5);

    EVP_PKEY *pubKey = readPublicKeyFromPEM(pathPubK);

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pubKey);

    char* pubkey_data;
    size_t pubkey_len = BIO_get_mem_data(bio, &pubkey_data);

    sendEncryptedPublicKey(server_sock, pubKey);
}

/**
 * Function that starts all the functionalities
 */
void startEngine() {

    unsigned char *message;
    struct sockaddr_in serv_addr;

    server = (struct server_info *) malloc(sizeof(struct server_info));

    mySelf = malloc(sizeof(PeerInfo));
    if (mySelf == NULL) {
        perror("Error in the allocation of PeerInfo");
        return;
    }

    // Initialize the transaction hash table
    mySelf->transaction_table.transactions = malloc(MAX_TRANSACTIONS * sizeof(Transaction));
    mySelf->transaction_table.transaction_count = 0;

    // Socket creation
    if ((server_sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Errore nella creazione del socket");
        return;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Conversion of IP address from string to binary format
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Indirizzo non valido / errore di conversione");
        return;
    }

    // Connection to the server
    if (connect(server_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connessione fallita");
        return;
    }

    server->server_sock = server_sock;

    /* Verify the identity of the server */
    verifySelfSignedCertificate("../server/certificate.pem");

    printf("\n\n   ****************************************** WELCOME TO SECURE BANK  ******************************************\n\n");

    char answer;

    do {
        printf("Are you already registered? [Y/n]\n> ");
        scanf(" %c", &answer);

        answer = toupper(answer);

        // Ignore any additional characters
        int c;
        while ((c = getchar()) != '\n' && c != EOF) {}

    } while (answer != 'Y' && answer != 'N');

    if (answer == 'Y' || answer == 'y') {

        int loginResult = -1;

        while (loginResult == -1) {
            printf("\nPlease, Sign In.\n");
            char username[50];
            char password[50];
            printf("\nUsername: \n> ");
            scanf("%s", username);

            printf("Password: \n>");
            hideInput(); // Nascondi l'input dell'utente
            scanf("%s", password);
            showInput(); // Mostra di nuovo l'input dell'utente

            char credentials[100];
            strcpy(credentials, username);
            strcat(credentials, " ");
            strcat(credentials, password);

            loginResult = login_executor(credentials);
        }

    } else if (answer == 'N' || answer == 'n') {
        printf("Please Sign Up.\n");
        system("clear");  // For Unix/Linux
        register_executor();
    }

    int stringLength = snprintf(NULL, 0, "1:%s", mySelf->username);

    message = malloc((stringLength + 1) * sizeof(char));
    sprintf(message, "1:%s", mySelf->username);
    send(server->server_sock, message, stringLength, 0);

    unsigned char receivedBuffer[BUFFER_SIZE];  // Definisci la dimensione massima del buffer
    int receivedSize = recv(server->server_sock, receivedBuffer, sizeof(receivedBuffer), 0);

    if (receivedSize <= 0) {
        perror("Failed to receive public key");
        return;
    }

    serverPublicKey = convertToPublicKey(receivedBuffer, receivedSize);
    if (serverPublicKey == NULL) {
        printf("Failed to convert received data to public key\n");
        return;
    }
    server->serverPublicKey = EVP_PKEY_dup(serverPublicKey);
    printf("\t\t\t\t\t [*** SERVER PUBLIC KEY STORED CORRECTLY! ***]\n\n\n");

    diffieHellman();

    unsigned char pathInfo[BUFFER_SIZE];
    unsigned char *folderpath = "../client/registered";

    if (registered) {
        unsigned char pathKey[BUFFER_SIZE];

        snprintf(pathKey, sizeof(pathKey), "%s/%s/%s", folderpath, mySelf->username, "key.txt");
        memcpy(keyStore, shared_secret, strlen(shared_secret));
        saveSharedSecretToFile(keyStore, strlen(keyStore), pathKey);

        snprintf(pathInfo, sizeof(pathInfo), "%s/%s/%s", folderpath, mySelf->username, "info.txt");

        char* formattedString = (char*)malloc(5 * BUFFER_SIZE * sizeof(char)); // Assumendo una lunghezza massima di BUFFER_SIZE caratteri per ogni campo
        sprintf(formattedString, "%s:%s:%s:%s:%f", mySelf->nome, mySelf->cognome, mySelf->username, mySelf->password, mySelf->balance);
        encryptFile(pathInfo, formattedString);

    } else {

        unsigned char pathKey[BUFFER_SIZE];
        snprintf(pathKey, sizeof(pathKey), "%s/%s/%s", folderpath, mySelf->username, "key.txt");
        snprintf(pathInfo, sizeof(pathInfo), "%s/%s/%s", folderpath, mySelf->username, "info.txt");
        loadSharedSecretFromFile(keyStore, pathKey);

        decryptFile(pathInfo);
    }

    // Set number of transactions
    unsigned char pathTransactions[BUFFER_SIZE];
    snprintf(pathTransactions, sizeof(pathTransactions), "%s/%s/transactions", folderpath, mySelf->username);
    numTransaction = countFilesInDirectory(pathTransactions);

    sendPubKey();
}

cmd_executor executors[] = {
        sendMoney,
        showBalance,
        deposit,
        history,
        stop_executor
};

/**
 * Process the command
 * @param cmd the command typed by the user
 * @param arg the arguments of the command
 * @return
 */
int process_command(const char* cmd, char* arg) {

    int i, ris;

    for (i = 0; i < COMMANDS; ++i){
        if (strcmp(cmd, valid_cmds[i]) == 0){
            ris = executors[i](arg);
            if (ris == -2){
                perror("Communication error with the server");
                return -1;
            }
            return ris;
        }
    }

    /* Invalid command */
    printf("Error: command not found\n");
    return 1;
}

/**
 * Function that elaborate the command typed by the user
 * @return
 */
int handle_cmd() {

    char* buf = NULL;
    size_t buf_len = 0;
    char* cmd = NULL;
    char* arg = NULL;
    int ris;

    buf_len = getline(&buf, &buf_len, stdin);

    if (buf_len > 0 && buf[0] != COMMAND_PREFIX) {
        free(buf);
        return -1;
    }

    if (parse_command(buf, buf_len, &cmd, &arg) == -1) {
        /* line contains only '!' */
        printf("Error: command not specified\n");
        free(buf);
        return -1;
    }

    ris = process_command(cmd, arg);
    free(buf);
    return ris;
}

int main() {
    int i;

    startEngine();

    /* Reset of descriptors */
    FD_ZERO(&master);
    FD_ZERO(&read_fds);

    /* I add the File Descriptor of the STD-INPUT to the monitored sockets */
    FD_SET(STDIN_FILENO, &master);
    FD_SET(server_sock, &master);

    fdmax = (server_sock > STDIN_FILENO) ? server_sock : STDIN_FILENO;

    while(1) {

        print_help();

        read_fds = master;

        select(fdmax + 1, &read_fds, NULL, NULL, NULL);
        for (i=0; i<=fdmax; i++) {

            if (FD_ISSET(i, &read_fds)) {

                if (i == STDIN_FILENO) {
                    handle_cmd();
                } else {
                    // Server shutdown request
                    stop_executor();
                }
            }
        }
    }
}
