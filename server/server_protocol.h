#include "server.h"
#ifndef SECUREBANK_SERVER_PROTOCOL_H
#define SECUREBANK_SERVER_PROTOCOL_H


/** Executors Functions **/
int help_executor(char* arg);
int esc_executor(char* arg);
int close_executor(char* arg);

/** Entry Functions **/
Entry* createEntry(PeerInfo* value);
EntryList* createEntryList();
void insertEntry(EntryList* list, PeerInfo* value);
Entry* findEntryByUsername(EntryList* list, const char* username);
void printEntryList(EntryList* list);
Entry* findEntryByKey(EntryList* list, int key);

/** Transactions Functions **/
void updateDestBalance(PeerInfo *peer);
void elaborateTransaction(unsigned char *username, float amount, int sd);

/** Utility Functions **/
void handle_error(const char* error_message);
void initializePaths();
void print_hex(const unsigned char* data, size_t data_len, const unsigned char* title);
void print_help();
int parse_command(char* line, size_t line_len, char** cmd, char** arg);
int process_command(const char* cmd, char* arg);
void readPeerInfoFromFolders(const char* parentFolder);

/** Certificates Functions **/
void generate_private_key_and_certificate();
X509* generateSelfSignedCertificate(EVP_PKEY* privateKey);

/** Diffie-Hellman Functions **/
DH* create_dh_params();
void diffieHellman(int client_socket);

/** Keys Functions **/
void generate_public_key();
EVP_PKEY* generate_keypair(const char* private_key_file, const char* public_key_file);
void sendPublicKey(int socket, EVP_PKEY* publicKey);
EVP_PKEY* readPrivateKeyFromPEM(const char* filename);
EVP_PKEY* readPublicKeyFromPEM(const char* filename);
void printEvpKey(EVP_PKEY *key);
void printPrivateKey(const EVP_PKEY* privateKey);
EVP_PKEY* convertToPublicKey(unsigned char* buffer, int bufferSize);

/** Encryption / Decryption Messages Functions **/
void calculate_hmac(const unsigned char* data, size_t data_len, const unsigned char* key, size_t key_len, unsigned char* hmac);
size_t encrypt_message(const unsigned char* plaintext, size_t plaintext_len, unsigned char* ciphertext);
size_t decrypt_message(unsigned char* ciphertext, size_t ciphertext_len, unsigned char* plaintext);
int extract_values(const unsigned char* ciphertext, size_t ciphertext_len, unsigned char* iv, unsigned char* nonce, unsigned char* hmac, const unsigned char* key, size_t key_len);
void sendMessage(int socket, unsigned char *buffer, int buffer_len);
void send_signed_message(int socket, const unsigned char* message, size_t message_length, const unsigned char* signature, size_t signature_length);
int receive_signed_message(int socket, unsigned char** message, size_t* message_length, unsigned char** signature, size_t* signature_length, EVP_PKEY* public_key);
int sign_message(const unsigned char* message, size_t message_length, const char* private_key_path, unsigned char** signature, size_t* signature_length);
int verify_signature(const unsigned char* message, size_t message_length, const unsigned char* signature, size_t signature_length,  EVP_PKEY* public_key);


/** Encryption / Decryption Files Functions **/
void loadSharedSecretFromFile(unsigned char* keyStore, const char* keyPath);
void generateRandomIV(unsigned char *iv, int iv_len);
void encryptFile(unsigned char* ciphertext_file, char *string, unsigned char *keyStore);
unsigned char* decryptFile(const char* ciphertext_file, unsigned char* keyStore);

#endif //SECUREBANK_SERVER_PROTOCOL_H
