#include "client.h"
#ifndef SECUREBANK_CLIENT_PROTOCOL_H
#define SECUREBANK_CLIENT_PROTOCOL_H

/** Executors Functions **/
int register_executor();
int login_executor(char* arg);
int stop_executor();
int history();
int showBalance();


/** Diffie-Hellman Functions **/
DH* create_dh_params();
void diffieHellman();

/** Transaction Functions **/
Transaction createTransaction(int trans_id, const char* account_num, float amount);
Transaction createTransactionFromString(const char* transactionString);
void addTransaction(Transaction transaction);
int saveTransaction(unsigned char* received, ssize_t rec_len, unsigned char* transaction);
void printDate(time_t currentTime);
char* generateRandomString(int length);

/** Encryption / Decryption Files Functions **/
void generateRandomIV(unsigned char *iv, int iv_len);
void encryptFile(unsigned char* ciphertext_file, char *string);
unsigned char* decryptFile(const char* ciphertext_file);
void saveSharedSecretToFile(const unsigned char* keyStore, size_t sharedSecretSize, const char* keyPath);
int loadSharedSecretFromFile(unsigned char* keyStore, const char* keyPath);
void calculate_hmac(const unsigned char* data, size_t data_len, const unsigned char* key, size_t key_len, unsigned char* hmac);
int extract_values(const unsigned char* ciphertext, size_t ciphertext_len, unsigned char* iv, unsigned char* nonce, unsigned char* hmac, const unsigned char* key, size_t key_len);
size_t encrypt_message(const unsigned char* plaintext, size_t plaintext_len, unsigned char* ciphertext);
size_t decrypt_message(const unsigned char* ciphertext, size_t ciphertext_len, unsigned char* plaintext);

/** Encryption / Decryption Messages Functions **/
int sign_message(const unsigned char* message, size_t message_length, const char* private_key_path, unsigned char** signature, size_t* signature_length);
int verify_signature(const unsigned char* message, size_t message_length, const unsigned char* signature, size_t signature_length,  EVP_PKEY* public_key);
void send_signed_message(int socket, const unsigned char* message, size_t message_length, const unsigned char* signature, size_t signature_length);
int receive_signed_message(int socket, unsigned char** message, size_t* message_length, unsigned char** signature, size_t* signature_length);
void sendMessage(int socket, unsigned char *buffer, int buffer_len);

/** Keys Functions **/
EVP_PKEY* readPublicKeyFromPEM(const char* filename);
EVP_PKEY* readPrivateKeyFromPEM(const char* filename);
void printEvpKey(EVP_PKEY *key);
void printPrivateKey(const EVP_PKEY* privateKey);
EVP_PKEY* generate_keypair(const char* private_key_file, const char* public_key_file);
EVP_PKEY* convertToPublicKey(unsigned char* buffer, int bufferSize);
void sendPublicKey(int socket, EVP_PKEY* publicKey);
void sendPubKey();
void sendEncryptedPublicKey(int socket, EVP_PKEY* publicKey);

/** Certificates Functions **/
int verifySelfSignedCertificate(const char* certFile);

/** Utility **/
int countFilesInDirectory(const char* directoryPath);
void readFilesInDirectory(const char *directoryPath);
void print_hex(const unsigned char* data, size_t data_len, const unsigned char* title);
int isFormatValid(const char* input);
int checkExistingUser(const char* username, const char* pwd);
void print_help();
int parse_command(char* line, size_t line_len, char** cmd, char** arg);
void handle_error(const char* error_message);
void initializePaths();
void hideInput();
void showInput();
void startEngine();
int process_command(const char* cmd, char* arg);
int handle_cmd();

/** Balance Functions **/
void updateBalance();
int deposit(char *amount);
int sendMoney(char* message);

#endif //SECUREBANK_CLIENT_H
