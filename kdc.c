#include <netinet/in.h> // For sockaddr_in
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <openssl/crypto.h>
#include <unistd.h>
#include <pthread.h>

// kdc.c 
#define CLIENT_PORT 9001
#define MAX_CLIENTS 10
#define BUFFER_SIZE 255
#define IV_LEN 12
#define KEY_LEN 32
#define NONCE_SIZE 16
#define TAG_LEN 16

typedef struct
{
    int client_socket;
} client_args;

#define MAX_USERNAME 64
#define MAX_TICKET_DATA 1024
#define MAX_FILE_SIZE 10485760

typedef struct
{
    char username[MAX_USERNAME];
    unsigned char key[KEY_LEN];
} user_credentials;

typedef struct
{
    unsigned char nonce[NONCE_SIZE];
    unsigned char data[BUFFER_SIZE];
    size_t data_len;
    unsigned char tag[TAG_LEN];
} secured_message;

user_credentials users[] = {
    {"ALICE", {0}},
    {"bob", {0}},
    {"charlie", {0}}};
int num_users = 3;

pthread_mutex_t user_mutex = PTHREAD_MUTEX_INITIALIZER;

unsigned char print_server_key[KEY_LEN];

// Find user by username
user_credentials *find_user(const char *username)
{
    pthread_mutex_lock(&user_mutex);
    for (int i = 0; i < num_users; i++)
    {
        if (strcmp(users[i].username, username) == 0)
        {
            pthread_mutex_unlock(&user_mutex);
            return &users[i];
        }
    }
    pthread_mutex_unlock(&user_mutex);
    return NULL;
}

// Derive key from password using PBKDF2
void derive_key(const char *password, unsigned char *key, unsigned char *salt)
{
    // Use a fixed salt for development/testing purposes
    unsigned char fixed_salt[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

    if (salt == NULL)
    {
        // Always use the same fixed salt
        PKCS5_PBKDF2_HMAC(password, strlen(password),
                          fixed_salt, 16,
                          10000, EVP_sha256(),
                          KEY_LEN, key);
    }
    else
    {
        // Use the provided salt
        PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt, 16,
                          10000, EVP_sha256(),
                          KEY_LEN, key);
    }
}

// Initialize user keys from passwords
void init_user_keys()
{
    derive_key("password", users[0].key, NULL);
    derive_key("password", users[1].key, NULL);
    derive_key("password", users[2].key, NULL);

    derive_key("printserverpass", print_server_key, NULL);
}

int encrypt_data(unsigned char *plaintext, size_t plaintext_len,
                 unsigned char *key, unsigned char *iv,
                 unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Initialize encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
    {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    // Provide the message to be encrypted, and obtain the encrypted output
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    ciphertext_len += len;

    // Get the tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag))
    {
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }

    //printf("\nWe encrypting this one.\n");

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

// Decrypt data using AES-GCM
int decrypt_data(unsigned char *ciphertext, size_t ciphertext_len,
                 unsigned char *key, unsigned char *iv, unsigned char *tag,
                 unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len, ret;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    // Initialize decryption operation
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
        return -1;

    // Provide the message to be decrypted, and obtain the decrypted output
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        return -1;
    plaintext_len = len;

    // Set expected tag value
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag))
        return -1;

    // Finalize decryption. A positive return value indicates success,
    // anything else is a failure - the plaintext is not trustworthy.
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        // Success
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        // Verify failed
        return -1;
    }
}

// Generate a ticket for the print server
size_t generate_ticket(const char *username, unsigned char *session_key, unsigned char *ticket) {
    // Create ticket structure
    time_t now = time(NULL);
    time_t expiry = now + 3600; // Valid for 1 hour
    
    // Ticket data: username, session key, timestamp, expiry
    unsigned char ticket_data[MAX_TICKET_DATA];
    size_t username_len = strlen(username);
    
    // Copy username and add null terminator
    memcpy(ticket_data, username, username_len);
    ticket_data[username_len] = '\0';  // Add the null terminator
    
    // Then copy the rest of the data
    memcpy(ticket_data + username_len + 1, session_key, KEY_LEN);
    memcpy(ticket_data + username_len + 1 + KEY_LEN, &now, sizeof(time_t));
    memcpy(ticket_data + username_len + 1 + KEY_LEN + sizeof(time_t), &expiry, sizeof(time_t));
    
    // Calculate ticket data length
    size_t ticket_data_len = username_len + 1 + KEY_LEN + 2 * sizeof(time_t);
    
    // Encrypt ticket with print server's key
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    RAND_bytes(iv, IV_LEN);
    memcpy(ticket, iv, IV_LEN);
    size_t ciphertext_len = encrypt_data(ticket_data, ticket_data_len,
                                        print_server_key, iv,
                                        ticket + IV_LEN, tag);
    // Add tag to the end
    memcpy(ticket + IV_LEN + ciphertext_len, tag, TAG_LEN);
    return IV_LEN + ciphertext_len + TAG_LEN;
}

void *handle_client(void *arg)
{
    client_args *args = (client_args *)arg;
    int client_socket = args->client_socket;
    free(args);

    unsigned char buffer[BUFFER_SIZE];
    int read_size;

    // GET THE USERNAME FROM CLIENT//////////////////////

    // Receive username and nonce
    memset(buffer, 0, BUFFER_SIZE);
    read_size = recv(client_socket, buffer, BUFFER_SIZE, 0);

    if (read_size <= 0)
    {
        close(client_socket);
        return NULL;
    }

    // Extract username and nonce
    char username[MAX_USERNAME];
    unsigned char nonce[NONCE_SIZE];
    strncpy(username, (char *)buffer, MAX_USERNAME);
    memcpy(nonce, buffer + strlen(username) + 1, NONCE_SIZE);

    printf("Received authentication request from: %s\n", username);
    printf("username: %s\n", username);

    // SEND CLIENT THE CHALLENGE//////////////////////

    // Find user in database
    user_credentials *user = find_user(username);
    if (!user)
    {
        printf("User not found: %s\n", username);
        close(client_socket);
        return NULL;
    }

    unsigned char response[BUFFER_SIZE];
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    RAND_bytes(iv, IV_LEN);

    // Encrypt nonce with user's key to create challenge response
    memcpy(response, iv, IV_LEN);
    size_t response_len = encrypt_data(nonce, NONCE_SIZE,
                                       user->key, iv,
                                       response + IV_LEN, tag);
    memcpy(response + IV_LEN + response_len, tag, TAG_LEN);

    // printf("Server -> Key: ");
    // for(int i=0; i<KEY_LEN; i++) printf("%02x", user->key[i]);
    // printf("\n");

    printf("Sending Challenge to %s\n", user->username);
    // Send challenge response to client
    send(client_socket, response, IV_LEN + response_len + TAG_LEN, 0);

    // CHECK CLIENT RESPONSE TO CHALLENGE AND GIVE TICKET//////////////////////

    // Receive client's response to the challenge
    memset(buffer, 0, BUFFER_SIZE);
    read_size = recv(client_socket, buffer, BUFFER_SIZE, 0);
    
    if (read_size <= 0) {
        close(client_socket);
        return NULL;
    }

    // Verify client's response
    unsigned char server_nonce[NONCE_SIZE];
    RAND_bytes(server_nonce, NONCE_SIZE);

    // Extract IV and tag from response
    unsigned char resp_iv[IV_LEN];
    unsigned char resp_data[BUFFER_SIZE];
    unsigned char resp_tag[TAG_LEN];

    memcpy(resp_iv, buffer, IV_LEN);
    memcpy(resp_tag, buffer + read_size - TAG_LEN, TAG_LEN);

    // Decrypt and verify client's response
    int resp_len = decrypt_data(buffer + IV_LEN, read_size - IV_LEN - TAG_LEN,
                                user->key, resp_iv, resp_tag, resp_data);

    if (resp_len <= 0)
    {
        printf("Authentication failed for user: %s\n", username);
        close(client_socket);
        return NULL;
    }

    // Client authenticated successfully
    printf("User %s authenticated successfully\n", username);

    // Generate session key for client and print server
    unsigned char session_key[KEY_LEN];
    RAND_bytes(session_key, KEY_LEN);

    // Generate ticket for print server
    unsigned char ticket[BUFFER_SIZE];
    size_t ticket_size = generate_ticket(username, session_key, ticket);

    // Create response for client containing session key and ticket
    unsigned char auth_response[BUFFER_SIZE];
    unsigned char auth_data[BUFFER_SIZE];

    // Structure auth_data: server_nonce + session_key + ticket
    memcpy(auth_data, server_nonce, NONCE_SIZE);
    memcpy(auth_data + NONCE_SIZE, session_key, KEY_LEN);
    memcpy(auth_data + NONCE_SIZE + KEY_LEN, ticket, ticket_size);
    size_t auth_data_len = NONCE_SIZE + KEY_LEN + ticket_size;

    // Encrypt auth_data with user's key
    unsigned char auth_iv[IV_LEN];
    unsigned char auth_tag[TAG_LEN];
    RAND_bytes(auth_iv, IV_LEN);

    memcpy(auth_response, auth_iv, IV_LEN);
    size_t auth_response_len = encrypt_data(auth_data, auth_data_len,
                                            user->key, auth_iv,
                                            auth_response + IV_LEN, auth_tag);
    memcpy(auth_response + IV_LEN + auth_response_len, auth_tag, TAG_LEN);

    // Send authentication response to client
    send(client_socket, auth_response, IV_LEN + auth_response_len + TAG_LEN, 0);

    printf("Sent ticket and session key to user: %s\n", username);

    // free(ct_bin);
    close(client_socket);
    pthread_exit(NULL);
}

int main(int argc, char const *argv[])
{
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    init_user_keys();

    int servSockD = socket(AF_INET, SOCK_STREAM, 0);
    if (servSockD == -1)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(servSockD, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in servAddr;
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(CLIENT_PORT);
    servAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(servSockD, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0)
    {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(servSockD, MAX_CLIENTS) < 0)
    {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server started. Listening on port %d...\n", CLIENT_PORT);

    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int clientSocket = accept(servSockD, (struct sockaddr *)&client_addr, &client_len);

        if (clientSocket < 0)
        {
            perror("Accept failed");
            continue;
        }

        printf("New client connected\n");

        client_args *args = malloc(sizeof(client_args));
        if (!args)
        {
            perror("Memory allocation failed");
            close(clientSocket);
            continue;
        }

        args->client_socket = clientSocket;

        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, handle_client, (void *)args) < 0)
        {
            perror("Thread creation failed");
            close(clientSocket);
            free(args);
            continue;
        }

        pthread_detach(thread_id);
    }

    // This line might never be reached, but it's good practice.
    close(servSockD);
    return 0;
}