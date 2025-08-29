#include <netinet/in.h> //structure for storing address information
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h> //for socket APIs
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/sha.h> 
#include <time.h>
#include <string.h>
#include <unistd.h>

// client.c

#define KDC_PORT 9001
#define PRINT_PORT 9010
#define KEY_LEN 32
#define IV_LEN 12
#define TAG_LEN 16
#define NONCE_SIZE 16

#define BUFFER_SIZE 4096

typedef struct
{
    unsigned char nonce[NONCE_SIZE];
    unsigned char data[BUFFER_SIZE];
    size_t data_len;
    unsigned char tag[TAG_LEN];
} secured_message;

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

// Encrypt data using AES-GCM
int encrypt_data(unsigned char *plaintext, size_t plaintext_len,
                 unsigned char *key, unsigned char *iv,
                 unsigned char *ciphertext, unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new()))
        return -1;

    // Initialize encryption operation
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv))
        return -1;

    // Provide the message to be encrypted, and obtain the encrypted output
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        return -1;
    ciphertext_len = len;

    // Finalize encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        return -1;
    ciphertext_len += len;

    // Get the tag
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag))
        return -1;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

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

// Function to calculate SHA-256 checksum
void print_sha256(const unsigned char *data, size_t data_len) {
    unsigned char output[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx;
    // Create a context for the hash operation
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, data, data_len);
    unsigned int output_len;
    EVP_DigestFinal_ex(mdctx, output, &output_len); 

    EVP_MD_CTX_free(mdctx);

    // Print the SHA-256 checksum
    printf("PRINTER -> SHA-256 checksum of the received file data: ");
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", output[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s <username> <password> <filename>\n", argv[0]);
        return 1;
    }

    char *username = argv[1];
    char *password = argv[2];
    char *filename = argv[3];

    // OpenSSL_add_all_algorithms();
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    unsigned char *ticket;
    size_t ticket_size;
    unsigned char buffer[BUFFER_SIZE];
    int read_size;
    unsigned char session_key[KEY_LEN];

    int sockD = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in servAddr;
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(KDC_PORT);
    servAddr.sin_addr.s_addr = INADDR_ANY;

    int connectStatus = connect(sockD, (struct sockaddr *)&servAddr,
                                sizeof(servAddr));

    if (connectStatus == -1)
    {
        printf("Error connecting to server...\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        // char message[32];
        // time_t seconds = time(NULL);
        // sprintf(message, "ALICE%ld", seconds);

        // unsigned char salt[SALT_SIZE] = {0};
        //  unsigned char key[KEY_LEN];
        //  unsigned char iv[IV_LEN];
        //  int iv_len = IV_LEN;
        //  unsigned char tag[TAG_LEN];
        //  unsigned char ciphertext[BUFFER_SIZE];

        unsigned char user_key[KEY_LEN];
        derive_key(password, user_key, NULL);

        // Generate nonce
        unsigned char client_nonce[NONCE_SIZE];
        if (!RAND_bytes(client_nonce, NONCE_SIZE))
        {
            printf("Error generating NONCE.\n");
            exit(EXIT_FAILURE);
        }

        // int ciphertext_len = gcm_encrypt((unsigned char *)message, strlen(message),
        //                                  (unsigned char *)"ALICE", 5,
        //                                  key, iv, iv_len,
        //                                  ciphertext, tag);

        // Send username and nonce to KDC
        unsigned char auth_request[BUFFER_SIZE];
        strcpy((char *)auth_request, username);
        memcpy(auth_request + strlen(username) + 1, client_nonce, NONCE_SIZE);

        send(sockD, auth_request, strlen(username) + 1 + NONCE_SIZE, 0);

        printf("Original auth_request: %s (length: %zu)\n", auth_request, strlen((const char *)auth_request));

        // Receive challenge from KDC
        read_size = recv(sockD, buffer, sizeof(buffer), 0);

        if (read_size <= 0)
        {
            perror("Failed to receive from KDC");
            close(sockD);
            return 1;
        }


        // Extract IV and tag from challenge
        unsigned char challenge_iv[IV_LEN];
        unsigned char challenge_tag[TAG_LEN];

        memcpy(challenge_iv, buffer, IV_LEN);
        memcpy(challenge_tag, buffer + read_size - TAG_LEN, TAG_LEN);

        // Decrypt challenge
        unsigned char challenge_data[BUFFER_SIZE];
        int challenge_len = decrypt_data(buffer + IV_LEN, read_size - IV_LEN - TAG_LEN,
                                         user_key, challenge_iv, challenge_tag, challenge_data);

        if (challenge_len <= 0 || challenge_len != NONCE_SIZE ||
            memcmp(challenge_data, client_nonce, NONCE_SIZE) != 0)
        {
            printf("Challenge received: ");
            for (int i = 0; i < challenge_len; i++)
                printf("%02x", challenge_data[i]);
            printf("\n");
            fprintf(stderr, "Challenge verification failed\n");
            close(sockD);
            return 1;
        }
        printf("Client Challenge Accepted.\n");
        //  Send response to challenge//////////////////////////
        unsigned char response[BUFFER_SIZE];
        unsigned char response_iv[IV_LEN];
        unsigned char response_tag[TAG_LEN];
        RAND_bytes(response_iv, IV_LEN);

        memcpy(response, response_iv, IV_LEN);
        int response_len = encrypt_data(challenge_data, NONCE_SIZE,
                                        user_key, response_iv,
                                        response + IV_LEN, response_tag);
        memcpy(response + IV_LEN + response_len, response_tag, TAG_LEN);

        send(sockD, response, IV_LEN + response_len + TAG_LEN, 0);

        // Receive ticket and session key
        read_size = recv(sockD, buffer, sizeof(buffer), 0);

        if (read_size <= 0)
        {
            perror("Failed to receive ticket from KDC");
            close(sockD);
            return 1;
        }

        // Extract IV and tag
        unsigned char ticket_iv[IV_LEN];
        unsigned char ticket_tag[TAG_LEN];

        memcpy(ticket_iv, buffer, IV_LEN);
        memcpy(ticket_tag, buffer + read_size - TAG_LEN, TAG_LEN);

        // Decrypt ticket data
        unsigned char ticket_data[BUFFER_SIZE];
        int ticket_data_len = decrypt_data(buffer + IV_LEN, read_size - IV_LEN - TAG_LEN,
                                           user_key, ticket_iv, ticket_tag, ticket_data);

        if (ticket_data_len <= 0)
        {
            fprintf(stderr, "Failed to decrypt ticket data\n");
            close(sockD);
            return 1;
        }

        // Extract server nonce, session key, and ticket
        unsigned char server_nonce[NONCE_SIZE];

        ticket = ticket_data + NONCE_SIZE + KEY_LEN;
        ticket_size = ticket_data_len - NONCE_SIZE - KEY_LEN;

        memcpy(server_nonce, ticket_data, NONCE_SIZE);
        memcpy(session_key, ticket_data + NONCE_SIZE, KEY_LEN);

        printf("Received ticket and session key from KDC\n");
        close(sockD);
    }

    int sockPrinter = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in printerAddr;
    printerAddr.sin_family = AF_INET;
    printerAddr.sin_port = htons(PRINT_PORT);
    printerAddr.sin_addr.s_addr = INADDR_ANY;

    int connectStatusPrinter = connect(sockPrinter, (struct sockaddr *)&printerAddr,
                                       sizeof(printerAddr));
    if (connectStatusPrinter == -1)
    {
        printf("Error connecting to printer...\n");
        exit(EXIT_FAILURE);
    }
    else
    {
        // Generate new client nonce for print server
        unsigned char print_client_nonce[NONCE_SIZE];
        RAND_bytes(print_client_nonce, NONCE_SIZE);
        // Send ticket and nonce to printer /////////////////////////////////////////
        size_t ticket_len = ticket_size;
        unsigned char print_auth[BUFFER_SIZE];
        memcpy(print_auth, print_client_nonce, NONCE_SIZE);
        memcpy(print_auth + NONCE_SIZE, &ticket_len, sizeof(size_t));
        memcpy(print_auth + NONCE_SIZE + sizeof(size_t), ticket, ticket_len);

        send(sockPrinter, print_auth, NONCE_SIZE + sizeof(size_t) + ticket_len, 0);

        // Receive challenge from print server /////////////////////////////////////////
        read_size = recv(sockPrinter, buffer, sizeof(buffer), 0);
        if (read_size <= 0)
        {
            perror("Failed to receive from print server");
            close(sockPrinter);
            return 1;
        }
        printf("Received challenge from printer.\n");

        // Extract IV and tag from the challenge message
        unsigned char challenge_iv[IV_LEN];
        unsigned char challenge_tag[TAG_LEN];
        memcpy(challenge_iv, buffer, IV_LEN);
        memcpy(challenge_tag, buffer + read_size - TAG_LEN, TAG_LEN);

        // Decrypt the challenge
        unsigned char decrypted_challenge[BUFFER_SIZE];
        int decrypted_len = decrypt_data(buffer + IV_LEN, read_size - IV_LEN - TAG_LEN,
                                         session_key, challenge_iv, challenge_tag, decrypted_challenge);

        if (decrypted_len <= 0)
        {
            fprintf(stderr, "Failed to decrypt challenge from print server\n");
            close(sockPrinter);
            return 1;
        }

        // Verify the client nonce in the challenge
        if (decrypted_len != NONCE_SIZE * 2 ||
            memcmp(decrypted_challenge, print_client_nonce, NONCE_SIZE) != 0)
        {
            fprintf(stderr, "Print server challenge verification failed\n");
            close(sockPrinter);
            return 1;
        }
        printf("Challenge from printer verified successfully.\n");

        // Extract the server nonce from the challenge (second half)
        unsigned char server_nonce[NONCE_SIZE];
        memcpy(server_nonce, decrypted_challenge + NONCE_SIZE, NONCE_SIZE);

        //  KEEP IN MIND -------->    Define the secured_message structure (must match the server's definition)

        // Prepare a secured_message for the response
        secured_message response;
        memset(&response, 0, sizeof(secured_message));

        // Set the nonce field to the original client (print) nonce
        memcpy(response.nonce, print_client_nonce, NONCE_SIZE);

        // Generate a random IV for encryption
        unsigned char response_iv[IV_LEN];
        if (!RAND_bytes(response_iv, IV_LEN))
        {
            fprintf(stderr, "Error generating response IV\n");
            close(sockPrinter);
            return 1;
        }

        // Place the IV at the beginning of the data field
        memcpy(response.data, response_iv, IV_LEN);

        // Encrypt the server nonce (challenge part) using the session key and the generated IV
        int ciphertext_len = encrypt_data(server_nonce, NONCE_SIZE,
                                          session_key, response_iv,
                                          response.data + IV_LEN, response.tag);
        if (ciphertext_len < 0)
        {
            fprintf(stderr, "Encryption failed\n");
            close(sockPrinter);
            return 1;
        }

        // Set data_len to the total length of the IV plus ciphertext
        response.data_len = IV_LEN + ciphertext_len;

        // Send the secured_message structure to the printer
        printf("Sending secured response to printer.\n");
        if (send(sockPrinter, &response, sizeof(secured_message), 0) < 0)
        {
            fprintf(stderr, "Failed to send response to printer\n");
            close(sockPrinter);
            return 1;
        }

        // Receive authentication success message /////////////////////////////////////
        read_size = recv(sockPrinter, buffer, sizeof(buffer), 0);
        if (read_size <= 0)
        {
            perror("Failed to receive authentication confirmation");
            close(sockPrinter);
            return 1;
        }

        // Decrypt success message (assuming similar message formatting as before)
        unsigned char success_iv[IV_LEN];
        unsigned char success_tag[TAG_LEN];
        unsigned char success_data[BUFFER_SIZE];
        memcpy(success_iv, buffer, IV_LEN);
        memcpy(success_tag, buffer + read_size - TAG_LEN, TAG_LEN);
        int success_len = decrypt_data(buffer + IV_LEN, read_size - IV_LEN - TAG_LEN,
                                       session_key, success_iv, success_tag, success_data);
        if (success_len <= 0)
        {
            fprintf(stderr, "Failed to decrypt authentication confirmation\n");
            close(sockPrinter);
            return 1;
        }
        printf("Authentication to print server successful: %s\n", success_data);

        // AUTHENTICATION COMPLETED HERE-------------------------------------
        FILE *file = fopen(filename, "rb");
        if (!file)
        {
            fprintf(stderr, "Error: Cannot open file '%s'\n", filename);
            close(sockPrinter);
            return 1;
        }

        // Determine file size
        fseek(file, 0, SEEK_END);
        size_t file_size = ftell(file);
        fseek(file, 0, SEEK_SET);

        if (file_size > BUFFER_SIZE - sizeof(char[10]) - sizeof(size_t))
        {
            fprintf(stderr, "Error: File too large (max size: %ld bytes)\n",
                    BUFFER_SIZE - sizeof(char[10]) - sizeof(size_t));
            fclose(file);
            close(sockPrinter);
            return 1;
        }

        // Determine file format from filename extension
        char file_format[10] = {0};
        char *dot = strrchr(filename, '.');
        if (dot && strlen(dot + 1) < sizeof(file_format))
        {
            strncpy(file_format, dot + 1, sizeof(file_format) - 1);
        }
        else
        {
            strcpy(file_format, "txt"); // Default to txt if no extension found
        }

        printf("Sending %s file (format: %s, size: %zu bytes)\n", filename, file_format, file_size);

        // Create file data buffer with metadata + content
        unsigned char file_buffer[BUFFER_SIZE];
        // First store file format (10 bytes)
        memcpy(file_buffer, file_format, sizeof(file_format));
        // Then store file size
        memcpy(file_buffer + sizeof(file_format), &file_size, sizeof(size_t));
        // Then read and store the actual file content
        if (fread(file_buffer + sizeof(file_format) + sizeof(size_t), 1, file_size, file) != file_size)
        {
            fprintf(stderr, "Error reading file\n");
            fclose(file);
            close(sockPrinter);
            return 1;
        }
        fclose(file);

        //unsigned char file_sha256[SHA256_DIGEST_LENGTH];
        print_sha256(file_buffer + sizeof(file_format) + sizeof(size_t), file_size);

        // Prepare a secured message for the file
        secured_message file_msg;
        memset(&file_msg, 0, sizeof(secured_message));

        // Set the nonce field to the original client nonce
        memcpy(file_msg.nonce, print_client_nonce, NONCE_SIZE);

        // Generate random IV for file encryption
        unsigned char file_iv[IV_LEN];
        if (!RAND_bytes(file_iv, IV_LEN))
        {
            fprintf(stderr, "Error generating file IV\n");
            close(sockPrinter);
            return 1;
        }

        // Place the IV at the beginning of the data field
        memcpy(file_msg.data, file_iv, IV_LEN);

        // Calculate total size of the file data with metadata
        size_t total_file_data_size = sizeof(file_format) + sizeof(size_t) + file_size;

        // Encrypt the file data using the session key
        int file_ciphertext_len = encrypt_data(
            file_buffer,
            total_file_data_size,
            session_key,
            file_iv,
            file_msg.data + IV_LEN,
            file_msg.tag);

        if (file_ciphertext_len < 0)
        {
            fprintf(stderr, "File encryption failed\n");
            close(sockPrinter);
            return 1;
        }

        // Set data_len to the total length of the IV plus ciphertext
        file_msg.data_len = IV_LEN + file_ciphertext_len;

        // Send the encrypted file to the print server
        printf("Sending encrypted file to print server...\n");
        if (send(sockPrinter, &file_msg, sizeof(secured_message), 0) != sizeof(secured_message))
        {
            fprintf(stderr, "Failed to send file to print server\n");
            close(sockPrinter);
            return 1;
        }

        // Receive the converted PDF file from the print server
        printf("Waiting for converted PDF from print server...\n");

        secured_message pdf_msg;
        read_size = recv(sockPrinter, &pdf_msg, sizeof(secured_message), 0);
        if (read_size <= 0)
        {
            fprintf(stderr, "Failed to receive PDF from print server\n");
            close(sockPrinter);
            return 1;
        }

        printf("Expected nonce: ");
        for (int i = 0; i < NONCE_SIZE; i++) {
            printf("%02x", print_client_nonce[i]);
        }
        printf("\nReceived nonce: ");
        for (int i = 0; i < NONCE_SIZE; i++) {
            printf("%02x", pdf_msg.nonce[i]);
        }
        printf("\n");

        // Verify that the nonce matches
        if (memcmp(pdf_msg.nonce, print_client_nonce, NONCE_SIZE) != 0)
        {
            fprintf(stderr, "PDF message nonce verification failed\n");
            close(sockPrinter);
            return 1;
        }

        // Extract IV from PDF data
        unsigned char pdf_iv[IV_LEN];
        memcpy(pdf_iv, pdf_msg.data, IV_LEN);

        // Decrypt the PDF data
        unsigned char pdf_buffer[BUFFER_SIZE];
        int pdf_decrypted_len = decrypt_data(
            pdf_msg.data + IV_LEN,
            pdf_msg.data_len - IV_LEN,
            session_key,
            pdf_iv,
            pdf_msg.tag,
            pdf_buffer);

        if (pdf_decrypted_len <= 0)
        {
            fprintf(stderr, "PDF decryption failed\n");
            close(sockPrinter);
            return 1;
        }

        // Extract PDF size from the decrypted data
        size_t pdf_size;
        memcpy(&pdf_size, pdf_buffer, sizeof(size_t));

        // Create output PDF filename (replace extension with .pdf)
        char pdf_filename[256];
        char *dot_pos = strrchr(filename, '.');
        if (dot_pos)
        {
            // Copy original filename up to the dot
            size_t base_len = dot_pos - filename;
            strncpy(pdf_filename, filename, base_len);
            pdf_filename[base_len] = '\0';
        }
        else
        {
            // Use the whole filename if no extension found
            strcpy(pdf_filename, filename);
        }
        // Append .pdf extension
        strcat(pdf_filename, ".pdf");

        // Save the PDF data to a file
        FILE *pdf_file = fopen(pdf_filename, "wb");
        if (!pdf_file)
        {
            fprintf(stderr, "Error: Cannot create PDF file '%s'\n", pdf_filename);
            close(sockPrinter);
            return 1;
        }

        // Write PDF content (skip the size prefix)
        if (fwrite(pdf_buffer + sizeof(size_t), 1, pdf_size, pdf_file) != pdf_size)
        {
            fprintf(stderr, "Error writing PDF file\n");
            fclose(pdf_file);
            close(sockPrinter);
            return 1;
        }

        fclose(pdf_file);
        close(sockPrinter);

        printf("Successfully received and saved PDF as '%s' (%zu bytes)\n", pdf_filename, pdf_size);
        return 0;
    }

    return 0;
}