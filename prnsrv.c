#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <pthread.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/sha.h>

#include <time.h>
#include <sys/stat.h>

#include <hpdf.h>

// prnsrv.c

#define CLIENT_PORT 9001
#define PRINT_PORT 9010
#define MAX_CLIENTS 10
#define MAX_BUFFER 4096
#define NONCE_SIZE 16
#define KEY_SIZE 32
#define IV_SIZE 12
#define TAG_SIZE 16
#define MAX_USERNAME 64
#define MAX_TICKET_DATA 1024
#define MAX_FILE_SIZE 1048576

typedef struct
{
    unsigned char nonce[NONCE_SIZE];
    unsigned char data[MAX_BUFFER];
    size_t data_len;
    unsigned char tag[TAG_SIZE];
} secured_message;

typedef struct
{
    char username[MAX_USERNAME];
    unsigned char session_key[KEY_SIZE];
    time_t timestamp;
    time_t expiry;
} ticket_data;

typedef struct
{
    int client_socket;
} client_args;

// Print server's encryption key (must match KDC's)
unsigned char server_key[KEY_SIZE];

// Mutex for thread safety
//pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

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
                          KEY_SIZE, key);
    }
    else
    {
        // Use the provided salt
        PKCS5_PBKDF2_HMAC(password, strlen(password),
                          salt, 16,
                          10000, EVP_sha256(),
                          KEY_SIZE, key);
    }
}

// Initialize server key
void init_server_key()
{
    derive_key("printserverpass", server_key, NULL);
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
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag))
        return -1;

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
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag))
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

#include <openssl/evp.h> // Include EVP header for SHA-256

void print_sha256(const unsigned char *data, size_t data_len)
{
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
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        printf("%02x", output[i]);
    }
    printf("\n");
}

// Validate ticket and extract data
int validate_ticket(unsigned char *ticket, size_t ticket_len, ticket_data *data)
{
    // Extract IV
    unsigned char *iv = ticket;

    // Extract ciphertext and tag
    unsigned char *ciphertext = ticket + IV_SIZE;
    size_t ciphertext_len = ticket_len - IV_SIZE - TAG_SIZE;
    unsigned char *tag = ticket + IV_SIZE + ciphertext_len;

    // Decrypt ticket
    unsigned char decrypted[MAX_TICKET_DATA];
    int decrypted_len = decrypt_data(ciphertext, ciphertext_len, server_key, iv, tag, decrypted);

    if (decrypted_len <= 0)
    {
        return -1;
    }

    // Extract ticket data
    char *username = (char *)decrypted;
    // Find the actual length of the username (look for null terminator)
    size_t username_len = 0;
    while (username_len < MAX_USERNAME && username[username_len] != '\0')
    {
        username_len++;
    }

    // Copy only up to the null terminator
    strncpy(data->username, username, username_len);
    data->username[username_len] = '\0';
    username_len = strlen(data->username);

    memcpy(data->session_key, decrypted + username_len + 1, KEY_SIZE);
    memcpy(&data->timestamp, decrypted + username_len + 1 + KEY_SIZE, sizeof(time_t));

    // Check expiry if needed
    // memcpy(&data->expiry, decrypted + username_len + 1 + KEY_SIZE + sizeof(time_t), sizeof(time_t));
    // time_t now = time(NULL);
    // if (now > data->expiry) {
    //     return -2;
    // }

    return 0;
}

// Include the required headers
#include <hpdf.h>  // Using libharu for PDF generation

// Error handler for libharu
void error_handler(HPDF_STATUS error_no, HPDF_STATUS detail_no, void *user_data) {
    printf("PRINTER -> PDF Error: error_no=%04X, detail_no=%d\n", (unsigned int)error_no, (int)detail_no);
}

// Function to convert text file to PDF
int convert_text_to_pdf(const char *input_file, const char *output_file, const char *username) {
    HPDF_Doc pdf;
    HPDF_Page page;
    HPDF_Font font;
    FILE *text_file;
    char buffer[1024];
    float text_height = 12.0;
    float margin = 50.0;
    float y_position;
    
    // Initialize PDF document
    pdf = HPDF_New(NULL, NULL);
    if (!pdf) {
        printf("PRINTER -> Error: Failed to create PDF document\n");
        return -1;
    }
    
    // Error handler
    HPDF_SetErrorHandler(pdf, error_handler);
    
    // Create a new page
    page = HPDF_AddPage(pdf);
    HPDF_Page_SetSize(page, HPDF_PAGE_SIZE_A4, HPDF_PAGE_PORTRAIT);
    
    // Set font
    font = HPDF_GetFont(pdf, "Helvetica", NULL);
    HPDF_Page_SetFontAndSize(page, font, text_height);
    
    // Calculate starting position
    y_position = HPDF_Page_GetHeight(page) - margin;
    
    // Open text file
    text_file = fopen(input_file, "r");
    if (!text_file) {
        printf("PRINTER -> Error: Failed to open input text file\n");
        HPDF_Free(pdf);
        return -1;
    }
    
    // Read text file line by line and add to PDF
    while (fgets(buffer, sizeof(buffer), text_file) != NULL) {
        // Remove newline character if present
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len-1] == '\n') {
            buffer[len-1] = '\0';
        }
        
        // Check if we need a new page
        if (y_position < margin) {
            page = HPDF_AddPage(pdf);
            HPDF_Page_SetFontAndSize(page, font, text_height);
            y_position = HPDF_Page_GetHeight(page) - margin;
        }
        
        // Add text to page
        HPDF_Page_BeginText(page);
        HPDF_Page_TextOut(page, margin, y_position, buffer);
        HPDF_Page_EndText(page);
        
        // Move to next line
        y_position -= (text_height + 5);
    }
    
    // Close text file
    fclose(text_file);
    
    // Add metadata
    HPDF_SetInfoAttr(pdf, HPDF_INFO_CREATOR, username);
    HPDF_SetInfoAttr(pdf, HPDF_INFO_TITLE, "Converted Text Document");
    
    // Save PDF document
    if (HPDF_SaveToFile(pdf, output_file) != HPDF_OK) {
        printf("PRINTER -> Error: Failed to save PDF file\n");
        HPDF_Free(pdf);
        return -1;
    }
    
    // Free PDF document
    HPDF_Free(pdf);
    printf("PRINTER -> Successfully converted text to PDF using libharu\n");
    
    return 0;
}

void *client_handler(void *socket_desc)
{
    pthread_detach(pthread_self());

    int client_sock = *(int *)socket_desc;
    free(socket_desc);

    unsigned char buffer[MAX_BUFFER];
    int read_size;
    ticket_data ticket = {0};

    // Step 1: Receive initial message with client nonce and ticket
    memset(buffer, 0, MAX_BUFFER);
    read_size = recv(client_sock, buffer, MAX_BUFFER, 0);

    if (read_size <= 0)
    {
        printf("Error: Failed to receive initial message\n");
        close(client_sock);
        return NULL;
    }

    // Extract client nonce
    unsigned char client_nonce[NONCE_SIZE];
    memcpy(client_nonce, buffer, NONCE_SIZE);

    printf("PRINTER -> Received client nonce: ");
    for (int i = 0; i < NONCE_SIZE; i++)
    {
        printf("%02x", client_nonce[i]);
    }
    printf("\n");

    // Extract ticket length and ticket data
    size_t ticket_len;
    memcpy(&ticket_len, buffer + NONCE_SIZE, sizeof(size_t));

    if (ticket_len > MAX_TICKET_DATA)
    {
        printf("Error: Invalid ticket length\n");
        close(client_sock);
        return NULL;
    }

    unsigned char ticket_buffer[MAX_TICKET_DATA];
    memcpy(ticket_buffer, buffer + NONCE_SIZE + sizeof(size_t), ticket_len);

    // Validate ticket
    int result = validate_ticket(ticket_buffer, ticket_len, &ticket);
    if (result != 0)
    {
        printf("Error: Ticket validation failed: %d\n", result);
        close(client_sock);
        return NULL;
    }

    printf("PRINTER -> User %s authenticated with valid ticket\n", ticket.username);

    // Step 2: Generate server nonce for challenge
    unsigned char server_nonce[NONCE_SIZE];
    if (RAND_bytes(server_nonce, NONCE_SIZE) != 1)
    {
        printf("Error: Failed to generate server nonce\n");
        close(client_sock);
        return NULL;
    }

    printf("PRINTER -> Generated server nonce: ");
    for (int i = 0; i < NONCE_SIZE; i++)
    {
        printf("%02x", server_nonce[i]);
    }
    printf("\n");

    // Create challenge with both nonces (client_nonce + server_nonce)
    unsigned char challenge_data[NONCE_SIZE * 2];
    memcpy(challenge_data, client_nonce, NONCE_SIZE);
    memcpy(challenge_data + NONCE_SIZE, server_nonce, NONCE_SIZE);

    // Encrypt challenge with session key
    unsigned char iv[IV_SIZE];
    if (RAND_bytes(iv, IV_SIZE) != 1)
    {
        printf("Error: Failed to generate IV\n");
        close(client_sock);
        return NULL;
    }

    unsigned char encrypted[MAX_BUFFER];
    unsigned char tag[TAG_SIZE];

    // Encrypt challenge data (place IV at beginning of message)
    memcpy(encrypted, iv, IV_SIZE);
    int encrypted_len = encrypt_data(challenge_data, NONCE_SIZE * 2,
                                     ticket.session_key, iv,
                                     encrypted + IV_SIZE, tag);

    if (encrypted_len < 0)
    {
        printf("Error: Challenge encryption failed\n");
        close(client_sock);
        return NULL;
    }

    // Add authentication tag to the end
    memcpy(encrypted + IV_SIZE + encrypted_len, tag, TAG_SIZE);
    size_t total_msg_len = IV_SIZE + encrypted_len + TAG_SIZE;

    // Send encrypted challenge to client
    if (send(client_sock, encrypted, total_msg_len, 0) != total_msg_len)
    {
        printf("Error: Failed to send challenge\n");
        close(client_sock);
        return NULL;
    }

    printf("PRINTER -> Sent encrypted challenge to client\n");

    // Step 3: Receive and validate client's response
    secured_message response;
    memset(&response, 0, sizeof(secured_message));

    read_size = recv(client_sock, &response, sizeof(secured_message), 0);
    if (read_size <= 0)
    {
        printf("Error: Failed to receive challenge response\n");
        close(client_sock);
        return NULL;
    }

    // Verify the nonce in the response matches client's original nonce
    if (memcmp(client_nonce, response.nonce, NONCE_SIZE) != 0)
    {
        printf("Error: Client nonce verification failed\n");
        printf("PRINTER -> Expected nonce: ");
        for (int i = 0; i < NONCE_SIZE; i++)
        {
            printf("%02x", client_nonce[i]);
        }
        printf("\n");

        printf("PRINTER -> Received nonce: ");
        for (int i = 0; i < NONCE_SIZE; i++)
        {
            printf("%02x", response.nonce[i]);
        }
        printf("\n");

        close(client_sock);
        return NULL;
    }

    // Extract IV from response data
    unsigned char response_iv[IV_SIZE];
    memcpy(response_iv, response.data, IV_SIZE);

    // Decrypt the challenge response
    unsigned char decrypted[MAX_BUFFER];
    int decrypted_len = decrypt_data(
        response.data + IV_SIZE,
        response.data_len - IV_SIZE,
        ticket.session_key,
        response_iv,
        response.tag,
        decrypted);

    // Verify decryption succeeded and response contains server's nonce
    if (decrypted_len != NONCE_SIZE || memcmp(decrypted, server_nonce, NONCE_SIZE) != 0)
    {
        printf("Error: Challenge verification failed\n");
        printf("PRINTER -> Expected server nonce: ");
        for (int i = 0; i < NONCE_SIZE; i++)
        {
            printf("%02x", server_nonce[i]);
        }
        printf("\n");

        if (decrypted_len == NONCE_SIZE)
        {
            printf("PRINTER -> Received nonce in response: ");
            for (int i = 0; i < NONCE_SIZE; i++)
            {
                printf("%02x", decrypted[i]);
            }
            printf("\n");
        }
        else
        {
            printf("PRINTER -> Decryption failed or incorrect length\n");
        }

        close(client_sock);
        return NULL;
    }

    // Step 4: Authentication successful
    //printf("PRINTER -> Successfully authenticated client %s\n", ticket.username);

    // Prepare the confirmation message as plaintext
    char confirmation_plaintext[128];
    sprintf(confirmation_plaintext, "Authentication successful for user %s", ticket.username);

    // Encrypt the confirmation message using the session key from the ticket
    unsigned char conf_iv[IV_SIZE];
    if (RAND_bytes(conf_iv, IV_SIZE) != 1)
    {
        printf("Error: Failed to generate IV for confirmation\n");
        close(client_sock);
        return NULL;
    }

    unsigned char conf_ciphertext[MAX_BUFFER];
    unsigned char conf_tag[TAG_SIZE];
    int conf_ciphertext_len = encrypt_data((unsigned char *)confirmation_plaintext,
                                           strlen(confirmation_plaintext) + 1,
                                           ticket.session_key, conf_iv,
                                           conf_ciphertext, conf_tag);
    if (conf_ciphertext_len < 0)
    {
        printf("Error: Failed to encrypt confirmation message\n");
        close(client_sock);
        return NULL;
    }

    // Create a message buffer that includes the IV, ciphertext, and tag
    unsigned char conf_message[MAX_BUFFER];
    memcpy(conf_message, conf_iv, IV_SIZE);
    memcpy(conf_message + IV_SIZE, conf_ciphertext, conf_ciphertext_len);
    memcpy(conf_message + IV_SIZE + conf_ciphertext_len, conf_tag, TAG_SIZE);
    size_t conf_message_len = IV_SIZE + conf_ciphertext_len + TAG_SIZE;

    // Send the encrypted confirmation to the client
    if (send(client_sock, conf_message, conf_message_len, 0) != conf_message_len)
    {
        printf("Error: Failed to send confirmation message\n");
        close(client_sock);
        return NULL;
    }

    // SUCCESSFULL AUTHENTICATION----------------------
    // AUTHENTICATION PART ENDS HERE-------------------
    printf("\n-----------------------------PRINTER -> Successfully authenticated client %s\n-----------------------------", ticket.username);

    // // Send the encrypted confirmation to the client
    // if (send(client_sock, conf_message, conf_message_len, 0) != conf_message_len)
    // {
    //     printf("Error: Failed to send confirmation message\n");
    //     close(client_sock);
    //     return NULL;
    // }

    // Step 5: Receive the file from the client
    secured_message file_msg;
    memset(&file_msg, 0, sizeof(secured_message));

    read_size = recv(client_sock, &file_msg, sizeof(secured_message), 0);
    if (read_size <= 0)
    {
        printf("Error: Failed to receive file data\n");
        close(client_sock);
        return NULL;
    }

    // Extract IV from file data
    unsigned char file_iv[IV_SIZE];
    memcpy(file_iv, file_msg.data, IV_SIZE);

    // Decrypt the file data
    unsigned char file_data[MAX_FILE_SIZE];
    int file_data_len = decrypt_data(
        file_msg.data + IV_SIZE,
        file_msg.data_len - IV_SIZE,
        ticket.session_key,
        file_iv,
        file_msg.tag,
        file_data);

    if (file_data_len <= 0)
    {
        printf("Error: File decryption failed\n");
        close(client_sock);
        return NULL;
    }

    // Extract file metadata (format and size)
    char file_format[10];
    size_t file_size;

    memcpy(file_format, file_data, sizeof(file_format));
    memcpy(&file_size, file_data + sizeof(file_format), sizeof(size_t));

    // Ensure file format is null-terminated
    file_format[sizeof(file_format) - 1] = '\0';

    printf("PRINTER -> Received file from %s, format: %s, size: %zu bytes\n",
           ticket.username, file_format, file_size);

    // Extract the actual file content
    unsigned char *file_content = file_data + sizeof(file_format) + sizeof(size_t);

    // Generate unique filenames using username and timestamp
    char temp_input_file[128];
    char temp_output_file[128];

    snprintf(temp_input_file, sizeof(temp_input_file), "%s_input_%ld.%s",
             ticket.username, (long)time(NULL), file_format);
    snprintf(temp_output_file, sizeof(temp_output_file), "%s_output_%ld.pdf",
             ticket.username, (long)time(NULL));

    // Write the file content to the temporary file
    FILE *fp = fopen(temp_input_file, "wb");
    if (!fp)
    {
        fprintf(stderr, "Error: Failed to create temporary file at %s\n", temp_input_file);
        close(client_sock);
        return NULL;
    }

    fwrite(file_content, 1, file_size, fp);
    fclose(fp);

    print_sha256(file_content, file_size);

    // Convert the file to PDF based on the format
    // char conversion_cmd[2500];
    int conversion_result = -1;

    #include <errno.h>
    if (strcmp(file_format, "txt") == 0) {
        conversion_result = convert_text_to_pdf(temp_input_file, temp_output_file, ticket.username);
        
        if (conversion_result == 0) {
            printf("PRINTER -> Converted and saved successfully.\n");
            
            // Check the file size
            FILE *check_file = fopen(temp_output_file, "rb");
            if (check_file) {
                fseek(check_file, 0, SEEK_END);
                long file_size = ftell(check_file);
                fclose(check_file);
                printf("PRINTER -> PDF file created, size: %ld bytes\n", file_size);
            }
        } else {
            printf("PRINTER -> Text to PDF conversion failed\n");
        }
    }
    else
    {
        printf("Error: Unsupported file format: %s\n", file_format);
        remove(temp_input_file);
        close(client_sock);
        return NULL;
    }

    // Check if conversion was successful
    if (conversion_result != 0)
    {
        printf("Error: File conversion failed with exit code %d\n", conversion_result);
        remove(temp_input_file);
        close(client_sock);
        return NULL;
    }

    printf("PRINTER -> Successfully converted file to PDF\n");

    // Read the PDF file
    fp = fopen(temp_output_file, "rb");
    if (!fp)
    {
        printf("Error: Failed to open converted PDF file\n");
        remove(temp_input_file);
        close(client_sock);
        return NULL;
    }

    // Determine the PDF file size
    fseek(fp, 0, SEEK_END);
    size_t pdf_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Read the PDF file content
    unsigned char pdf_content[MAX_FILE_SIZE];
    if (pdf_size > MAX_FILE_SIZE - sizeof(size_t))
    {
        printf("Error: PDF file too large\n");
        fclose(fp);
        remove(temp_input_file);
        remove(temp_output_file);
        close(client_sock);
        return NULL;
    }

    // Read the PDF file into the buffer
    if (fread(pdf_content + sizeof(size_t), 1, pdf_size, fp) != pdf_size)
    {
        printf("Error: Failed to read PDF file\n");
        fclose(fp);
        remove(temp_input_file);
        remove(temp_output_file);
        close(client_sock);
        return NULL;
    }
    fclose(fp);

    printf("Loading pdf into buffer--------\n");

    // Store the PDF size at the beginning of the buffer
    memcpy(pdf_content, &pdf_size, sizeof(size_t));

    // Generate a random IV for the PDF encryption
    unsigned char pdf_iv[IV_SIZE];
    if (RAND_bytes(pdf_iv, IV_SIZE) != 1)
    {
        printf("Error: Failed to generate IV for PDF encryption\n");
        remove(temp_input_file);
        remove(temp_output_file);
        close(client_sock);
        return NULL;
    }

    // Prepare the secured message for sending the PDF
    secured_message pdf_msg;
    memset(&pdf_msg, 0, sizeof(secured_message));

    // Set the nonce to the original client nonce
    memcpy(pdf_msg.nonce, client_nonce, NONCE_SIZE);

    // Place the IV at the beginning of the data field
    memcpy(pdf_msg.data, pdf_iv, IV_SIZE);

    printf("Using nonce for PDF: ");
    for (int i = 0; i < NONCE_SIZE; i++) {
        printf("%02x", client_nonce[i]);
    }
    printf("\n");

    // Encrypt the PDF content (size + data)
    int pdf_ciphertext_len = encrypt_data(
        pdf_content,
        sizeof(size_t) + pdf_size,
        ticket.session_key,
        pdf_iv,
        pdf_msg.data + IV_SIZE,
        pdf_msg.tag);

    if (pdf_ciphertext_len < 0)
    {
        printf("Error: PDF encryption failed\n");
        remove(temp_input_file);
        remove(temp_output_file);
        close(client_sock);
        return NULL;
    }

    // Set the data length
    pdf_msg.data_len = IV_SIZE + pdf_ciphertext_len;

    printf("PRINTER -> PDF message nonce before sending: ");
    for (int i = 0; i < NONCE_SIZE; i++) {
        printf("%02x", pdf_msg.nonce[i]);
    }
    printf("\n");

    printf("Sending PDF file to client.\n");

    // Send the encrypted PDF to the client
    if (send(client_sock, &pdf_msg, sizeof(secured_message), 0) != sizeof(secured_message))
    {
        printf("Error: Failed to send PDF to client\n");
        remove(temp_input_file);
        remove(temp_output_file);
        close(client_sock);
        return NULL;
    }

    printf("PRINTER -> Successfully sent encrypted PDF to client %s\n", ticket.username);

    // Clean up temporary files
    remove(temp_input_file);
    remove(temp_output_file);

    // Close connection
    close(client_sock);
    return NULL;
}

int main(int argc, char *argv[])
{
    // Initialize OpenSSL
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, NULL);

    // Initialize server key
    init_server_key();

    // Create socket
    int printSock = socket(AF_INET, SOCK_STREAM, 0);
    if (printSock == -1)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Set socket options
    int opt = 1;
    if (setsockopt(printSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    struct sockaddr_in servAddr;
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(PRINT_PORT);
    servAddr.sin_addr.s_addr = INADDR_ANY;

    // Bind socket
    if (bind(printSock, (struct sockaddr *)&servAddr, sizeof(servAddr)) < 0)
    {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for connections
    if (listen(printSock, MAX_CLIENTS) < 0)
    {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Printer server started. Listening on port %d...\n", PRINT_PORT);

    // Main server loop
    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int clientSocket = accept(printSock, (struct sockaddr *)&client_addr, &client_len);

        if (clientSocket < 0)
        {
            perror("Accept failed");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        printf("PRINTER -> New client connected from %s\n", client_ip);

        // Create thread arguments
        client_args *args = malloc(sizeof(client_args));
        if (!args)
        {
            perror("Memory allocation failed");
            close(clientSocket);
            continue;
        }

        args->client_socket = clientSocket;

        // Create client handler thread
        pthread_t thread_id;
        if (pthread_create(&thread_id, NULL, client_handler, (void *)args) < 0)
        {
            perror("Thread creation failed");
            close(clientSocket);
            free(args);
            continue;
        }

        //pthread_detach(thread_id);
    }

    // Clean up (this might never be reached)
    close(printSock);
    return 0;
}