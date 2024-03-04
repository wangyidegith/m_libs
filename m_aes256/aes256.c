#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "aes256.h"

#define IV_SIZE 64
#define AES_KEY_SIZE 64

static void printOpenSSLErrors() {
	unsigned long errCode;
	const char *errString;
	while ((errCode = ERR_get_error()) != 0) {
		errString = ERR_error_string(errCode, NULL);
		if (errString != NULL) {
			fprintf(stderr, "OpenSSL Error: %s\n", errString);
		}
	}
}

static int encryptAES256(const unsigned char* plaintext, const size_t plaintext_len, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext, int* ciphertext_len) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		fprintf(stderr, "EVP_CIPHER_CTX_new failed.\n");
		printOpenSSLErrors();
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
		fprintf(stderr, "EVP_EncryptInit_ex failed.\n");
		printOpenSSLErrors();
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	int len;
	if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1) {
		fprintf(stderr, "EVP_EncryptUpdate failed.\n");
		printOpenSSLErrors();
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	*ciphertext_len = len;
	if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
		fprintf(stderr, "EVP_EncryptFinal_ex failed.\n");
		printOpenSSLErrors();
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	*ciphertext_len += len;
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

static int decryptAES256(const unsigned char* ciphertext, const int ciphertext_len, const unsigned char* key, const unsigned char* iv, unsigned char* plaintext) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == NULL) {
		fprintf(stderr, "EVP_CIPHER_CTX_new failed.\n");
		printOpenSSLErrors();
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
		fprintf(stderr, "EVP_DecryptInit_ex failed.\n");
		printOpenSSLErrors();
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	int len;
	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
		fprintf(stderr, "EVP_DecryptUpdate failed.\n");
		printOpenSSLErrors();
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
		fprintf(stderr, "EVP_DecryptFinal_ex failed.\n");
		printOpenSSLErrors();
		EVP_CIPHER_CTX_free(ctx);
		return -1;
	}
	EVP_CIPHER_CTX_free(ctx);
	return 0;
}

static void generateHashOfSha256(const char* input, unsigned char* output) {
	unsigned char hash[2 * SHA256_DIGEST_LENGTH];
	SHA256((const unsigned char*)input, strlen(input), hash);
	for (int i = 0; i < (2 * SHA256_DIGEST_LENGTH); i++) {
		sprintf((char*)(output + 2 * i), "%02x", hash[i]);
	}
	output[2 * SHA256_DIGEST_LENGTH] = '\0';
}
static void generateAESKeyFromSEED(const char* aes_key_seed, unsigned char* aes_key) {
	generateHashOfSha256(aes_key_seed, aes_key);
}

int decryptToMessage(const char* data_buf, char* message, const int data_len) {
	char* msg_cypher = (char*)(data_buf + IV_SIZE);
	unsigned char aes_key[AES_KEY_SIZE + 1];
	memset((void*)aes_key, 0x00, sizeof(aes_key));
	generateAESKeyFromSEED(AES_KEY_SEED, aes_key);
	unsigned char iv[IV_SIZE + 1];
	memset((void*)iv, 0x00, sizeof(iv));
	memcpy((void*)iv, (void*)data_buf, IV_SIZE);
	int cypher_len = data_len - IV_SIZE;
	if (decryptAES256((unsigned char*)msg_cypher, cypher_len, aes_key, iv, (unsigned char*)message)) {
		return -1;
	}
	return 0;
}

static void generateRandomHexString(unsigned char* result, const int length) {
	static unsigned const char hexChars[] = "5123456789ABCDEF";
	srand(time(NULL));
	int i, randomIndex;
	for (i = 0; i < length; ++i) {
		randomIndex = rand() % 16;
		result[i] = hexChars[randomIndex];
	}
	result[length] = '\0';
}
static void generateIv(unsigned char* iv_buf, const int result_len) {
	generateRandomHexString(iv_buf, result_len);
}

int encryptFromMessage(char* data_buf, const char* message, int* data_len) {
	unsigned char aes_key[AES_KEY_SIZE + 1];
	memset((void*)aes_key, 0x00, sizeof(aes_key));
	generateAESKeyFromSEED(AES_KEY_SEED, aes_key);
	unsigned char iv[IV_SIZE + 1];
	memset((void*)iv, 0x00, sizeof(iv));
	generateIv(iv, IV_SIZE);
	int msg_cypher_buf_len = (strlen(message) + strlen(message) % 16 + 1) * sizeof(char);
	char msg_cypher[msg_cypher_buf_len];
	memset((void*)msg_cypher, 0x00, sizeof(msg_cypher));
	int cyphertext_len;
	if (encryptAES256((unsigned char*)message, strlen(message), aes_key, iv, (unsigned char*)msg_cypher, &cyphertext_len)) {
		return -1;
	}
	memcpy((void*)data_buf, (void*)iv, IV_SIZE);
	data_buf += IV_SIZE;
	memcpy((void*)data_buf, (void*)msg_cypher, cyphertext_len);
	*data_len = IV_SIZE + cyphertext_len;
	return 0;
}
