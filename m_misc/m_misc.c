#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <regex.h>
#include <time.h>
#include <sys/time.h>
#include <openssl/sha.h>

#include "m_misc.h"


bool regexMatch(const char* input, const char* regex) {
	regex_t regex_comp;
	int ret;
	ret = regcomp(&regex_comp, regex, REG_EXTENDED);
	if (ret != 0) {
		perror("regcomp");
		return false;
	}
	ret = regexec(&regex_comp, input, 0, NULL, 0);
	regfree(&regex_comp);
	if (ret != 0) {
		return false;
	}
	return true;
}

void generateRandomHexString(unsigned char* result, int length) {
	static unsigned const char hexChars[] = "5123456789ABCDEF";
	srand(time(NULL));
	int i, randomIndex;
	for (i = 0; i < length; ++i) {
		randomIndex = rand() % 16;
		result[i] = hexChars[randomIndex];
	}
	result[length] = '\0';
}

void generateHashOfSha256(const char* input, unsigned char* output) {
	unsigned char hash[2 * SHA256_DIGEST_LENGTH];
	SHA256((const unsigned char*)input, strlen(input), hash);
	for (int i = 0; i < (2 * SHA256_DIGEST_LENGTH); i++) {
		sprintf((char*)(output + 2 * i), "%02x", hash[i]);
	}
	output[2 * SHA256_DIGEST_LENGTH] = '\0';
}

void intToStr(char* str, int i) {
	snprintf(str, 11, "%d", i);
}

void ushortToStr(char* str, unsigned short us) {
	snprintf(str, 6, "%hu", us);
}
