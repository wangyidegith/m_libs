#define AES_KEY_SEED "one string that must be contast from config"

int decryptToMessage(const char* data_buf, char* message, const int data_len);
int encryptFromMessage(char* data_buf, const char* message, int* data_len);
