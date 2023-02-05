#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 128

void xor(const unsigned char *a, const unsigned char *b, int len, unsigned char *result) {
    int i;
    for (i = 0; i < len; i++) {
        result[i] = a[i] ^ b[i];
    }
}

void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    int i;
    for (i = 0; i < plaintext_len; i += BLOCK_SIZE) {
        xor(plaintext + i, iv, BLOCK_SIZE, ciphertext + i);
        // memcpy(iv, ciphertext + i, BLOCK_SIZE);
    }
    printf("Enc text: %s\n", ciphertext);
}

void decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    int i;
    for (i = 0; i < ciphertext_len; i += BLOCK_SIZE) {
        xor(ciphertext + i, iv, BLOCK_SIZE, plaintext + i);
        // memcpy(iv, ciphertext + i, BLOCK_SIZE);
    }
}

int main(int argc, char const *argv[]) {
    unsigned char key[BLOCK_SIZE];
    unsigned char iv[BLOCK_SIZE];
    memset(key, 0, BLOCK_SIZE);
    memset(iv, 0, BLOCK_SIZE);

    const char *plaintext = "This is a plaintext";
    unsigned char ciphertext[strlen(plaintext) + BLOCK_SIZE];
    unsigned char decryptedtext[strlen(plaintext) + BLOCK_SIZE];

    encrypt((unsigned char *)plaintext, strlen(plaintext), key, iv, ciphertext);
    
    decrypt(ciphertext, strlen(plaintext), key, iv, decryptedtext);

    decryptedtext[strlen(plaintext)] = '\0';
    printf("Decrypted text: %s\n", decryptedtext);

    return 0;
}
