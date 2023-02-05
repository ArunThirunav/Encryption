#include <string.h>
#include <stdio.h>

#define BLOCK_SIZE 16

void xor_block(unsigned char *dst, const unsigned char *a, const unsigned char *b) {
    int i;
    for (i = 0; i < BLOCK_SIZE; i++)
        dst[i] = a[i] ^ b[i];
}

void encrypt_block(unsigned char *out, const unsigned char *in, const unsigned char *key) {
    // Actual encryption logic here (using a hypothetical encryption function "encrypt_128")
    // ...

    // Dummy encryption logic for demonstration purposes
    memcpy(out, in, BLOCK_SIZE);
}

void decrypt_block(unsigned char *out, const unsigned char *in, const unsigned char *key) {
    // Actual decryption logic here (using a hypothetical decryption function "decrypt_128")
    // ...

    // Dummy decryption logic for demonstration purposes
    memcpy(out, in, BLOCK_SIZE);
}

void encrypt_cbc(unsigned char *ciphertext, const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv) {
    unsigned char block[BLOCK_SIZE], last_block[BLOCK_SIZE];
    int i;

    memcpy(last_block, iv, BLOCK_SIZE);
    for (i = 0; i < plaintext_len; i += BLOCK_SIZE) {
        xor_block(block, plaintext + i, last_block);
        encrypt_block(ciphertext + i, block, key);
        memcpy(last_block, ciphertext + i, BLOCK_SIZE);
    }
}

void decrypt_cbc(unsigned char *plaintext, const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv) {
    unsigned char block[BLOCK_SIZE], last_block[BLOCK_SIZE];
    int i;

    memcpy(last_block, iv, BLOCK_SIZE);
    for (i = 0; i < ciphertext_len; i += BLOCK_SIZE) {
        decrypt_block(block, ciphertext + i, key);
        xor_block(plaintext + i, block, last_block);
        memcpy(last_block, ciphertext + i, BLOCK_SIZE);
    }
}

int main(int argc, char const *argv[]) {
    unsigned char key[BLOCK_SIZE];
    unsigned char iv[BLOCK_SIZE];
    int i;

    // Generate a random key and IV
    for (i = 0; i < BLOCK_SIZE; i++) {
        key[i] = i;
        iv[i] = i * 2;
    }

    const char *plaintext = "This character is pretty long and should be encrypted";
    int plaintext_len = strlen(plaintext);
    unsigned char ciphertext[plaintext_len + BLOCK_SIZE];
    unsigned char decryptedtext[plaintext_len + BLOCK_SIZE];

    encrypt_cbc(ciphertext, plaintext, plaintext_len, key, iv);
    // printf("Enc: %s\n", ciphertext);
    #ifdef DEBUG_
    for (i = 0; ciphertext[i] != '\0'; i++) {
        printf("%d\n", (int)ciphertext[i]);
    }
    #endif
    decrypt_cbc(decryptedtext, ciphertext, strlen(ciphertext), key, iv);
    printf("Dec: %s\n", decryptedtext);
}