#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

#define BLOCK_SIZE 16

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  AES_KEY enc_key;
  AES_set_encrypt_key(key, 128, &enc_key);
  AES_cbc_encrypt(plaintext, ciphertext, plaintext_len, &enc_key, iv, AES_ENCRYPT);
  return 0;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  AES_KEY dec_key;
  AES_set_decrypt_key(key, 128, &dec_key);
  AES_cbc_encrypt(ciphertext, plaintext, ciphertext_len, &dec_key, iv, AES_DECRYPT);
  return 0;
}

int main(int argc, char const *argv[]) {
  unsigned char key[AES_BLOCK_SIZE];
  unsigned char iv[AES_BLOCK_SIZE];
  RAND_bytes(key, AES_BLOCK_SIZE);
  RAND_bytes(iv, AES_BLOCK_SIZE);

  const char *plaintext = "This is a plaintext";
  unsigned char ciphertext[strlen(plaintext) + BLOCK_SIZE];
  unsigned char decryptedtext[strlen(plaintext) + BLOCK_SIZE];

  int ciphertext_len = encrypt((unsigned char *)plaintext, strlen(plaintext), key, iv, ciphertext);
  int decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

  decryptedtext[decryptedtext_len] = '\0';
  printf("Decrypted text: %s\n", decryptedtext);

  return 0;
}
