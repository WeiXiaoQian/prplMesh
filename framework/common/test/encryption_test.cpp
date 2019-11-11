/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2019 Arnout Vandecappelle (Essensium/Mind)
 * Copyright (c) 2019 Tomer Eliyahu (Intel)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

#if 0
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <mapf/common/encryption.h>
#include <mapf/common/logger.h>

#include <arpa/inet.h>

MAPF_INITIALIZE_LOGGER

std::string dump_buffer(uint8_t *buffer, size_t len)
{
    std::ostringstream hexdump;
    for (size_t i = 0; i < len; i += 16) {
        for (size_t j = i; j < len && j < i + 16; j++)
            hexdump << std::hex << std::setw(2) << std::setfill('0') << (unsigned)buffer[j] << " ";
        hexdump << std::endl;
    }
    return hexdump.str();
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main (void)
{
    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    LOG(DEBUG) << "key: " << std::endl << dump_buffer((uint8_t *)key, strlen ((char *)key));
    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";
    LOG(DEBUG) << "iv: " << std::endl << dump_buffer((uint8_t *)iv, strlen ((char *)iv));

    /* Message to be encrypted */
    unsigned char *plaintext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog";
    LOG(DEBUG) << "data before encryption: " << std::endl << dump_buffer((uint8_t *)plaintext, strlen ((char *)plaintext));

    /*
     * Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, depending on the
     * algorithm and mode.
     */
    unsigned char ciphertext[128];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt (plaintext, strlen ((char *)plaintext), key, iv,
                              ciphertext);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp (stdout, (const char *)ciphertext, ciphertext_len);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
                                decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);


    return 0;
}
#else
#include <mapf/common/encryption.h>
#include <mapf/common/logger.h>

#include <arpa/inet.h>

MAPF_INITIALIZE_LOGGER

static bool check(int &errors, bool check, std::string message)
{
    if (check) {
        MAPF_INFO(" OK  ") << message;
    } else {
        MAPF_ERR("FAIL ") << message;
        errors++;
    }
    return check;
}

std::string dump_buffer(uint8_t *buffer, size_t len)
{
    std::ostringstream hexdump;
    for (size_t i = 0; i < len; i += 16) {
        for (size_t j = i; j < len && j < i + 16; j++)
            hexdump << std::hex << std::setw(2) << std::setfill('0') << (unsigned)buffer[j] << " ";
        hexdump << std::endl;
    }
    return hexdump.str();
}


int main()
{
    mapf::Logger::Instance().LoggerInit("encryption_test");
    int errors = 0;

    MAPF_INFO("Start encryption test");
    mapf::encryption::diffie_hellman m1;
    mapf::encryption::diffie_hellman m2;

    uint8_t key1[192];
    uint8_t key2[192];
    unsigned key1_length = sizeof(key1);
    unsigned key2_length = sizeof(key2);
    std::fill(key1, key1 + key1_length, 1);
    std::fill(key2, key2 + key2_length, 2);

    key1_length    = sizeof(key1);
    uint8_t mac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t authkey1[32];
    uint8_t keywrapkey1[16];
    check(errors,
          wps_calculate_keys(m1, m2.pubkey(), m2.pubkey_length(), m1.nonce(), mac, m2.nonce(),
                             authkey1, keywrapkey1),
          "WPS calculate keys");
    uint8_t authkey2[32];
    uint8_t keywrapkey2[16];
    check(errors,
          wps_calculate_keys(m2, m1.pubkey(), m1.pubkey_length(), m1.nonce(), mac, m2.nonce(),
                             authkey2, keywrapkey2),
          "WPS calculate keys");
    check(errors, std::equal(authkey1, authkey1 + sizeof(authkey1), authkey2),
          "authkeys should be equal");
    check(errors, std::equal(keywrapkey1, keywrapkey1 + sizeof(keywrapkey1), keywrapkey2),
          "keywrapkeys should be equal");

    {
        uint8_t plaintext[50];
        std::fill(plaintext, plaintext + sizeof(plaintext), 1);
        // calculate length of data to encrypt
        // = plaintext length + 32 bits HMAC aligned to 16 bytes boundary
        size_t len = (sizeof(plaintext) + 8 + 15) & ~0xFU;
        uint8_t data[len] = {0}; // last 64 bytes are the KWA
        uint8_t ciphertext[len] = {0};
        int ciphertext_len;

        std::fill(data, data + sizeof(plaintext), 1);
        uint8_t *kwa = &data[sizeof(plaintext)];
        check(errors, mapf::encryption::kwa_compute(authkey1, data, sizeof(plaintext), kwa),
              "KWA compute IN");
        LOG(DEBUG) << "data before encryption: " << std::endl << dump_buffer((uint8_t *)data, len);
        uint8_t iv[16];
        mapf::encryption::create_iv(iv, sizeof(iv));
        LOG(DEBUG) << "iv: " << std::endl
               << dump_buffer((uint8_t *)iv, 16);
        LOG(DEBUG) << "keywrapkey1: " << std::endl
               << dump_buffer((uint8_t *)keywrapkey1, 16);
        check(errors, mapf::encryption::aes_encrypt2(data, sizeof(data), keywrapkey1, iv, ciphertext, ciphertext_len), "AES encrypt2");
        LOG(DEBUG) << "data after encryption: " << std::endl << dump_buffer((uint8_t *)ciphertext, ciphertext_len);
        uint8_t decryptedtext[ciphertext_len] = {0};
        int decryptedtext_len;
        check(errors, mapf::encryption::aes_decrypt2(ciphertext, ciphertext_len, keywrapkey2, iv, decryptedtext, decryptedtext_len),
              "AES decrypt2");
        LOG(DEBUG) << "data after decryption: " << std::endl << dump_buffer((uint8_t *)decryptedtext, decryptedtext_len);
        check(errors, std::equal(decryptedtext, decryptedtext + sizeof(plaintext), plaintext),
              "Decrypted cyphertext should be equal to plaintext");
        uint8_t *kwa_in = &data[sizeof(plaintext)];
        uint8_t kwa_out[8];
        check(errors, mapf::encryption::kwa_compute(authkey2, decryptedtext, sizeof(plaintext), kwa_out),
              "KWA compute OUT");
        check(errors, std::equal(kwa_out, kwa_out + sizeof(kwa_out), kwa_in),
              "KWA should be equal");
    }

    return errors;
}
#endif
