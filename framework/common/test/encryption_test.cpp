/* SPDX-License-Identifier: BSD-2-Clause-Patent
 *
 * Copyright (c) 2019 Arnout Vandecappelle (Essensium/Mind)
 * Copyright (c) 2019 Tomer Eliyahu (Intel)
 *
 * This code is subject to the terms of the BSD+Patent license.
 * See LICENSE file for more details.
 */

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
        int plen = sizeof(plaintext) + 8; // last 64 bytes are the KWA
        int clen = plen + 15;             // leave room for in place encryption
        int dlen = clen + 16;
        uint8_t data[clen];
        std::fill(data, data + plen, 1);
        uint8_t decrypted[dlen];
        uint8_t *kwa = &data[sizeof(plaintext)];

        check(errors, mapf::encryption::kwa_compute(authkey1, data, sizeof(plaintext), kwa),
              "KWA compute IN");
        uint8_t iv[128];
        mapf::encryption::create_iv(iv, sizeof(iv));
        LOG(DEBUG) << "plaintext: " << std::endl << dump_buffer(data, plen);
        check(errors, mapf::encryption::aes_encrypt(keywrapkey1, iv, data, plen, data, clen),
              "AES encrypt");
        LOG(DEBUG) << "ciphertext: " << std::endl << dump_buffer(data, clen);
        check(errors, mapf::encryption::aes_decrypt(keywrapkey2, iv, data, clen, decrypted, dlen),
              "AES decrypt");
        LOG(DEBUG) << "decrypted: " << std::endl << dump_buffer(decrypted, dlen);
        check(errors, std::equal(decrypted, decrypted + sizeof(plaintext), plaintext),
              "Decrypted cyphertext should be equal to plaintext");

        uint8_t *kwa_in = &decrypted[sizeof(plaintext)];
        uint8_t kwa_out[8];
        check(errors,
              mapf::encryption::kwa_compute(authkey2, decrypted, sizeof(plaintext), kwa_out),
              "KWA compute OUT");
        check(errors, std::equal(kwa_out, kwa_out + sizeof(kwa_out), kwa_in),
              "KWA should be equal");
    }

    return errors;
}
