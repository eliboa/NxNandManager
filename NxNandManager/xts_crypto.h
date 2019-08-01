#pragma once

#include <cstddef>
#include <openssl/evp.h>

class xts_crypto {

private:
    size_t sector_size;
    EVP_CIPHER_CTX* ctx_crypto;
    EVP_CIPHER_CTX* ctx_tweak;
    const unsigned char* crypto_key;
    const unsigned char* tweak_key;

    void create_tweak(unsigned char* tweak, size_t offset);

    void apply_tweak(const unsigned char* tweak, unsigned char* data, size_t data_len);

public:
    xts_crypto(const unsigned char* crypto_key, const unsigned char* tweak_key, size_t sector_size);

    void decrypt(unsigned char* data, size_t offset);

};

