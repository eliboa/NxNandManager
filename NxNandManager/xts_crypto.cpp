#include <cassert>
#include <cstring>
#include "xts_crypto.h"

xts_crypto::xts_crypto(const unsigned char* crypto_key, const unsigned char* tweak_key, size_t sector_size)
        : sector_size(sector_size) {
    ctx_crypto = EVP_CIPHER_CTX_new();
    ctx_tweak = EVP_CIPHER_CTX_new();
    this->crypto_key = crypto_key;
    this->tweak_key = tweak_key;
}

void xts_crypto::create_tweak(unsigned char* tweak, size_t offset) {
    int outl, outl2;

    // Create the tweak data
    memset(tweak, 0, sizeof(tweak));
    for (int i = 0; i < sizeof(size_t); i++)
        tweak[15 - i] = ((unsigned char*) &offset)[i];

    // Encrypt the tweak
    assert(EVP_EncryptInit(ctx_tweak, EVP_aes_128_ecb(), tweak_key, nullptr));
    assert(EVP_CIPHER_CTX_set_padding(ctx_tweak, 0));
    assert(EVP_EncryptUpdate(ctx_tweak, tweak, &outl, tweak, 16));
    assert(EVP_EncryptFinal(ctx_tweak, &tweak[outl], &outl2));
    assert(outl + outl2 == 16);
}

void xts_crypto::apply_tweak(const unsigned char* tweak, unsigned char* data, size_t data_len) {
    unsigned char buf[16];
    memcpy(buf, tweak, sizeof(buf));
    for (size_t i = 0; i < data_len; i += 16) {
        for (int j = 0; j < 16; j++) {
            data[i + j] ^= buf[j];
        }

        bool last_high = (bool) (buf[15] & 0x80);
        for (int j = 15; j > 0; j--)
            buf[j] = (unsigned char) (((buf[j] << 1) & ~1) | (buf[j - 1] & 0x80 ? 1 : 0));
        buf[0] = (unsigned char) (((buf[0] << 1) & ~1) ^ (last_high ? 0x87 : 0));
    }
}

void xts_crypto::decrypt(unsigned char* data, size_t offset) {
    int outl, outl2;

    unsigned char tweak[16];
    create_tweak(tweak, offset);

    apply_tweak(tweak, data, sector_size);

    assert(EVP_DecryptInit(ctx_crypto, EVP_aes_128_ecb(), crypto_key, nullptr));
    assert(EVP_CIPHER_CTX_set_padding(ctx_crypto, 0));
    assert(EVP_DecryptUpdate(ctx_crypto, data, &outl, data, (int) sector_size));
    assert(EVP_DecryptFinal(ctx_crypto, &data[outl], &outl2));
    assert(outl + outl2 == sector_size);

    apply_tweak(tweak, data, sector_size);
}