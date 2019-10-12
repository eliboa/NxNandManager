/*
 * Copyright (c) 2019 eliboa
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "NxCrypto.h"

NxCrypto::NxCrypto(char* crypto, char* tweak)
{
    sector_size = CLUSTER_SIZE;
    ctx_crypto = EVP_CIPHER_CTX_new();
    ctx_tweak = EVP_CIPHER_CTX_new();

    crypto_key = hex_string::decode(crypto);
    tweak_key = hex_string::decode(tweak);    
}

// Create & encrypt tweak
void NxCrypto::create_tweak(unsigned char* tweak, size_t offset) 
{
    int outl, outl2;
    
    memset(tweak, 0, 16);
    for (int i = 0; i < sizeof(size_t); i++)
        tweak[15 - i] = ((unsigned char*)&offset)[i];

    assert(EVP_EncryptInit(ctx_tweak, EVP_aes_128_ecb(), tweak_key.data(), nullptr));
    assert(EVP_CIPHER_CTX_set_padding(ctx_tweak, 0));
    assert(EVP_EncryptUpdate(ctx_tweak, tweak, &outl, tweak, 16));
    assert(EVP_EncryptFinal(ctx_tweak, &tweak[outl], &outl2));
    assert(outl + outl2 == 16);
}

// Apply the tweak
void NxCrypto::apply_tweak(const unsigned char* tweak, unsigned char* data, size_t data_len) 
{
    unsigned char buf[16];
    memcpy(buf, tweak, sizeof(buf));

    for (size_t i = 0; i < data_len; i += 16) 
    {
        for (int j = 0; j < 16; j++) 
            data[i + j] ^= buf[j];

        bool last_high = (bool)(buf[15] & 0x80);
        for (int j = 15; j > 0; j--)
            buf[j] = (unsigned char)(((buf[j] << 1) & ~1) | (buf[j - 1] & 0x80 ? 1 : 0));

        buf[0] = (unsigned char)(((buf[0] << 1) & ~1) ^ (last_high ? 0x87 : 0));
    }
}

// XTS-AES decrypt cluster
void NxCrypto::decrypt(unsigned char* data, size_t offset) 
{
    int outl, outl2;
    unsigned char tweak[16];

    create_tweak(tweak, offset);
    apply_tweak(tweak, data, sector_size);

    assert(EVP_DecryptInit(ctx_crypto, EVP_aes_128_ecb(), crypto_key.data(), nullptr));
    assert(EVP_CIPHER_CTX_set_padding(ctx_crypto, 0));
    assert(EVP_DecryptUpdate(ctx_crypto, data, &outl, data, (int)sector_size));
    assert(EVP_DecryptFinal(ctx_crypto, &data[outl], &outl2));
    assert(outl + outl2 == sector_size);

    apply_tweak(tweak, data, sector_size);
    /*
    std::string ck;
    for (unsigned char c : crypto_key) ck.append(hexStr(&c, 1));
    printf("NxCrypto::decrypt(%d) crypt = %s\n", offset, ck.c_str());
    */
}

// XTS-AES encrypt cluster
void NxCrypto::encrypt(unsigned char* data, size_t offset) 
{    
    int outl, outl2;
    unsigned char tweak[16];

    create_tweak(tweak, offset);
    apply_tweak(tweak, data, sector_size);

    assert(EVP_EncryptInit(ctx_crypto, EVP_aes_128_ecb(), crypto_key.data(), nullptr));
    assert(EVP_CIPHER_CTX_set_padding(ctx_crypto, 0));
    assert(EVP_EncryptUpdate(ctx_crypto, data, &outl, data, (int)sector_size));
    assert(EVP_EncryptFinal(ctx_crypto, &data[outl], &outl2));
    assert(outl + outl2 == sector_size);

    apply_tweak(tweak, data, sector_size);

    /*
    std::string ck;
    for (unsigned char c : crypto_key) ck.append(hexStr(&c, 1));
    printf("NxCrypto::encrypt(%d) crypt = %s\n", offset, ck.c_str());
    */
}