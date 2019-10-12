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

#ifndef __NxCrypto_h__
#define __NxCrypto_h__

#include <string.h> 
#include <fstream>
#include <cstddef>
#include <cassert>
#include <openssl/evp.h>
#include "res/types.h"
#include "res/hex_string.h"
#include "NxPartition.h"

using namespace std;


class NxPartition;
class NxCrypto
{
    // Constructors
    public:
        NxCrypto(char* crypto, char* tweak);

    // Member variables
    private:
        size_t sector_size;
        EVP_CIPHER_CTX* ctx_crypto;
        EVP_CIPHER_CTX* ctx_tweak;
        std::vector<unsigned char> crypto_key;
        std::vector<unsigned char> tweak_key;

    // Member methods
    private:
        void create_tweak(unsigned char* tweak, size_t offset);
        void apply_tweak(const unsigned char* tweak, unsigned char* data, size_t data_len);

    public:        
        void decrypt(unsigned char* data, size_t offset);
        void encrypt(unsigned char* data, size_t offset);
};

#endif