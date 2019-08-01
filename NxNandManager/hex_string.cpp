#include <stdexcept>
#include "hex_string.h"

unsigned char hex_string::decode_half_byte(char c) {
    if (c >= '0' && c <= '9')
        return (unsigned char) (c - '0');
    if (c >= 'a' && c <= 'f')
        return (unsigned char) (c - 'a' + 10);
    if (c >= 'A' && c <= 'F')
        return (unsigned char) (c - 'A' + 10);
    throw std::runtime_error("Invalid hex character");
}

std::vector<unsigned char> hex_string::decode(char* text) {
    std::vector<unsigned char> ret;
    for (size_t i = 0; text[i] != 0 && text[i +1] != 0; i += 2)
        ret.push_back((decode_half_byte(text[i]) << 4) | decode_half_byte(text[i + 1]));
    return ret;
}