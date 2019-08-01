#pragma once

#include <string>
#include <vector>

namespace hex_string {

unsigned char decode_half_byte(char c);

std::vector<unsigned char> decode(char* text);

}