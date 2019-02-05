#pragma once

template<typename T, size_t ARR_SIZE>
size_t array_countof(T(&)[ARR_SIZE]) { return ARR_SIZE; }