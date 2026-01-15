#ifndef FUZZER_BYTE_PARSER_H_
#define FUZZER_BYTE_PARSER_H_
#include <stdint.h>

#include <cstddef>
#include <vector>

bool parseCommands(const uint8_t* Data, size_t Size,
                   std::vector<std::vector<uint8_t>>& commands);

#endif