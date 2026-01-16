#ifndef FUZZER_BYTE_PARSER_H_
#define FUZZER_BYTE_PARSER_H_
#include <stdint.h>

#include <cstddef>
#include <vector>

bool parseCommands(const uint8_t* data, size_t size,
                   std::vector<std::vector<uint8_t>>& commands);

#endif
