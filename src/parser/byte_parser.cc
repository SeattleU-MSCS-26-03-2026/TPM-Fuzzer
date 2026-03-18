#include <arpa/inet.h>
#include <stdint.h>

#include <cstddef>
#include <cstring>
#include <vector>

const int kHeaderTagLen = 2;
const int kHeaderCommandSizeLen = 4;
const int kHeaderCommandCodeLen = 4;

bool parseCommands(const uint8_t* data, size_t size,
                   std::vector<std::vector<uint8_t>>& commands) {
  size_t offset = 0;
  commands.clear();

  while (offset < size) {
    if (offset + kHeaderTagLen + kHeaderCommandSizeLen + kHeaderCommandCodeLen >
        size)
      return false;

    // TAG
    uint16_t tag;
    memcpy(&tag, data + offset, kHeaderTagLen);
    tag = ntohs(tag);

    // COMMAND LENGTH
    uint32_t length = 0;
    memcpy(&length, data + offset + kHeaderTagLen, kHeaderCommandSizeLen);
    length = ntohl(length);

    if (length < kHeaderTagLen + kHeaderCommandSizeLen + kHeaderCommandCodeLen)
      return false;
    if (offset + length > size) return false;

    commands.emplace_back(data + offset, data + offset + length);

    offset += length;
  }

  return true;
}
