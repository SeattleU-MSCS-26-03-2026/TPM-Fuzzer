#include <arpa/inet.h>
#include <stdint.h>

#include <cstddef>
#include <cstring>
#include <vector>

#define HEADER_TAG_LEN 2
#define HEADER_COMMAND_SIZE_LEN 4
#define HEADER_COMMAND_CODE_LEN 4

bool parseCommands(const uint8_t* Data, size_t Size,
                   std::vector<std::vector<uint8_t>>& commands) {
  size_t offset = 0;
  commands.clear();

  while (offset < Size) {
    if (offset + HEADER_TAG_LEN + HEADER_COMMAND_SIZE_LEN +
            HEADER_COMMAND_CODE_LEN >
        Size)
      return false;

    // TAG
    uint16_t tag;
    memcpy(&tag, Data + offset, HEADER_TAG_LEN);
    tag = ntohs(tag);

    if (tag != 0x8001 && tag != 0x8002) return false;

    // COMMAND LENGTH
    uint32_t length = 0;
    memcpy(&length, Data + offset + HEADER_TAG_LEN, HEADER_COMMAND_SIZE_LEN);
    length = ntohl(length);

    if (length <
        HEADER_TAG_LEN + HEADER_COMMAND_SIZE_LEN + HEADER_COMMAND_CODE_LEN)
      return false;
    if (offset + length > Size) return false;

    commands.emplace_back(Data + offset, Data + offset + length);

    offset += length;
  }

  return true;
}
