#include <arpa/inet.h>
#include <byte_parser.h>

#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstring>

static std::vector<uint8_t> makeCommand(
    uint16_t tag, uint32_t commandCode,
    const std::vector<uint8_t>& payload = {}) {
  uint32_t length = 2 + 4 + 4 + payload.size();

  std::vector<uint8_t> cmd;
  cmd.reserve(length);

  // TAG
  cmd.push_back((tag >> 8) & 0xFF);
  cmd.push_back(tag & 0xFF);

  // COMMAND SIZE
  cmd.push_back((length >> 24) & 0xFF);
  cmd.push_back((length >> 16) & 0xFF);
  cmd.push_back((length >> 8) & 0xFF);
  cmd.push_back(length & 0xFF);

  // COMMAND CODE
  cmd.push_back((commandCode >> 24) & 0xFF);
  cmd.push_back((commandCode >> 16) & 0xFF);
  cmd.push_back((commandCode >> 8) & 0xFF);
  cmd.push_back(commandCode & 0xFF);

  // Payload
  cmd.insert(cmd.end(), payload.begin(), payload.end());

  return cmd;
}

TEST_CASE("parseCommands parses a single valid command") {
  auto cmd = makeCommand(0x8001, 0x0000017B);  // TPM2_GetRandom

  std::vector<std::vector<uint8_t>> commands;
  bool ok = parseCommands(cmd.data(), cmd.size(), commands);

  REQUIRE(ok);
  REQUIRE(commands.size() == 1);
  REQUIRE(commands[0] == cmd);
}

TEST_CASE("parseCommands parses multiple commands") {
  auto cmd1 = makeCommand(0x8001, 0x0000017B);                // TPM2_GetRandom
  auto cmd2 = makeCommand(0x8002, 0x00000144, {0x00, 0x10});  // TPM2_Startup

  std::vector<uint8_t> input;
  input.insert(input.end(), cmd1.begin(), cmd1.end());
  input.insert(input.end(), cmd2.begin(), cmd2.end());

  std::vector<std::vector<uint8_t>> commands;
  bool ok = parseCommands(input.data(), input.size(), commands);

  REQUIRE(ok);
  REQUIRE(commands.size() == 2);
  REQUIRE(commands[0] == cmd1);
  REQUIRE(commands[1] == cmd2);
}

TEST_CASE("parseCommands rejects invalid tag") {
  auto bad = makeCommand(0x1234, 0x0000017B);  // TPM2_GetRandom

  std::vector<std::vector<uint8_t>> commands;
  bool ok = parseCommands(bad.data(), bad.size(), commands);

  REQUIRE_FALSE(ok);
  REQUIRE(commands.empty());
}

TEST_CASE("parseCommands rejects length smaller than header") {
  std::vector<uint8_t> bad = {0x80, 0x01,              // TAG
                              0x00, 0x00, 0x00, 0x05,  // SIZE = 5
                              0x00, 0x00, 0x00, 0x00};

  std::vector<std::vector<uint8_t>> commands;
  bool ok = parseCommands(bad.data(), bad.size(), commands);

  REQUIRE_FALSE(ok);
}

TEST_CASE("parseCommands rejects length exceeding buffer") {
  std::vector<uint8_t> bad = {0x80, 0x01,              // TAG
                              0x00, 0x00, 0x00, 0x20,  // SIZE = 32
                              0x00, 0x00, 0x01, 0x7B};

  std::vector<std::vector<uint8_t>> commands;
  bool ok = parseCommands(bad.data(), bad.size(), commands);

  REQUIRE_FALSE(ok);
}
