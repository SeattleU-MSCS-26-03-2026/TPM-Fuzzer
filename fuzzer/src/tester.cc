#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <print>
#include <vector>

#include "harness/tpm_wrapper.h"
#include "parser/byte_parser.h"

// -----------------------------------------------------------------------------
// Forward declarations
// -----------------------------------------------------------------------------

/**
 * Prints the program arguments for debugging purposes.
 *
 * This function is compiled only when DEBUG is defined and is intended for
 * inspecting the exact argv/argc values the program was launched with.
 *
 * Behavior:
 *  - If @p argv is null, a message is printed and the function returns.
 *  - Otherwise, the number of arguments and each argument string are printed.
 *
 * @param argc Number of command-line arguments, including the program name.
 * @param argv Array of C-string arguments; may be nullptr only if @p argc is 0.
 */
void DebugArgs(int argc, char** argv);

/**
 * Reads the entire contents of a corpus file into a buffer.
 *
 * On success:
 *  - @p buffer is resized to exactly match the file size.
 *  - @p length is set to the number of bytes read.
 *
 * On failure:
 *  - An error is printed to stderr.
 *  - The process terminates with a non-zero exit code.
 *
 * @param path   Null-terminated path to the file to be read; must not be null.
 * @param buffer Output buffer that will be filled with file contents.
 * @param length Output length of the buffer after reading.
 */
void ReadCorpus(char* path, std::vector<char>& buffer, size_t& length);

/**
 * Sends a TPM command buffer and returns the raw response.
 *
 * The function:
 *  - Performs basic size validation of the input command.
 *  - Logs TPM header fields (tag, length, command code) when present.
 *  - Emits a hex and binary dump of the command buffer.
 *  - Sends the command to the TPM via TPMSendCommand.
 *
 * @param command TPM command buffer to send.
 * @return Raw TPM response buffer of size kMaxBuffers. The caller is
 *         responsible for interpreting / trimming the buffer contents.
 */
std::vector<uint8_t> SendCommand(std::vector<uint8_t> command);

/**
 * Prints out a TPM response buffer.
 *
 * The function prints:
 *   - Response tag and size (if header is present).
 *   - Hex dump of the entire response.
 *   - Binary dump of the entire response.
 *
 * If the response buffer is empty, a short message is printed instead.
 *
 * @param response TPM response buffer to print.
 */
void PrintResponse(std::vector<uint8_t> response);

// -----------------------------------------------------------------------------
// Function definitions
// -----------------------------------------------------------------------------

int main(int argc, char* argv[]) {
#ifdef DEBUG
  DebugArgs(argc, argv);
#endif

  if (argc < 2) {
    std::println(stderr, "expected file path.\nUsage: {} FILE_PATH", argv[0]);
    return 1;
  }

  char* path = argv[1];
  size_t length = 0;
  std::vector<char> in;
  std::vector<std::vector<uint8_t>> commands;

  ReadCorpus(path, in, length);
  if (length == 0) {
    std::println(stderr, "empty corpus file: {}", path);
    return 1;
  }

  if (!parseCommands(reinterpret_cast<uint8_t*>(in.data()), length, commands)) {
    std::println(stderr, "failed to parse corpus file: {}", path);
    return 1;
  }

  // Prepare TPM and perform startup.
  TPMManufactureIfNeeded();
  TPMStartup();
  SendTPM2StartupCommand();

  // Send all parsed commands and print their responses.
  for (auto command : commands) {
    PrintResponse(SendCommand(command));
  }

  SendTPM2ShutdownCommand();
  TPMShutdown();

  return 0;
}

void DebugArgs(int argc, char** argv) {
  if (argv == nullptr) {
    std::println(stderr, "DebugArgs called with null argv");
    return;
  }

  std::print(stdout, "Arg count: {}\nArguments:\n", argc);
  for (int i = 0; i < argc; ++i) {
    if (argv[i] == nullptr) {
      std::println(stdout, "(null)");
    } else {
      std::println(stdout, "{}", argv[i]);
    }
  }
}

void ReadCorpus(char* path, std::vector<char>& buffer, size_t& length) {
  if (path == nullptr) {
    std::println(stderr, "null file path provided");
    std::exit(1);
  }

  std::ifstream infile(path, std::ios_base::binary);
  if (!infile.is_open()) {
    std::println(stderr, "failed to open file: {}", path);
    std::exit(1);
  }

  infile.seekg(0, std::ios::end);
  const std::streampos end_pos = infile.tellg();
  if (!infile.good() || end_pos < 0) {
    std::println(stderr, "failed to determine file size: {}", path);
    std::exit(1);
  }

  length = static_cast<size_t>(end_pos);
  infile.seekg(0, std::ios::beg);
  if (!infile.good()) {
    std::println(stderr, "failed to seek to beginning of file: {}", path);
    std::exit(1);
  }

  buffer.resize(length);
  if (!buffer.empty()) {
    infile.read(buffer.data(), static_cast<std::streamsize>(length));
    if (!infile) {
      std::println(stderr, "failed to read file: {}", path);
      std::exit(1);
    }
  }
}

std::vector<uint8_t> SendCommand(std::vector<uint8_t> command) {
  std::println("==============================");
  std::println("            REQUEST           ");
  std::println("==============================");

  // Basic validation before logging and sending.
  if (command.size() < 10) {
    std::println(
        stderr,
        "command too short ({} bytes); expected at least TPM header size",
        command.size());
  }

  // Print the session tag and command length in hex, if available.
  if (command.size() >= 6) {
    uint16_t tag;
    uint32_t length;
    memcpy(&tag, command.data(), 2);
    memcpy(&length, command.data() + 2, 4);
    std::println(stdout, "TPM Command Tag (hex): 0x{:04x}", tag);
    std::println(stdout, "TPM Command Length (hex): 0x{:08x}", length);
  } else {
    std::println(stdout,
                 "TPM command too short to contain tag and length ({} bytes)",
                 command.size());
  }

  // Print the command size in bytes.
  std::println(stdout, "TPM Command Buffer Size (bytes): {}", command.size());

  // Print the command code in hex, if available.
  if (command.size() >= 10) {
    uint32_t code;
    memcpy(&code, command.data() + 6, 4);
    std::println(stdout, "TPM Command Code (hex): 0x{:08x}", code);
  } else {
    std::println(stdout,
                 "TPM command too short to contain command code ({} bytes)",
                 command.size());
  }

  // Hex and binary dumps of the command.
  if (!command.empty()) {
    std::println(stdout, "TPM Command (hex):");
    for (size_t i = 0; i < command.size(); ++i) {
      std::print(stdout, "{:02x} ", command[i]);
      if ((i + 1) % 16 == 0) {
        std::print(stdout, "\n");
      }
    }
    if (command.size() % 16 != 0) {
      std::print(stdout, "\n");
    }

    std::println(stdout, "TPM Command (binary):");
    for (size_t i = 0; i < command.size(); ++i) {
      for (int bit = 7; bit >= 0; --bit) {
        std::print(stdout, "{}", (command[i] >> bit) & 0x1);
      }
      std::print(stdout, " ");
      if ((i + 1) % 8 == 0) {
        std::print(stdout, "\n");
      }
    }
    if (command.size() % 8 != 0) {
      std::print(stdout, "\n");
    }
  }

  std::println("");
  std::println("");

  InBuffer request;
  request.buffer = command.data();
  request.buffer_size = command.size();

  std::vector<uint8_t> out;
  out.resize(kMaxBuffers);
  OutBuffer response;
  response.buffer = out.data();
  response.buffer_size = out.size();

  TPMSendCommand(kDefaultLocality, request, &response);
  out.resize(response.buffer_size);
  return out;
}

void PrintResponse(std::vector<uint8_t> response) {
  std::println("==============================");
  std::println("            RESPONSE          ");
  std::println("==============================");

  if (response.empty()) {
    std::println(stdout, "Empty TPM response.");
    return;
  }

  // Print response tag and size if available.
  if (response.size() >= 6) {
    uint16_t tag;
    uint32_t size;
    memcpy(&tag, response.data(), 2);
    memcpy(&size, response.data() + 2, 4);

    std::println(stdout, "TPM Response Tag (hex): 0x{:04x}", tag);
    std::println(stdout, "TPM Response Size (hex): 0x{:08x}", size);
  } else {
    std::println(stdout,
                 "TPM response too short to contain tag and size ({} bytes)",
                 response.size());
  }

  // Hex dump of the response.
  std::println(stdout, "TPM Response (hex):");
  for (size_t i = 0; i < response.size(); ++i) {
    std::print(stdout, "{:02x} ", response[i]);
    if ((i + 1) % 16 == 0) {
      std::print(stdout, "\n");
    }
  }
  if (response.size() % 16 != 0) {
    std::print(stdout, "\n");
  }

  // Binary dump of the response.
  std::println(stdout, "TPM Response (binary):");
  for (size_t i = 0; i < response.size(); ++i) {
    for (int bit = 7; bit >= 0; --bit) {
      std::print(stdout, "{}", (response[i] >> bit) & 0x1);
    }
    std::print(stdout, " ");
    if ((i + 1) % 8 == 0) {
      std::print(stdout, "\n");
    }
  }
  if (response.size() % 8 != 0) {
    std::print(stdout, "\n");
  }

  std::println("");
  std::println("");
}
