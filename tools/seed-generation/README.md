# Seed Generator

The seed generator is a Python tool for defining and generating seed corpus entries for the Trusted Platform Module (TPM) fuzzer.

The tool is packaged using [uv](https://docs.astral.sh/uv/) and is intended to be used from within the TPM Fuzzer ecosystem rather than as a standalone utility. Protobuf support also depends on the CMake-generated artifacts in this directory already being present.

## Getting Started

1. Install [uv](https://docs.astral.sh/uv/)
2. Ensure Python 3.13 or newer is available
3. Ensure the CMake and protobuf generated artifacts already exist
4. Run `uv sync` to set up the Python environment
5. Run `uv run main.py -h`

## Architecture

### Directory Structure

The tooling is tightly coupled to the TPM Fuzzer, and some of the directories and files in this tool are auto-generated and not safe to edit manually. They are included here to support review and to improve LSP experiences.

The breakdown below highlights the auto-generated directories and files, as well as the purpose of the other files in this directory.

```sh
seed-generation/
├── constants/            # Auto-generated - CMake build artifact
├── main.py               # Command line program - contains seed test case definitions
├── pyproject.toml
├── README.md
├── tpm2_commands.py      # TPM command definitions - protobuf and bytearray serialization logic
├── tpm2_types.py         # TPM type definitions and logic
├── tpm_commands/         # Auto-generated - CMake build artifact
├── tpm_commands_pb2.py   # Auto-generated - CMake build artifact
├── tpm_types/            # Auto-generated - CMake build artifact
└── uv.lock
```

## Generating Seeds

Run the generator with:

```sh
uv run main.py
```

Useful options:

```sh
uv run main.py -recreate
uv run main.py --output-dir <output-dir>
```

The tool generates seed corpus files in `bytearray/` and `proto/` subdirectories under the selected output directory. Bytearray seeds are always generated. Protobuf seeds are only generated for commands that implement protobuf serialization.

Use `-recreate` after changing serialization logic or seed definitions to ensure the generated files stay aligned with the current test case definitions. Without `-recreate`, the tool only generates missing or newly added seeds.

### Protobuf and Bytearray Support

The tool supports both bytearray and protobuf seed outputs for the test cases defined in [main.py](./main.py).

#### Developer Note

To support protobuf seed generation for a [command](./tpm2_commands.py), define a `to_proto(self)` method on the relevant `TPMCommand` subclass.

Bytearray support is required for all commands and is implemented via `__bytes__`. If `to_proto(self)` is not implemented, the inherited default returns `None` and no protobuf seed is generated for that command.

Protobuf support is optional per command, but protobuf-only seeds are not supported.

## Extending the Generator

New command structures and serialization logic should be added in `tpm2_commands.py` by subclassing `TPMCommand`. Seed test cases are defined in `main.py`.

To add support for a new command:

1. Define the command structure in `tpm2_commands.py`
2. Implement `__bytes__` for bytearray serialization
3. Implement `to_proto(self)` if protobuf output is needed
4. Add the seed test cases in `main.py`
5. Regenerate the seeds, typically with `uv run main.py -recreate`

At the moment, supporting both formats effectively requires maintaining two representations of the command: one in this tool and one in protobuf.

## Validation

There are no dedicated automated tests for generated seeds.

Recommended validation methods:

- Manually inspect protobuf seeds, which are emitted in text format
- Use TPM Fuzzer tooling such as `test-seed.sh` for byte-oriented seed validation
- Run the fuzzer with `-runs=0` to inspect coverage behaviour
