# Architecture

This document describes the overall design of the TPM 2.0 Fuzzer, including its two complementary fuzzing modes and how the components fit together.

## Overview

The TPM 2.0 Fuzzer is a coverage-guided fuzzing framework for testing TPM 2.0 implementations. It leverages [libFuzzer](https://llvm.org/docs/LibFuzzer.html) as its fuzzing engine and provides **two distinct fuzzing modes** to comprehensively test TPM implementations from different angles:

1. **Byte-level fuzzing** - Tests low-level parsing and error handling
2. **Structure-aware fuzzing** - Tests semantic logic and command-level behavior

Both modes work with the [TCG TPM 2.0 Reference Implementation](https://github.com/TrustedComputingGroup/TPM) and can be adapted for custom TPM implementations.

## System Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     libFuzzer Engine                         │
│              (Coverage-guided fuzzing loop)                  │
└────────┬──────────────────────────────────────────────┬─────┘
         │                                              │
    ┌────▼────────────┐                    ┌───────────▼────┐
    │  Byte Fuzzer    │                    │  Proto Fuzzer  │
    │  (Unstructured) │                    │ (Structured)   │
    └────┬────────────┘                    └───────────┬────┘
         │                                              │
    ┌────▼──────────────────┐              ┌──────────▼────┐
    │ Raw Byte Mutations    │              │ Protobuf      │
    │ - No format knowledge │              │ Generation &  │
    │ - Fast exploration    │              │ Mutation      │
    └────┬──────────────────┘              └──────────┬────┘
         │                                            │
         └────────────────────┬─────────────────────┘
                              │
                    ┌─────────▼──────────┐
                    │  TPM 2.0 Harness   │
                    │   (Core library)   │
                    └─────────┬──────────┘
                              │
                    ┌─────────▼──────────────┐
                    │ TPM 2.0 Implementation │
                    │ (Reference or Custom)  │
                    └────────────────────────┘
```

## Two Fuzzing Modes

### 1. Byte-level Fuzzer

**Purpose:** Discover low-level parsing bugs and error handling issues

**How it works:**
- Generates random sequences of raw bytes as input
- libFuzzer mutates these bytes and feeds them to the TPM harness
- No knowledge of TPM command structure
- Explores edge cases through brute-force mutation

**Characteristics:**

| Aspect | Details |
|--------|---------|
| **Input Format** | Raw bytes (no structure) |
| **Mutation Strategy** | Random bit/byte flips, inserts, deletes |
| **Coverage** | Fast exploration of parsing paths |
| **Best For** | Buffer overflows, format string bugs, parsing errors |
| **Execution Mode** | `./scripts/run-fuzzer.sh -bin fuzzer` |
| **Output Directories** | `corpus/`, `coverage/`, `artifacts/` |

---

### 2. Structure-aware (Proto) Fuzzer

**Purpose:** Exercise TPM command-level behavior using structured command sequences instead of arbitrary raw bytes.
**How it works:**
- Uses **libprotobuf-mutator** to generate well-formed TPM command structures
- Generates structured TPM command inputs using protobuf and applies post-processing to improve validity and reach deeper execution paths
- Mutates protobuf fields and uses post-processing to improve command validity
- Explores semantic behaviors and logical bugs

**Characteristics:**

| Aspect | Details |
|--------|---------|
| **Input Format** | Protobuf-encoded TPM commands |
| **Mutation Strategy** | Field-aware protobuf mutation plus post-processing |
| **Coverage** | Deeper command-handling and stateful TPM paths |
| **Best For** | Logic bugs, command sequencing issues, state management issues |
| **Execution Mode** | `./scripts/run-fuzzer.sh -bin proto-fuzzer` |
| **Output Directories** | `proto-corpus/`, `proto-coverage/`, `proto-artifacts/` |

---

## Key Differences

### Comparison Table

| Aspect | Byte Fuzzer | Proto Fuzzer |
|--------|------------|--------------|
| **Structure** | None (raw bytes) | Protobuf schema |
| **Validity** | Can generate invalid inputs | Generates more structured TPM commands than raw byte fuzzing |
| **Speed** | Faster (less constraint checking) | Slower (structure validation) |
| **Coverage Type** | Low-level parsing paths | High-level semantic paths |
| **Mutation** | Random bit/byte changes | Field-aware changes |
| **Bug Types Found** | Parser bugs, buffer issues | Logic bugs, state issues |

### Complementary Strengths

- **Byte Fuzzer** finds crashes and parsing errors quickly through random exploration
- **Proto Fuzzer** finds logical flaws by generating semantically valid but novel command sequences
- **Together** they provide comprehensive coverage of both low-level and high-level behavior

---

## Component Architecture

### 1. Core Harness Library

Located in `src/`, the harness library provides:

```
src/
├── TPM interface adapters
├── Corpus management
├── Coverage collection
├── Seed handling
└── Fuzzer targets (byte + proto)
```

**Responsibilities:**
- Normalize TPM implementation APIs to a common interface
- Manage input corpus (test cases)
- Collect and export coverage data
- Seed management for deterministic fuzzing

### 2. Fuzzer Targets

**Byte Fuzzer Target:**
- Accepts raw bytes
- Feeds directly to TPM harness
- Lightweight (minimal setup)

**Proto Fuzzer Target:**
- Accepts protobuf messages
- Uses `libprotobuf-mutator` for intelligent mutation
- Converts messages to TPM commands before execution

### 3. Coverage Collection

Both fuzzers collect coverage data using:
- **Instrumentation:** Clang's `-fprofile-instr-generate` flag
- **Output Format:** LLVM profdata format
- **Coverage Reports:** HTML-based coverage visualization in `coverage/` directories

### 4. Corpus Management

Both fuzzers maintain test case corpora:
- **Seed Corpus:** Initial test cases (see [SEEDS.md](./SEEDS.md))
- **Generated Corpus:** New interesting test cases discovered during fuzzing
- **Reproduction:** Any crash can be minimized and reproduced using corpus files

---

## Data Flow

### Fuzzing Loop

```
For each fuzzer type (byte or proto):

1. Load seed corpus
2. Initialize coverage tracking
3. Start libFuzzer loop:
   a) Generate/mutate input (byte | protobuf)
   b) Execute input against TPM
   c) Measure code coverage
   d) If new coverage: add to corpus
   e) If crash: save to artifacts/
4. Periodic coverage reports
5. Export final results
```

### Output Structure

```
corpus/                    # Generated test cases (byte fuzzer)
├── [hash1]
├── [hash2]
└── ...

proto-corpus/             # Generated test cases (proto fuzzer)
├── [hash1]
├── [hash2]
└── ...

coverage/                 # Coverage reports (byte fuzzer)
├── index.html
├── coverage-summary.txt
└── src/ (source files with coverage info)

proto-coverage/           # Coverage reports (proto fuzzer)
├── index.html
├── coverage-summary.txt
└── src/

artifacts/                # Crashes and errors (byte fuzzer)
├── crash-[hash]
├── leak-[hash]
└── ...

proto-artifacts/          # Crashes and errors (proto fuzzer)
├── crash-[hash]
├── leak-[hash]
└── ...
```

---

## Implementation Details

### Byte Fuzzer

**Entry Point:** `src/fuzzer.cc`

```c
// Minimal fuzzer target
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TPMContext context = InitializeTPM();
    ExecuteCommand(context, data, size);
    return 0;
}
```

**Mutation:** libFuzzer's default mutator creates random variations

### Proto Fuzzer

**Entry Point:** `src/proto_fuzzer.cc`

The proto fuzzer uses `DEFINE_PROTO_FUZZER` with a `TPMCommandSequence`.
libprotobuf-mutator generates and mutates structured command sequences, while project-specific post-processors normalize important TPM fields such as command tags, command codes, algorithms, handles, and session data.

At runtime, the fuzzer:
1. Initializes and starts the TPM
2. Iterates through each command in the generated `TPMCommandSequence`
3. Marshals each protobuf command into a TPM command buffer
4. Sends the command buffer through the TPM harness
5. Shuts down the TPM after the sequence finishes

**Mutation:** `libprotobuf-mutator` performs field-aware mutation, with post-processing to make generated command sequences more useful for exercising TPM command logic.


## Building and Running

### Docker-based Execution

```bash
# Byte fuzzer
docker compose build fuzzer
docker compose run fuzzer

# Proto fuzzer
docker compose build proto-fuzzer
docker compose run proto-fuzzer
```

### Direct Execution

```bash
# Build
./scripts/run-fuzzer.sh -bin fuzzer

# Run with seed corpus
./fuzzer -seed=38912891 -max_total_time=3600 seeds/
```

See [DEVELOPER.md](./DEVELOPER.md) for detailed build instructions.

---

## Coverage Analysis

Coverage data is collected during fuzzing:

- **Line Coverage:** Which lines of code were executed
- **Branch Coverage:** Which code paths were taken
- **Function Coverage:** Which functions were exercised

Coverage reports are generated as HTML for manual inspection:
```
coverage/index.html    # Byte fuzzer coverage
proto-coverage/index.html  # Proto fuzzer coverage
```

---

## Advantages of Dual-Mode Approach

| Advantage | Impact |
|-----------|--------|
| **Complementary Testing** | Catches both low-level and semantic bugs |
| **Faster Discovery** | Byte fuzzer finds quick wins; proto finds deep issues |
| **Reduced False Positives** | Proto mode validates inputs before execution |
| **Comprehensive Coverage** | Combined coverage > either mode alone |
| **Flexible Deployment** | Can run separately or in parallel |

---

## Extending the Architecture

### Supporting Custom TPM Implementations

See [CUSTOM_TPM.md](./CUSTOM_TPM.md) for details on adapting the fuzzer for non-standard TPM implementations.

### Adding New Fuzzing Modes

The architecture is designed to support additional fuzzing modes:

1. Create a new fuzzer target in `src/`
2. Add corresponding harness glue code
3. Wire up in `CMakeLists.txt`
4. Update Docker compose for automated building

---

## References

- [libFuzzer Documentation](https://llvm.org/docs/LibFuzzer.html)
- [libprotobuf-mutator GitHub](https://github.com/google/libprotobuf-mutator)
- [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
