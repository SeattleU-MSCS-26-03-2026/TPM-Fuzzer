# Fuzzer

This directory contains the source code for the TPM Fuzzer binary. The fuzzer
uses libFuzzer to exercise the TPM SendCommand API and uncover unexpected
behavior.

## Developer Guide

Note: This project requires OpenSSL version 1.1.x through 3.5.x. It will not
build with OpenSSL 3.6 or newer. If your operating system includes a newer
version, you must direct CMake to a compatible OpenSSL installation.

To configure the build with your chosen OpenSSL version, provide the following
variables when running CMake:

```sh
cmake -B build -DOPENSSL_ROOT_DIR=<path to openssl root> -DOPENSSL_INCLUDE_DIR=<path to openssl root>/include
cmake --build build
```



## Configuring the corpus directory

The fuzzer expects a corpus directory, which is the folder where input
samples are stored and evolved during fuzzing runs.

By default we use a corpus/ directory at the repository root:

SUSE-26-03-Google/
  corpus/          # default corpus directory
  fuzzer/
  scripts/
  ...


To configure (and optionally override) the corpus directory, run:

```sh
./scripts/config_corpus.py
```

The script:

- Shows the default corpus directory (e.g. <repo_root>/corpus)

- Allows the user to enter a different path

- Creates the directory if it does not exist

- Writes the configuration to tpm_fuzzer_config.yaml
```yaml
corpus_dir: "./corpus"
protocol: "tcp"
tpm_host: "127.0.0.1"
```

## Running the fuzzer

After building the Fuzzer binary and configuring the corpus directory, the
fuzzer can be invoked by passing the corpus directory as its argument:

```sh
./build/Fuzzer ./corpus
```


## Loader

Configuration is loaded using scripts/config_loader.py, which:

- Parses the YAML configuration

- Validates required fields (corpus_dir, protocol, tpm_host)

- Ensures the corpus directory exists

- Ensures the protocol value is valid

- Throws descriptive errors for invalid or missing fields

Run:
```sh
python3 scripts/config_loader.py
```

## Tests

Tests are located under tests/ and can be executed using:
```sh
pytest -q
```

Tests cover:

- Valid configurations

- Missing required fields

- Invalid protocol values

- Nonexistent corpus directories