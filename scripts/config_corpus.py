#!/usr/bin/env python3
import yaml
from pathlib import Path

DEFAULT_PROTOCOL = "tcp"
DEFAULT_TPM_HOST = "127.0.0.1"

def main():
    repo_root = Path(__file__).resolve().parent.parent
    default_corpus = repo_root / "corpus"
    default_yaml = repo_root / "tpm_fuzzer_config.yaml"

    print("=== TPM Fuzzer Configuration Generator ===\n")

    print(f"Default corpus directory:\n  {default_corpus}")
    user_corpus = input("Enter corpus directory (press ENTER to use default): ").strip()
    corpus_dir = Path(user_corpus).expanduser().resolve() if user_corpus else default_corpus
    corpus_dir.mkdir(parents=True, exist_ok=True)

    protocol = input(f"Protocol (default: {DEFAULT_PROTOCOL}): ").strip() or DEFAULT_PROTOCOL
    tpm_host = input(f"TPM host (default: {DEFAULT_TPM_HOST}): ").strip() or DEFAULT_TPM_HOST

    config = {
        "corpus_dir": str(corpus_dir),
        "protocol": protocol,
        "tpm_host": tpm_host,
    }

    with default_yaml.open("w", encoding="utf-8") as f:
        yaml.dump(config, f)

    print("\nConfiguration written to:")
    print(f"  {default_yaml}")

    print("\nFinal configuration:")
    for k, v in config.items():
        print(f"  {k}: {v}")

if __name__ == "__main__":
    main()
