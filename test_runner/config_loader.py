#!/usr/bin/env python3
import yaml
from pathlib import Path

class ConfigError(Exception):
    """Raised when configuration is invalid."""
    pass

REQUIRED_FIELDS = {"corpus_dir", "protocol", "tpm_host"}
ALLOWED_PROTOCOLS = {"tcp"}

def load_config(config_path: str | Path) -> dict:
    config_path = Path(config_path)

    if not config_path.exists():
        raise ConfigError(f"Configuration file not found: {config_path}")

    try:
        data = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ConfigError(f"Failed to parse YAML: {e}") from e

    if not isinstance(data, dict):
        raise ConfigError("Configuration root must be a YAML mapping (dict)")

    # Check required fields
    for field in REQUIRED_FIELDS:
        if field not in data:
            raise ConfigError(f"Missing required field: '{field}'")

    # Validate corpus_dir
    corpus_dir = Path(data["corpus_dir"])
    if not corpus_dir.is_dir():
        raise ConfigError(f"Corpus directory does not exist: {corpus_dir}")
    data["corpus_dir"] = str(corpus_dir.resolve())

    # Validate protocol
    protocol = str(data["protocol"]).lower()
    if protocol not in ALLOWED_PROTOCOLS:
        allowed = ", ".join(ALLOWED_PROTOCOLS)
        raise ConfigError(f"Invalid protocol '{protocol}'. Allowed: {allowed}")
    data["protocol"] = protocol

    # Validate tpm_host
    if not str(data["tpm_host"]).strip():
        raise ConfigError("tpm_host must be a non-empty string")

    return data


if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parent.parent
    config_path = repo_root / "tpm_fuzzer_config.yaml"

    try:
        config = load_config(config_path)
    except ConfigError as e:
        print(f"[config error] {e}")
        exit(1)

    print("Loaded configuration:")
    for k, v in config.items():
        print(f"  {k}: {v}")
