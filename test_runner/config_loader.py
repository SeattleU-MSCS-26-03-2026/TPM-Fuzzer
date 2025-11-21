#!/usr/bin/env python3
import yaml
from pathlib import Path

class ConfigError(Exception):
    """Raised when configuration is invalid."""
    pass

REQUIRED_FIELDS = {"corpus_dir", "protocol", "tpm_host"}
ALLOWED_PROTOCOLS = {"tcp"}

# Default configuration values (fallback when YAML is missing)
DEFAULT_CONFIG = {
    "corpus_dir": str((Path(__file__).resolve().parent / "corpus")),
    "protocol": "tcp",
    "tpm_host": "127.0.0.1",
}

def load_config(config_path: str | Path | None, allow_defaults: bool = False) -> dict:
    """
    Load configuration from YAML and validate it.

    Behavior:
    - If config_path exists → load YAML + validate (strict)
    - If config_path does NOT exist:
        * if allow_defaults = True → use DEFAULT_CONFIG
        * else → raise ConfigError
    """
    repo_root = Path(__file__).resolve().parent

    # ---- Case 1: No config path provided ----
    if config_path is None:
        if not allow_defaults:
            raise ConfigError("No configuration file provided.")
        cfg = DEFAULT_CONFIG.copy()
    else:
        config_path = Path(config_path)

        # ---- Case 2: config.yaml missing ----
        if not config_path.exists():
            if not allow_defaults:
                raise ConfigError(f"Configuration file not found: {config_path}")
            cfg = DEFAULT_CONFIG.copy()
        else:
            # ---- Case 3: Load YAML ----
            try:
                raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
            except yaml.YAMLError as e:
                raise ConfigError(f"Failed to parse YAML: {e}") from e

            if not isinstance(raw, dict):
                raise ConfigError("Configuration root must be a YAML mapping (dict)")

            # Merge user YAML over defaults (user overrides defaults)
            cfg = {**DEFAULT_CONFIG, **raw}

    # ---- Validation ----

    # Validate corpus_dir
    corpus_dir = Path(cfg["corpus_dir"])
    if not corpus_dir.is_dir():
        raise ConfigError(f"Corpus directory does not exist: {corpus_dir}")
    cfg["corpus_dir"] = str(corpus_dir.resolve())

    # Validate protocol
    protocol = str(cfg["protocol"]).lower()
    if protocol not in ALLOWED_PROTOCOLS:
        allowed = ", ".join(ALLOWED_PROTOCOLS)
        raise ConfigError(f"Invalid protocol '{protocol}'. Allowed: {allowed}")
    cfg["protocol"] = protocol

    # Validate tpm_host
    if not str(cfg["tpm_host"]).strip():
        raise ConfigError("tpm_host must be a non-empty string")

    return cfg


if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parent
    config_path = repo_root / "config.yaml"

    try:
        # allow_defaults=True even without yaml
        config = load_config(config_path, allow_defaults=True)
    except ConfigError as e:
        print(f"[config error] {e}")
        exit(1)

    print("Loaded configuration:")
    for k, v in config.items():
        print(f"  {k}: {v}")
