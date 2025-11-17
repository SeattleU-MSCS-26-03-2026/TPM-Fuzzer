import pytest
from pathlib import Path
import yaml

import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scripts.config_loader import load_config, ConfigError

def write_yaml(path: Path, content: dict):
    path.write_text(yaml.dump(content), encoding="utf-8")

def test_valid_config(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()

    cfg_file = tmp_path / "cfg.yaml"
    write_yaml(cfg_file, {
        "corpus_dir": str(corpus),
        "protocol": "tcp",
        "tpm_host": "127.0.0.1",
    })

    cfg = load_config(cfg_file)
    assert cfg["protocol"] == "tcp"
    assert cfg["tpm_host"] == "127.0.0.1"

def test_missing_field(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()

    cfg_file = tmp_path / "cfg.yaml"
    write_yaml(cfg_file, {
        "corpus_dir": str(corpus),
        "protocol": "tcp",
    })

    with pytest.raises(ConfigError):
        load_config(cfg_file)

def test_invalid_protocol(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()

    cfg_file = tmp_path / "cfg.yaml"
    write_yaml(cfg_file, {
        "corpus_dir": str(corpus),
        "protocol": "udp",
        "tpm_host": "127.0.0.1",
    })

    with pytest.raises(ConfigError):
        load_config(cfg_file)

def test_invalid_corpus_dir(tmp_path):
    cfg_file = tmp_path / "cfg.yaml"
    write_yaml(cfg_file, {
        "corpus_dir": str(tmp_path / "not_exist"),
        "protocol": "tcp",
        "tpm_host": "127.0.0.1",
    })

    with pytest.raises(ConfigError):
        load_config(cfg_file)
