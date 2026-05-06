artifact_registry = {
  location      = "us"
  repository_id = "seattleu"
  image_name    = "seattleu-fuzzing:latest"
}

job = {
  name                = "tpm-fuzzer"
  location            = "us-west1"
  deletion_protection = true
  max_retries         = 0
  service_account     = "22998728541-compute@developer.gserviceaccount.com"
}

container_env = [
  { name = "GEN_COVERAGE", value = "1" },
  { name = "FUZZER_EXTRA_ARGS", value = "-max_total_time=28800" },
  { name = "CORPUS_DIR", value = "/mnt/gcs/corpus" },
  { name = "COVERAGE_DIR", value = "/mnt/gcs/coverage" },
  { name = "ARTIFACTS_DIR", value = "/mnt/gcs/artifacts" },
  { name = "FUZZER_BIN_NAME", value = "Fuzzer" },
]

corpus_store = {
  volume_name   = "gcs-vol"
  mount_path    = "/mnt/gcs"
  bucket        = "tcg_private"
  mount_options = []
  read_only     = false
}
