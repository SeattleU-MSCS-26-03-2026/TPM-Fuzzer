variable "artifact_registry" {
  type = object({
    location      = string
    repository_id = string
    image_name    = string
  })

  default = {
    location      = "us"
    repository_id = "seattleu"
    image_name    = "seattleu-fuzzing:latest"
  }

  description = "Configures Artifact registry to pull registry and image information."
}

variable "job" {
  type = object({
    name                = string
    location            = string
    deletion_protection = bool
    max_retries         = number
    service_account     = string
  })

  default = {
    name                = "tpm-fuzzer"
    location            = "us-west1"
    deletion_protection = true
    max_retries         = 0
    service_account     = "22998728541-compute@developer.gserviceaccount.com"
  }

  description = "CloudRun Job configuration."
}

variable "container_env" {
  type = list(object({
    name  = string
    value = string
  }))

  default = [
    { name = "FUZZER_GEN_COVERAGE", value = "1" },
    { name = "FUZZER_EXTRA_ARGS", value = "-seed=38912891 -max_total_time=60" },
    { name = "GEN_CORPUS_DIR", value = "/mnt/gcs/corpus" },
    { name = "SEED_CORPUS_DIR", value = "/srv/seeds" },
    { name = "FUZZER_COVERAGE_OUT_DIR", value = "/mnt/gcs/coverage" },
  ]

  description = "Fuzzer container environment."
}

variable "corpus_store" {
  type = object({
    volume_name   = string
    mount_path    = string
    bucket        = string
    mount_options = list(string)
    read_only     = bool
  })

  default = {
    volume_name   = "gcs-vol"
    mount_path    = "/mnt/gcs"
    bucket        = "tcg_private"
    mount_options = []
    read_only     = false
  }

  description = "Cloud storage bucket to store corpus, coverage and artifacts."
}
