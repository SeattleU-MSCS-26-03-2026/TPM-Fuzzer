provider "google" {
  project = "goog-tcg"
  region  = "us-west1"
}

data "google_artifact_registry_repository" "seattleu_registry" {
  location      = var.artifact_registry.location
  repository_id = var.artifact_registry.repository_id
}

data "google_artifact_registry_docker_image" "fuzzer" {
  location      = data.google_artifact_registry_repository.seattleu_registry.location
  repository_id = data.google_artifact_registry_repository.seattleu_registry.repository_id
  image_name    = var.artifact_registry.image_name
}

resource "google_cloud_run_v2_job" "default" {
  name                = var.job.name
  location            = var.job.location
  deletion_protection = var.job.deletion_protection

  template {
    template {
      max_retries     = var.job.max_retries
      service_account = var.job.service_account

      containers {
        image = data.google_artifact_registry_docker_image.fuzzer.self_link

        dynamic "env" {
          for_each = var.container_env
          content {
            name  = env.value.name
            value = env.value.value
          }
        }

        volume_mounts {
          mount_path = var.corpus_store.mount_path
          name       = var.corpus_store.volume_name
        }
      }
      volumes {
        name = var.corpus_store.volume_name
        gcs {
          bucket        = var.corpus_store.bucket
          mount_options = var.corpus_store.mount_options
          read_only     = var.corpus_store.read_only
        }
      }
    }
  }
}
