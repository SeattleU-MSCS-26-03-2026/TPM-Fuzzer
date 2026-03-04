terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.22"
    }
  }

  required_version = ">= 1.2"
}
