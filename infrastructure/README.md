# Infrastructure

This directory contains the terraform code to setup the GCP Cloud Run infrastructure used to perform
scheduled fuzzing runs.

## Getting Started

You'll require the following tools:

- Terraform
- gcloud


Ensure `gcloud` is authenticated:

``` sh
gcloud init
```

Ensure `terraform` backend is initialized and up-to-date:

``` sh
terraform init -upgrade
```

View `variable.tf` for the supported variables, Modify variables in `terraform.tfvars`.
