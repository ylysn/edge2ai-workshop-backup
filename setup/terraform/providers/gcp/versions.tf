
terraform {
  required_version = ">= 0.12"

  required_providers {
    google = {
      source  = "registry.terraform.io/hashicorp/google"
      version = ">= 5.10.0"
    }
    null = {
      source  = "hashicorp/null"
      version = ">= 2.1"
    }
  }

}
