terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # >= 6.37 required for S3 bucket account-regional namespace support.
      version = "~> 6.37"
    }
  }

  backend "s3" {
    bucket       = "global-tf-states"
    key          = "letsencrypt-lambda/terraform.tfstate"
    region       = "eu-central-1"
    use_lockfile = true # S3 native locking (no DynamoDB needed)
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      application = "letsencrypt-lambda"
      owner       = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
