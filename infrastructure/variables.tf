variable "region" {
  description = "AWS region for deployment"
  type        = string
  default     = "eu-central-1"
}

variable "domain_name" {
  description = "Route53 hosted zone domain name"
  type        = string
  default     = "isnan.eu"
}

variable "domain_certificate_common_name" {
  description = "Certificate common name (e.g., *.isnan.eu)"
  type        = string
  default     = "*.isnan.eu"
}

variable "domain_hosted_zone_id" {
  description = "Route53 hosted zone ID"
  type        = string
  default     = "ZWC66FN0XU6P9"
}

variable "certificate_region" {
  description = "Primary region for ACM certificate"
  type        = string
  default     = "us-east-1"
}

variable "secondary_certificate_regions" {
  description = "Additional regions to import certificate (comma-separated, e.g., 'eu-central-1,us-west-2')"
  type        = string
  default     = "eu-central-1"
}

variable "bucket_name" {
  description = "S3 bucket name for Let's Encrypt storage"
  type        = string
  default     = "letsencrypt-lambda-storage"
}

variable "s3_letsencrypt_account_key_name" {
  description = "S3 key name for the ACME account key"
  type        = string
  default     = "account-key"
}

variable "topic_arn" {
  description = "SNS topic ARN for alerting"
  type        = string
  default     = "arn:aws:sns:eu-central-1:671123374425:alerting-events"
}

variable "tag_application" {
  description = "Application tag value"
  type        = string
  default     = "letsencrypt-lambda"
}

variable "tag_owner" {
  description = "Owner tag value"
  type        = string
  default     = "terraform"
}

variable "directory" {
  description = "Let's Encrypt directory (production or staging)"
  type        = string
  default     = "production"
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB"
  type        = number
  default     = 128
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 180
}

variable "schedule_rate" {
  description = "Schedule rate for certificate renewal"
  type        = string
  default     = "rate(30 days)"
}
