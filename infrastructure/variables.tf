variable "region" {
  description = "AWS region for the deployment (Lambda + Route53 client)."
  type        = string
  default     = "eu-central-1"
}

variable "domains" {
  description = "Per-domain certificate configuration. Each entry produces one cert."
  type = list(object({
    common_name         = string
    hosted_zone_id      = string
    acm_regions         = list(string)               # primary first, then secondaries
    pem_storage_regions = optional(list(string), []) # empty = no PEM storage
  }))

}

variable "pem_bucket_prefix" {
  description = "Prefix for per-region PEM buckets in the account-regional namespace. Final bucket name: '<prefix>-<accountId>-<region>-an'."
  type        = string
  default     = "letsencrypt-pems"
}

variable "account_key_parameter" {
  description = "SSM Parameter Store name for the ACME account key (SecureString)."
  type        = string
  default     = "letsencrypt-lambda-account-key"
}

variable "topic_arn" {
  description = "SNS topic ARN for alerting."
  type        = string
  default     = "arn:aws:sns:eu-central-1:671123374425:alerting-events"
}

variable "tag_application" {
  description = "Application tag value."
  type        = string
  default     = "letsencrypt-lambda"
}

variable "tag_owner" {
  description = "Owner tag value."
  type        = string
  default     = "terraform"
}

variable "directory" {
  description = "Let's Encrypt directory (production or staging) — runtime default; per-invocation override via event payload."
  type        = string
  default     = "production"
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB."
  type        = number
  default     = 128
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds."
  type        = number
  default     = 180
}

variable "schedule_rate" {
  description = "Schedule rate for certificate renewal."
  type        = string
  default     = "rate(7 days)"
}
