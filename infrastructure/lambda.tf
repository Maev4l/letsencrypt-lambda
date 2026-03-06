# Pre-built zip from function/dist/lambda.zip (run: cd function && yarn build && yarn package)
locals {
  lambda_zip_path = "${path.module}/../function/dist/lambda.zip"

  lambda_environment_variables = {
    REGION                         = var.region
    DOMAIN_HOSTED_ZONE_NAME        = var.domain_name
    DOMAIN_CERTIFICATE_COMMON_NAME = var.domain_certificate_common_name
    DOMAIN_HOSTED_ZONE_ID          = var.domain_hosted_zone_id
    CERTIFICATE_REGION             = var.certificate_region
    # Comma-separated list of regions, e.g.: "eu-central-1,us-west-2,ap-southeast-1"
    SECONDARY_CERTIFICATE_REGIONS   = var.secondary_certificate_regions
    BUCKET_NAME                     = var.bucket_name
    S3_LETSENCRYPT_ACCOUNT_KEY_NAME = var.s3_letsencrypt_account_key_name
    TOPIC_ARN                       = var.topic_arn
    TAG_APPLICATION                 = var.tag_application
    TAG_OWNER                       = var.tag_owner
    DIRECTORY                       = var.directory
  }
}

# Lambda function: renew certificates
module "renew_certificates" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.5.0"

  function_name = "renew-certificates"
  zip = {
    filename = local.lambda_zip_path
    runtime  = "nodejs22.x"
    handler  = "main.renewCertificates"
  }
  architecture           = "arm64"
  memory_size            = var.lambda_memory_size
  timeout                = var.lambda_timeout
  log_retention_in_days  = 7
  additional_policy_arns = [aws_iam_policy.lambda.arn]
  environment_variables  = local.lambda_environment_variables
}

# Lambda function: revoke certificate
module "revoke_certificate" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.5.0"

  function_name = "revoke-certificate"
  zip = {
    filename = local.lambda_zip_path
    runtime  = "nodejs22.x"
    handler  = "main.revokeCertificate"
  }
  architecture           = "arm64"
  memory_size            = var.lambda_memory_size
  timeout                = var.lambda_timeout
  log_retention_in_days  = 7
  additional_policy_arns = [aws_iam_policy.lambda.arn]
  environment_variables  = local.lambda_environment_variables
}

# EventBridge Scheduler trigger for certificate renewal
module "renew_certificates_scheduler" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-trigger-scheduler?ref=v1.5.0"

  function_name       = module.renew_certificates.function_name
  function_arn        = module.renew_certificates.function_arn
  schedule_name       = "renew-certificates-schedule"
  schedule_expression = var.schedule_rate
  description         = "Trigger certificate renewal"
}
