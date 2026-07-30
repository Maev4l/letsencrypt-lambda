# Pre-built zip from function/dist/lambda.zip (run: cd function && yarn build && yarn package)
locals {
  lambda_zip_path = "${path.module}/../function/dist/lambda.zip"

  lambda_environment_variables = {
    REGION                = var.region
    DOMAINS_CONFIG        = jsonencode(var.domains)
    PEM_BUCKET_PREFIX     = var.pem_bucket_prefix
    AWS_ACCOUNT_ID        = data.aws_caller_identity.current.account_id
    ACCOUNT_KEY_PARAMETER = aws_ssm_parameter.account_key.name
    TOPIC_ARN             = var.topic_arn
    TAG_APPLICATION       = var.tag_application
    TAG_OWNER             = var.tag_owner
    DIRECTORY             = var.directory
    ACME_EMAIL            = "maeval.nightingale@gmail.com"
  }

  # Dispatcher does no certificate work — only reads config and invokes the worker.
  dispatcher_environment_variables = {
    REGION              = var.region
    DOMAINS_CONFIG      = jsonencode(var.domains)
    RENEW_FUNCTION_NAME = module.renew_certificates.function_name
  }

  # Failure handler only publishes to the alerting topic.
  failure_handler_environment_variables = {
    REGION    = var.region
    TOPIC_ARN = var.topic_arn
  }
}

# Lambda function: renew certificates
module "renew_certificates" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.8.1"

  function_name = "renew-certificates"
  zip = {
    filename = local.lambda_zip_path
    runtime  = "nodejs22.x"
    handler  = "main.renewCertificates"
    hash     = filebase64sha256("../function/bin/main.js")
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
  source = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.8.1"

  function_name = "revoke-certificate"
  zip = {
    filename = local.lambda_zip_path
    runtime  = "nodejs22.x"
    handler  = "main.revokeCertificate"
    hash     = filebase64sha256("../function/bin/main.js")
  }
  architecture           = "arm64"
  memory_size            = var.lambda_memory_size
  timeout                = var.lambda_timeout
  log_retention_in_days  = 7
  additional_policy_arns = [aws_iam_policy.lambda.arn]
  environment_variables  = local.lambda_environment_variables
}

# Lambda function: fan-out dispatcher (scheduler entry point)
module "dispatch_certificate_renewals" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.8.1"

  function_name = "dispatch-certificate-renewals"
  zip = {
    filename = local.lambda_zip_path
    runtime  = "nodejs22.x"
    handler  = "main.dispatchRenewals"
    hash     = filebase64sha256("../function/bin/main.js")
  }
  architecture           = "arm64"
  memory_size            = var.lambda_memory_size
  timeout                = var.lambda_timeout
  log_retention_in_days  = 7
  additional_policy_arns = [aws_iam_policy.dispatcher.arn]
  environment_variables  = local.dispatcher_environment_variables
}

# Lambda function: OnFailure destination for renew-certificates
module "handle_certificate_renewal_failure" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.8.1"

  function_name = "handle-certificate-renewal-failure"
  zip = {
    filename = local.lambda_zip_path
    runtime  = "nodejs22.x"
    handler  = "main.handleRenewalFailure"
    hash     = filebase64sha256("../function/bin/main.js")
  }
  architecture           = "arm64"
  memory_size            = var.lambda_memory_size
  timeout                = var.lambda_timeout
  log_retention_in_days  = 7
  additional_policy_arns = [aws_iam_policy.failure_handler.arn]
  environment_variables  = local.failure_handler_environment_variables
}

# Route renew-certificates async failures (incl. timeout/OOM) to the failure
# handler after the 2 built-in async retries are exhausted.
resource "aws_lambda_function_event_invoke_config" "renew" {
  function_name                = module.renew_certificates.function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 3600

  destination_config {
    on_failure {
      destination = module.handle_certificate_renewal_failure.function_arn
    }
  }
}

# EventBridge Scheduler trigger for certificate renewal
module "renew_certificates_scheduler" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-trigger-scheduler?ref=v1.8.1"

  function_name       = module.dispatch_certificate_renewals.function_name
  function_arn        = module.dispatch_certificate_renewals.function_arn
  schedule_name       = "renew-certificates-schedule"
  schedule_expression = var.schedule_rate
  description         = "Trigger certificate renewal dispatch"
}
