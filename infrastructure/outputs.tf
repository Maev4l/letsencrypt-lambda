output "lambda_renew_certificates_arn" {
  description = "ARN of the renew-certificates Lambda function"
  value       = module.renew_certificates.function_arn
}

output "lambda_revoke_certificate_arn" {
  description = "ARN of the revoke-certificate Lambda function"
  value       = module.revoke_certificate.function_arn
}

output "iam_role_arn" {
  description = "ARN of the Lambda IAM role"
  value       = module.renew_certificates.role_arn
}
