resource "aws_ssm_parameter" "account_key" {
  name        = var.account_key_parameter
  type        = "SecureString"
  value       = " " # placeholder; populated by migration step (Task 11) before apply, or by Lambda auto-generate on fresh deploys
  description = "ACME account key (PEM) for letsencrypt-lambda"

  lifecycle {
    ignore_changes = [value]
  }
}
