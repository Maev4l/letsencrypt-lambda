# IAM policy for Lambda functions (role managed by lambda-function module)

data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "SNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [data.aws_sns_topic.alerting.arn]
  }

  statement {
    sid    = "SSMAccountKey"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:PutParameter",
    ]
    resources = [aws_ssm_parameter.account_key.arn]
  }

  # PEM buckets — write only. Emitted only when at least one domain has
  # pem_storage_regions populated (otherwise IAM rejects `resources = []`).
  dynamic "statement" {
    for_each = length(local.pem_regions) > 0 ? [1] : []
    content {
      sid    = "S3PemWrite"
      effect = "Allow"
      actions = [
        "s3:PutObject",
        "s3:PutObjectTagging",
      ]
      resources = [for b in aws_s3_bucket.pem : "${b.arn}/*"]
    }
  }

  statement {
    sid    = "Route53"
    effect = "Allow"
    actions = [
      "route53:GetChange",
      "route53:ListHostedZones",
      "route53:ListResourceRecordSets",
      "route53:ChangeResourceRecordSets",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ACM"
    effect = "Allow"
    actions = [
      "acm:ImportCertificate",
      "acm:ListCertificates",
      "acm:DescribeCertificate",
      "acm:AddTagsToCertificate",
      "acm:GetCertificate",
      "acm:ListTagsForCertificate",
    ]
    resources = ["*"]
  }

  # Lambda delivers async OnFailure records using the source function's execution
  # role, so the renew worker (which uses this shared policy) needs invoke
  # permission on the failure handler. The revoke function also gains this
  # permission — harmless, accepted for simplicity.
  statement {
    sid       = "InvokeFailureHandler"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [module.handle_certificate_renewal_failure.function_arn]
  }
}

resource "aws_iam_policy" "lambda" {
  name   = "letsencrypt-lambda"
  policy = data.aws_iam_policy_document.lambda.json
}

# Dispatcher needs only to async-invoke the renew worker — no ACME/ACM/Route53/S3/SNS.
data "aws_iam_policy_document" "dispatcher" {
  statement {
    sid       = "InvokeRenewWorker"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [module.renew_certificates.function_arn]
  }
}

resource "aws_iam_policy" "dispatcher" {
  name   = "dispatch-certificate-renewals"
  policy = data.aws_iam_policy_document.dispatcher.json
}

# Failure handler needs only to publish to the alerting topic.
data "aws_iam_policy_document" "failure_handler" {
  statement {
    sid       = "SNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [data.aws_sns_topic.alerting.arn]
  }
}

resource "aws_iam_policy" "failure_handler" {
  name   = "handle-certificate-renewal-failure"
  policy = data.aws_iam_policy_document.failure_handler.json
}
