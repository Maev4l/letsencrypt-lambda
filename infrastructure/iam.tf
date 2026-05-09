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
}

resource "aws_iam_policy" "lambda" {
  name   = "letsencrypt-lambda"
  policy = data.aws_iam_policy_document.lambda.json
}
