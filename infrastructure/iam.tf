# IAM policy for Lambda functions (role managed by lambda-function module)

data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "SNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [data.aws_sns_topic.alerting.arn]
  }

  statement {
    sid    = "S3Read"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:ListBucket",
    ]
    resources = [
      aws_s3_bucket.letsencrypt.arn,
      "${aws_s3_bucket.letsencrypt.arn}/*",
    ]
  }

  statement {
    sid    = "S3Write"
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:PutObjectTagging",
    ]
    resources = ["${aws_s3_bucket.letsencrypt.arn}/*"]
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
