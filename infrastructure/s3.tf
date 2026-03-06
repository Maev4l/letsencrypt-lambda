# S3 bucket for Let's Encrypt certificate storage
resource "aws_s3_bucket" "letsencrypt" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_server_side_encryption_configuration" "letsencrypt" {
  bucket = aws_s3_bucket.letsencrypt.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "letsencrypt" {
  bucket = aws_s3_bucket.letsencrypt.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Bucket policy enforcing encryption and secure transport
resource "aws_s3_bucket_policy" "letsencrypt" {
  bucket = aws_s3_bucket.letsencrypt.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyPublishingUnencryptedResources"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.letsencrypt.arn}/*"
        Condition = {
          Null = {
            "s3:x-amz-server-side-encryption" = "true"
          }
        }
      },
      {
        Sid       = "DenyIncorrectEncryptionHeader"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.letsencrypt.arn}/*"
        Condition = {
          "ForAllValues:StringNotEquals" = {
            "s3:x-amz-server-side-encryption" = ["AES256", "aws:kms"]
          }
        }
      },
      {
        Sid       = "DenyUnencryptedConnections"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:GetObject", "s3:PutObject"]
        Resource  = "${aws_s3_bucket.letsencrypt.arn}/*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid       = "DenyPublicReadAcl"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:PutBucketAcl", "s3:PutObject", "s3:PutObjectAcl"]
        Resource = [
          aws_s3_bucket.letsencrypt.arn,
          "${aws_s3_bucket.letsencrypt.arn}/*"
        ]
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = ["authenticated-read", "public-read", "public-read-write"]
          }
        }
      },
      {
        Sid       = "DenyGrantingPublicRead"
        Effect    = "Deny"
        Principal = "*"
        Action    = ["s3:PutBucketAcl", "s3:PutObject", "s3:PutObjectAcl"]
        Resource = [
          aws_s3_bucket.letsencrypt.arn,
          "${aws_s3_bucket.letsencrypt.arn}/*"
        ]
        Condition = {
          StringLike = {
            "s3:x-amz-grant-read" = [
              "*http://acs.amazonaws.com/groups/global/AllUsers*",
              "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"
            ]
          }
        }
      }
    ]
  })
}
