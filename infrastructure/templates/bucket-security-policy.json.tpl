{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublishingUnencryptedResources",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "${bucket_arn}/*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption": "true"
        }
      }
    },
    {
      "Sid": "DenyIncorrectEncryptionHeader",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "${bucket_arn}/*",
      "Condition": {
        "ForAllValues:StringNotEquals": {
          "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]
        }
      }
    },
    {
      "Sid": "DenyUnencryptedConnections",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "${bucket_arn}/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "DenyPublicReadAcl",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:PutBucketAcl", "s3:PutObject", "s3:PutObjectAcl"],
      "Resource": ["${bucket_arn}", "${bucket_arn}/*"],
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": ["authenticated-read", "public-read", "public-read-write"]
        }
      }
    },
    {
      "Sid": "DenyGrantingPublicRead",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:PutBucketAcl", "s3:PutObject", "s3:PutObjectAcl"],
      "Resource": ["${bucket_arn}", "${bucket_arn}/*"],
      "Condition": {
        "StringLike": {
          "s3:x-amz-grant-read": [
            "*http://acs.amazonaws.com/groups/global/AllUsers*",
            "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"
          ]
        }
      }
    }
  ]
}
