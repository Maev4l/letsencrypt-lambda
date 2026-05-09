locals {
  # Union of all regions any domain has opted into for PEM storage.
  pem_regions = toset(flatten([for d in var.domains : d.pem_storage_regions]))
}

# ---------- PEM buckets (per-region, account-regional namespace) ----------

resource "aws_s3_bucket" "pem" {
  for_each         = local.pem_regions
  bucket           = "${var.pem_bucket_prefix}-${data.aws_caller_identity.current.account_id}-${each.value}-an"
  bucket_namespace = "account-regional"
  region           = each.value
  force_destroy    = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "pem" {
  for_each = local.pem_regions
  bucket   = aws_s3_bucket.pem[each.value].id
  region   = each.value

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "pem" {
  for_each                = local.pem_regions
  bucket                  = aws_s3_bucket.pem[each.value].id
  region                  = each.value
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "pem" {
  for_each = local.pem_regions
  bucket   = aws_s3_bucket.pem[each.value].id
  region   = each.value
  policy = templatefile("${path.module}/templates/bucket-security-policy.json.tpl", {
    bucket_arn = aws_s3_bucket.pem[each.value].arn
  })
}
