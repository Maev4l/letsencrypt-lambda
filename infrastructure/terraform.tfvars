# Per-domain certificate configuration.
# This file is auto-loaded by Terraform (no -var-file flag needed).
domains = [
  {
    common_name         = "*.isnan.eu"
    hosted_zone_id      = "ZWC66FN0XU6P9"
    acm_regions         = ["us-east-1", "eu-central-1"]
    pem_storage_regions = []
  },
]
