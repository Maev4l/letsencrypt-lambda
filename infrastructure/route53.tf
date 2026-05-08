# ACME DNS challenge TXT record placeholder, one per configured domain.
# Wildcard handling: replace('*.<zone>', '*.', '') yields '<zone>', which is the
# canonical challenge target Let's Encrypt uses for wildcard certs (LE strips '*.').
resource "aws_route53_record" "acme_challenge" {
  for_each = { for d in var.domains : d.common_name => d }

  zone_id = each.value.hosted_zone_id
  name    = "_acme-challenge.${replace(each.value.common_name, "*.", "")}"
  type    = "TXT"
  ttl     = 60
  records = ["dummy"]
}
