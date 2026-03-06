# ACME DNS challenge TXT record placeholder
resource "aws_route53_record" "acme_challenge" {
  zone_id = data.aws_route53_zone.main.zone_id
  name    = "_acme-challenge.${var.domain_name}"
  type    = "TXT"
  ttl     = 60
  records = ["dummy"]
}
