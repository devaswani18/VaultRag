locals {
  name_prefix = "${var.project}-${var.env}"

  # Merges configured development origins (localhost) with the production CloudFront domain
  all_allowed_origins = distinct(concat(var.allowed_origins, [
    "https://${aws_cloudfront_distribution.web.domain_name}"
  ]))
}
