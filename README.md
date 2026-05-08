# Let's Encrypt Lambda

AWS Lambda that automates Let's Encrypt SSL/TLS certificate issuance,
renewal, and revocation for a single Route53 hosted zone via the ACME
DNS-01 challenge. Renewed certificates are imported into AWS
Certificate Manager across one primary and zero-or-more secondary
regions.

## Prerequisites

- AWS credentials in scope (env vars or AWS profile pointing at the
  target account).
- [Terraform](https://www.terraform.io/) `>= 1.10`.
- [Yarn](https://yarnpkg.com/) (any recent 1.x).

## Deploy

From the repo root:

```bash
yarn backend:deploy
```

This builds the Lambda zip (`yarn --cwd function package`, which runs
esbuild then zips `function/bin/`) and runs
`terraform -chdir=infrastructure apply -auto-approve`.

## Manual operations

### Renew

```bash
yarn renew         # Renews only if < 30 days of validity remain.
yarn renew:force   # Forces an immediate renewal regardless of validity.
```

The scheduler triggers `renew` weekly automatically; the manual
commands are for ad-hoc runs (e.g. validating a new deploy against the
staging directory by overriding the event payload).

### Revoke

Rare — typically only when a private key has been exposed.

```bash
aws lambda invoke \
  --function-name revoke-certificate \
  --cli-binary-format raw-in-base64-out \
  --payload '{"arn":"<certificate-arn>"}' \
  /dev/stdout 2>/dev/null
```

## Troubleshooting

- CloudWatch logs: log groups `/aws/lambda/renew-certificates` and
  `/aws/lambda/revoke-certificate` (retention 7 days).
- Issued-certificate lookup: <https://tools.letsdebug.net/cert-search>.

## Reference

Architecture, conventions, environment variables, and runtime flow:
see [`docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md`](docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md).
