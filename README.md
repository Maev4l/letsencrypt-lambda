# Let's Encrypt Lambda

AWS Lambda that automates Let's Encrypt SSL/TLS certificate issuance,
renewal, and revocation for one or more Route53 hosted zones via the
ACME DNS-01 challenge. Renewed certificates are imported into AWS
Certificate Manager across the destination regions configured per
domain.

## Renewal flow

Certificate renewal uses a fan-out dispatch architecture to give each
domain its own full Lambda timeout and retry budget:

1. **EventBridge Scheduler** triggers `dispatch-certificate-renewals`
   weekly (`rate(7 days)`).
2. **`dispatch-certificate-renewals`** reads the domain config and
   fires one async (`InvocationType: 'Event'`) invoke of
   `renew-certificates` per domain — all in parallel.
3. **`renew-certificates`** (invoked once per domain) handles the full
   ACME DNS-01 flow: checks expiry, generates a CSR, creates the
   `_acme-challenge` TXT record in Route53, obtains the certificate,
   writes PEM files to S3 (if configured), imports into ACM across the
   configured regions, and publishes a Slack notification via SNS.
4. If `renew-certificates` fails (including timeout or OOM crashes)
   after Lambda's 2 built-in async retries, the async OnFailure
   destination **`handle-certificate-renewal-failure`** fires. It
   reshapes the Lambda invocation record and publishes a last-resort
   crash alert to Slack via SNS, ensuring hard failures are never
   silently lost.

## Prerequisites

- AWS credentials in scope (env vars or AWS profile pointing at the
  target account).
- [Terraform](https://www.terraform.io/) `>= 1.10`.
- [Yarn](https://yarnpkg.com/) (any recent 1.x).

## Deploy

From the repo root:

```bash
make backend-deploy
```

This builds the Lambda zip (`yarn --cwd function package`, which runs
esbuild then zips `function/bin/`) and runs
`terraform -chdir=infrastructure apply -auto-approve`.

## Manual operations

### Renew

```bash
yarn renew         # Dispatches renewals (skips certs with >= 30 days remaining).
yarn renew:force   # Dispatches renewals, forcing immediate renewal for all domains.
```

These invoke `dispatch-certificate-renewals`, which fans out to
`renew-certificates` per domain. The scheduler triggers renewal weekly
automatically; the manual commands are for ad-hoc runs (e.g. validating
a new deploy against the staging directory by overriding the event
payload).

### Renew a single domain

For ad-hoc renewal of one specific domain (e.g., when validating a
new domain in staging without touching the others):

```bash
aws lambda invoke \
  --function-name dispatch-certificate-renewals \
  --cli-binary-format raw-in-base64-out \
  --payload '{"force":true,"common_name":"*.isnan.eu","directory":"staging"}' \
  /dev/stdout 2>/dev/null
```

The `common_name` filters to a single configured domain; `directory`
overrides the default (production / staging) for that invocation only.
The dispatcher fires a single async invoke of `renew-certificates` with
these parameters.

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

- CloudWatch logs: log groups `/aws/lambda/dispatch-certificate-renewals`,
  `/aws/lambda/renew-certificates`, `/aws/lambda/handle-certificate-renewal-failure`,
  and `/aws/lambda/revoke-certificate` (retention 7 days each).
- Issued-certificate lookup: <https://tools.letsdebug.net/cert-search>.
- If a domain renewal crashes (timeout/OOM) and the failure handler fires,
  the crash alert in Slack identifies the domain from the Lambda invocation
  record.

## Reference

Architecture, conventions, environment variables, and runtime flow:
see [`CLAUDE.md`](CLAUDE.md).
