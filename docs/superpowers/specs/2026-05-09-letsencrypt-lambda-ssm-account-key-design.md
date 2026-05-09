---
title: letsencrypt-lambda — relocate ACME account key from S3 to SSM Parameter Store
status: ready-for-plan
audience: AI agent (primary), maintainer (secondary)
created: 2026-05-09
foundation: design.md
---

# letsencrypt-lambda — SSM account-key migration spec

Eliminate the legacy `letsencrypt-lambda-storage` S3 bucket by relocating
the ACME account key (a 1.7 KB PEM private key) to AWS Systems Manager
Parameter Store as a `SecureString`. Per-region PEM-storage buckets
(account-regional namespace) are unaffected.

A single Terraform apply destroys the S3 bucket and its companions
(force_destroy sweeps the legitimate `account-key` object plus the 5
orphan PEM files identified in the multi-domain pass), creates a new
`aws_ssm_parameter.account_key` resource, and updates the Lambda code +
IAM + env vars. The migration is **populate-before-apply** with
`terraform import` to eliminate any window where the Lambda's
auto-generate path could fire on an empty SSM parameter and abandon the
existing Let's Encrypt account.

---

## Goals

1. Remove `aws_s3_bucket.account_key` and its 3 companion resources
   (SSE config, public-access block, bucket policy).
2. Store the ACME account key in SSM Parameter Store as a
   `SecureString`, encrypted with the AWS-managed key
   `alias/aws/ssm` (no customer-managed KMS key, no extra IAM).
3. Preserve the Lambda's auto-generate-if-missing logic, now triggered
   on `ParameterNotFound` OR empty placeholder value.
4. Preserve the existing Let's Encrypt account registration —
   `*.isnan.eu` cert ARN stays preserved through the migration; old
   certs remain revocable.

## Non-goals

- Tests / CI (still accepted gap).
- `ACME_EMAIL` variable promotion (still accepted gap).
- PEM-storage relocation — per-region account-regional buckets stay.
- Customer-managed KMS key.
- Cross-account or cross-region SSM replication.
- Secrets Manager (overkill for a static, non-rotated key).

---

## 1. Code architecture

### 1.1 New module `function/src/ssm.js`

Owns the account-key load/auto-create lifecycle.

```js
import acme from 'acme-client';
import { SSMClient, GetParameterCommand, PutParameterCommand } from '@aws-sdk/client-ssm';

import { getLogger } from './logger';

const {
  REGION: region,
  ACCOUNT_KEY_PARAMETER: parameterName,
} = process.env;

const logger = getLogger('ssm');

const ssm = new SSMClient({ region });

export const loadAccountKey = async () => {
  try {
    const { Parameter } = await ssm.send(
      new GetParameterCommand({ Name: parameterName, WithDecryption: true }),
    );
    if (Parameter.Value && Parameter.Value.trim().length > 0) {
      logger.info(`Account Key loaded from SSM.`);
      return Buffer.from(Parameter.Value);
    }
    // Empty placeholder (Terraform-created with `value = " "` and ignore_changes).
    // Fall through to auto-generate path.
    logger.info(`Account Key parameter exists but is empty — generating fresh key.`);
  } catch (e) {
    if (e.name !== 'ParameterNotFound') {
      logger.error(`Failed to load account key: ${e.name}.`);
      throw e;
    }
    logger.info(`Account Key parameter not found — generating fresh key.`);
  }

  const privateKey = await acme.crypto.createPrivateKey();
  await ssm.send(
    new PutParameterCommand({
      Name: parameterName,
      Value: privateKey.toString(),
      Type: 'SecureString',
      Overwrite: true, // works for both create-new and overwrite cases
    }),
  );
  logger.info(`Account Key generated + saved to SSM.`);
  return privateKey;
};
```

Auto-generate triggers on **either** `ParameterNotFound` (truly missing
parameter) **or** present-but-empty value (Terraform's pre-created
placeholder before manual migration). `Overwrite: true` covers both
create-new and replace cases in one code path.

### 1.2 `function/src/s3.js` — drop account-key handling, keep PEM writes

**Remove:**
- The `accountKeyClient` module-scope client (no longer needed —
  `saveFullCertificate` constructs its own per-call `S3Client` for the
  target PEM-storage region).
- The `ACCOUNT_KEY_BUCKET` and `ACCOUNT_KEY_NAME` env-var reads from
  the `process.env` destructuring.
- The `loadAccountKey` export and its body.

**Keep:**
- `saveFullCertificate(commonName, region, fullCert, privateKey)` and
  all its dependencies (the `acme-client` import is still needed for
  `acme.crypto.splitPemChain` inside `saveFullCertificate`).
- Env-var reads: `PEM_BUCKET_PREFIX`, `AWS_ACCOUNT_ID`, `REGION`,
  `TAG_APPLICATION`, `TAG_OWNER`.
- `sanitizePrefix` and `pemBucketName` helpers.

### 1.3 `function/src/main.js` — single import-line change

Was:

```js
import { loadAccountKey, saveFullCertificate } from './s3';
```

Becomes:

```js
import { loadAccountKey } from './ssm';
import { saveFullCertificate } from './s3';
```

No other change. Behaviour of `renewCertificates` and
`revokeCertificate` is unchanged at the API level.

### 1.4 `function/esbuild.config.mjs` — add SSM client to externals

Append `@aws-sdk/client-ssm` to the `external` list (provided by the
Lambda Node.js 22 runtime):

```js
external: [
  '@aws-sdk/client-acm',
  '@aws-sdk/client-route-53',
  '@aws-sdk/client-s3',
  '@aws-sdk/client-sns',
  '@aws-sdk/client-ssm',
],
```

No new npm dependency in `function/package.json` — the SDK is on the
Lambda runtime. ESLint already allows `^@aws-sdk/` via
`import/no-unresolved` (no eslint config change).

---

## 2. Terraform changes

### 2.1 New file `infrastructure/ssm.tf`

```hcl
resource "aws_ssm_parameter" "account_key" {
  name        = var.account_key_parameter
  type        = "SecureString"
  value       = " " # placeholder; populated by migration step 2 before apply, or by Lambda auto-generate on fresh deploys
  description = "ACME account key (PEM) for letsencrypt-lambda"

  lifecycle {
    ignore_changes = [value]
  }
}
```

`value = " "` (single space) — chosen over empty string because some
Terraform/SSM provider versions reject empty SecureString values. The
Lambda's `Parameter.Value.trim().length > 0` guard treats it as empty.

### 2.2 `infrastructure/s3.tf` — drop account_key resources

Delete these four resources (and their bodies):

- `aws_s3_bucket.account_key`
- `aws_s3_bucket_server_side_encryption_configuration.account_key`
- `aws_s3_bucket_public_access_block.account_key`
- `aws_s3_bucket_policy.account_key`

Keep all `aws_s3_bucket.pem` resources and their companions
(unchanged — per-region account-regional namespace, used by
`saveFullCertificate`).

The `local.pem_regions` definition stays.

### 2.3 `infrastructure/iam.tf` — swap S3 statement for SSM

Replace the `S3AccountKey` statement with:

```hcl
statement {
  sid    = "SSMAccountKey"
  effect = "Allow"
  actions = [
    "ssm:GetParameter",
    "ssm:PutParameter",
  ]
  resources = [aws_ssm_parameter.account_key.arn]
}
```

No `kms:*` actions needed because SSM uses the AWS-managed key
`alias/aws/ssm`, which delegates KMS access transparently to SSM as
service principal when the caller's role has the matching SSM action.

The `S3PemWrite` dynamic statement (PEM buckets) is **unchanged** —
it's a separate concern.

`SNSPublish`, `Route53`, `ACM` statements are unchanged.

### 2.4 `infrastructure/lambda.tf` — env-var rewrite

In `local.lambda_environment_variables`:

- **Remove:** `ACCOUNT_KEY_BUCKET`, `ACCOUNT_KEY_NAME`.
- **Add:** `ACCOUNT_KEY_PARAMETER = aws_ssm_parameter.account_key.name`.

All other env vars (`REGION`, `DOMAINS_CONFIG`, `PEM_BUCKET_PREFIX`,
`AWS_ACCOUNT_ID`, `TOPIC_ARN`, `TAG_APPLICATION`, `TAG_OWNER`,
`DIRECTORY`, `ACME_EMAIL`) unchanged.

### 2.5 `infrastructure/variables.tf` — variable rewrite

- **Remove:** `var.account_key_bucket`, `var.s3_letsencrypt_account_key_name`.
- **Add:**

```hcl
variable "account_key_parameter" {
  description = "SSM Parameter Store name for the ACME account key (SecureString)."
  type        = string
  default     = "letsencrypt-lambda-account-key"
}
```

All other variables unchanged.

### 2.6 `infrastructure/outputs.tf` — cleanup

- **Remove:** `output "account_key_bucket_name"`.
- **No additions.** The new SSM parameter doesn't need an output (its
  ARN is internal Terraform plumbing only; `aws ssm get-parameter` uses
  the name, which is captured in the Lambda env var).

### 2.7 Provider version constraint

No change. The `aws_ssm_parameter` resource is supported in all AWS
provider versions ≥ 5.x; the existing `~> 6.37` constraint is fine.

---

## 3. Migration runbook (populate-before-apply)

### Why this order

The Lambda's `loadAccountKey()` auto-generates a fresh key on
empty/missing parameter. If `terraform apply` lands first (creating an
empty SSM parameter, destroying the S3 source) and a Lambda invocation
fires before manual migration, a brand-new key is generated and the
**existing Let's Encrypt account is silently abandoned** — old certs
become non-revocable from the new account.

The fix: populate SSM with the migrated key **before** Terraform
applies. `terraform import` brings the pre-created parameter under
Terraform's management without modifying its value.

### Steps

**Step 1 — Copy the existing key out of S3** (read-only)

```bash
aws s3 cp s3://letsencrypt-lambda-storage/account-key /tmp/account-key --region eu-central-1
```

**Step 2 — Push it into SSM as a SecureString**

```bash
aws ssm put-parameter \
  --name letsencrypt-lambda-account-key \
  --type SecureString \
  --value "file:///tmp/account-key" \
  --region eu-central-1
```

**Step 3 — Confirm SSM holds the value**

```bash
aws ssm get-parameter \
  --name letsencrypt-lambda-account-key \
  --with-decryption \
  --region eu-central-1 \
  --query 'Parameter.Value' --output text | head -1
# Expected output begins with: "-----BEGIN PRIVATE KEY-----" (or similar PEM header)
```

**Step 4 — Remove the unencrypted local copy**

The `/tmp/account-key` file held an unencrypted private key; delete it
once SSM is confirmed populated. Lifetime on disk: ~30 seconds across
steps 1–4.

```bash
rm /tmp/account-key
```

**Step 5 — Import the parameter into Terraform state**

```bash
terraform -chdir=infrastructure import \
  aws_ssm_parameter.account_key \
  letsencrypt-lambda-account-key
```

This binds the existing parameter to the Terraform resource so the
upcoming apply is a no-op for value (resource exists in state +
`ignore_changes = [value]`).

**Step 6 — `terraform apply`**

Single apply lands all remaining changes:
- **Destroys** the legacy S3 bucket and 3 companions
  (`force_destroy = true` sweeps the `account-key` object and the 5
  orphan PEM files in one motion).
- **Updates** `aws_iam_policy.lambda` (drops `S3AccountKey`, adds
  `SSMAccountKey`).
- **Updates** both Lambda functions: new code (rebuilt zip with the
  new `ssm.js` + slimmed-down `s3.js`), new env vars
  (`ACCOUNT_KEY_PARAMETER` added; `ACCOUNT_KEY_BUCKET` /
  `ACCOUNT_KEY_NAME` removed).
- **No-op** on `aws_ssm_parameter.account_key` for value (already in
  state with the migrated key).
- **Removes** the `account_key_bucket_name` output.

Mid-apply Lambda invocations fail with `AccessDenied` during the IAM
transition (noisy, recoverable) — they do **not** trigger silent key
abandonment because SSM is already populated.

**Step 7 — Smoke test**

```bash
# Confirm the bucket is gone
aws s3 ls s3://letsencrypt-lambda-storage/ --region eu-central-1
# Expected: NoSuchBucket error

# Confirm SSM still holds the migrated key
aws ssm get-parameter \
  --name letsencrypt-lambda-account-key \
  --with-decryption --region eu-central-1 \
  --query 'Parameter.Value' --output text | head -1
# Expected: PEM header line, same as Step 3

# End-to-end staging-directory renewal
aws lambda invoke \
  --function-name renew-certificates \
  --cli-binary-format raw-in-base64-out \
  --payload '{"force":true,"common_name":"*.isnan.eu","directory":"staging"}' \
  /dev/stdout 2>/dev/null
# Expected: SNS notification "Certificate renewed for '*.isnan.eu' (staging)."
```

The staging-directory renewal exercises the full new code path
(SSMClient → GetParameter → ACME flow → Route53 → ACM imports) without
touching the production cert.

### Risk envelope

- **Pre-step 2 / step 5 failures** are recoverable: the legacy S3 bucket
  still has the key. Re-run from step 1.
- **Failures in step 6 mid-apply** are recoverable: re-run
  `terraform apply`. The SSM parameter persists across retries.
- **Failures after step 6 succeeds:** the legacy bucket is gone but
  SSM still has the key, so the system is functional. Lambda failures
  in this state are application-level (AWS API issues, ACME issues),
  not migration-level.
- **Worst case (operator skipped step 5)**: `terraform apply` would try
  to create a new parameter that already exists, error with
  `ParameterAlreadyExists`. Recovery: run step 5 (`terraform import`)
  and re-apply. The existing SSM value is preserved.

---

## 4. Acceptance criteria

- `yarn --cwd function lint` passes.
- `yarn --cwd function package` produces a fresh `dist/lambda.zip`
  containing the new bundle (config.js + main.js + acm.js + route53.js
  + s3.js [slimmed] + sns.js + ssm.js [new] + logger.js).
- `terraform -chdir=infrastructure plan` (after migration steps 1–5
  complete) shows:
  - Lambda code update (new `source_code_hash`) for both functions.
  - Lambda env-var diff: `ACCOUNT_KEY_PARAMETER` added;
    `ACCOUNT_KEY_BUCKET` / `ACCOUNT_KEY_NAME` removed.
  - IAM policy diff: `S3AccountKey` removed; `SSMAccountKey` added.
    `S3PemWrite` (dynamic) and other statements unchanged.
  - **Destroys:** `aws_s3_bucket.account_key` and its 3 companions.
  - **No-op** on `aws_ssm_parameter.account_key`.
  - Output diff: `account_key_bucket_name` removed.
- `aws s3 ls s3://letsencrypt-lambda-storage` returns `NoSuchBucket`.
- `aws ssm get-parameter --name letsencrypt-lambda-account-key
  --with-decryption` returns the migrated PEM (key value matches the
  pre-migration S3 object byte-for-byte).
- After force-renewal against staging directory, the existing
  Let's Encrypt account URL is reused (visible in CloudWatch logs:
  `Account url for '*.isnan.eu': <url>` matches pre-migration value).
- Production `*.isnan.eu` ACM certificate ARN is preserved (compare
  before / after via `aws acm list-certificates`).

---

## 5. Manual verification (post-rollout)

1. CloudWatch logs for `renew-certificates` show
   `[ssm] info: Account Key loaded from SSM.` — NOT
   `[ssm] info: Account Key parameter not found` (the latter would
   indicate the auto-generate path fired, abandoning the LE account).
2. CloudTrail event `GetParameter` is recorded for
   `letsencrypt-lambda-account-key` with `WithDecryption=true` on each
   Lambda cold start.
3. Slack receives the staging-renewal notification.
4. Production force-renewal (when ready):
   ```bash
   aws lambda invoke \
     --function-name renew-certificates \
     --cli-binary-format raw-in-base64-out \
     --payload '{"force":true,"common_name":"*.isnan.eu","directory":"production"}' \
     /dev/stdout 2>/dev/null
   ```
   ACM cert `NotAfter` advances; ARN unchanged; consumers see no
   reconfiguration.

---

## 6. Foundation doc updates (post-implementation)

When this work commits, the foundation doc (`design.md` at repo root) needs:

- **§2 Repo layout:**
  - Add `function/src/ssm.js` to the `src/` listing.
  - Update `infrastructure/s3.tf` description (only `pem` resources
    remain; account-key resources removed).
  - Add `infrastructure/ssm.tf` to the `infrastructure/` listing.
- **§3 Runtime architecture:**
  - `loadAccountKey()` description: "from SSM Parameter Store
    (`SecureString` decrypted via `alias/aws/ssm`); auto-generates
    + `PutParameter` on `ParameterNotFound` or empty value".
- **§4 Environment variables:**
  - Replace `ACCOUNT_KEY_BUCKET` and `ACCOUNT_KEY_NAME` rows with
    `ACCOUNT_KEY_PARAMETER`.
  - Update consumer column for `loadAccountKey` from `s3.js` to
    `ssm.js`.
- **§7 Conventions:**
  - JS: add note about per-module AWS service mapping
    (`ssm.js` joins `acm.js`, `route53.js`, `s3.js`, `sns.js`).
- **Frontmatter:** bump `verified-against-commit:` to the commit SHA
  that lands this work.

---

## 7. Accepted gaps (deliberately out of scope)

- **No tests, no CI** — inherited from cleanup spec.
- **`ACME_EMAIL` hardcoded** in `infrastructure/lambda.tf` — inherited.
- **No customer-managed KMS key** — `alias/aws/ssm` (AWS-managed) is
  sufficient for a single static secret.
- **No SSM parameter versioning history utilization** — SSM keeps the
  last 100 versions automatically; we don't surface or rotate them.
- **No SSM parameter for `ACME_EMAIL`** — the existing hardcoded value
  remains in `lambda.tf` (out of scope for this change).
- **No AWS Secrets Manager alternative** — SSM SecureString chosen for
  cost ($0/mo vs $0.40/mo) and simplicity.
