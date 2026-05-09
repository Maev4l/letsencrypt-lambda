# letsencrypt-lambda SSM Account-Key Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate the legacy `letsencrypt-lambda-storage` S3 bucket by relocating the ACME account key to AWS Systems Manager Parameter Store as a `SecureString` (encrypted via the AWS-managed key `alias/aws/ssm`). Lambda's auto-generate-if-missing logic is preserved. The existing Let's Encrypt account registration is preserved via populate-before-apply migration with `terraform import`.

**Architecture:** A new `function/src/ssm.js` module owns `loadAccountKey()` (read from SSM, auto-generate + `PutParameter` on `ParameterNotFound` or empty placeholder). `function/src/s3.js` slims down to PEM writes only. `function/src/main.js` swaps one import line. Terraform adds `infrastructure/ssm.tf` (single `aws_ssm_parameter.account_key` resource with `lifecycle.ignore_changes = [value]`), drops the four `aws_s3_bucket.account_key` resources, swaps the IAM `S3AccountKey` statement for `SSMAccountKey`, and rewrites Lambda env vars (`ACCOUNT_KEY_BUCKET` / `ACCOUNT_KEY_NAME` → `ACCOUNT_KEY_PARAMETER`). Provider version unchanged at `~> 6.37`.

**Tech Stack:** Node.js 22 (ESM, esbuild → CJS), `acme-client@5.3.0`, AWS SDK v3 (provided by Lambda runtime; adds `@aws-sdk/client-ssm` to externals — no new npm dep), Terraform `~> 6.37` AWS provider. No tests / no CI (accepted gap).

> **Repo conventions (from prior session work):**
> - User's global rule forbids auto-commit and auto-push. The user has explicitly chosen "no commits, no staging" for prior plan executions in this session — implementer subagents apply edits + run lint/grep/fmt verifications, then **stop without `git add` / `git commit`**. The user picks what to commit.
> - Lambda is zip-based (esbuild → CJS → zip); the global CLAUDE.md "Docker based AWS lambdas" rules do NOT apply here.
> - **CRITICAL:** This plan has a hard halt point at Task 11 — the manual migration commands (S3 read, SSM write, `terraform import`) **must be run by the user**. Implementer/reviewer subagents must NOT run them; they touch live AWS and read an unencrypted private key out of S3.

> **Spec:** [`docs/superpowers/specs/2026-05-09-letsencrypt-lambda-ssm-account-key-design.md`](../specs/2026-05-09-letsencrypt-lambda-ssm-account-key-design.md)
> **Foundation reference:** [`docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md`](../specs/2026-05-08-letsencrypt-lambda-foundation.md)

---

## File structure

| Path | Action | Responsibility |
| --- | --- | --- |
| `function/src/ssm.js` | **Create** | `loadAccountKey()` — reads/auto-generates the ACME account key in SSM Parameter Store. |
| `function/src/s3.js` | Modify | Drop `loadAccountKey`, `accountKeyClient`, and `ACCOUNT_KEY_BUCKET` / `ACCOUNT_KEY_NAME` env-var reads. Keep `saveFullCertificate` and its dependencies. |
| `function/src/main.js` | Modify | Swap one import line: `loadAccountKey` now imported from `./ssm`. |
| `function/esbuild.config.mjs` | Modify | Add `@aws-sdk/client-ssm` to the `external` list. |
| `infrastructure/ssm.tf` | **Create** | Single `aws_ssm_parameter.account_key` resource with `lifecycle.ignore_changes = [value]`. |
| `infrastructure/s3.tf` | Modify | Remove the four `account_key` resources (bucket, SSE config, public-access block, bucket policy). Keep all `pem` resources. |
| `infrastructure/iam.tf` | Modify | Replace `S3AccountKey` statement with `SSMAccountKey` statement. SNS / Route53 / ACM / `S3PemWrite` unchanged. |
| `infrastructure/lambda.tf` | Modify | In `local.lambda_environment_variables`: remove `ACCOUNT_KEY_BUCKET` and `ACCOUNT_KEY_NAME`; add `ACCOUNT_KEY_PARAMETER`. |
| `infrastructure/variables.tf` | Modify | Remove `var.account_key_bucket` and `var.s3_letsencrypt_account_key_name`. Add `var.account_key_parameter`. |
| `infrastructure/outputs.tf` | Modify | Remove `account_key_bucket_name` output. |
| `docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md` | Modify | Reflect the SSM relocation in §2 (repo layout: add `ssm.js`, `ssm.tf`; update `s3.tf` description), §3 (runtime architecture: `loadAccountKey()` source), §4 (env-var table: replace `ACCOUNT_KEY_BUCKET`/`NAME` with `ACCOUNT_KEY_PARAMETER`). |

All file edits in Tasks 1–9 are independent and can run in any order. Tasks 10–13 are sequenced:

- Task 10: build + lint verification (read-only — no apply, no migration commands).
- Task 11: **HALT for user-driven migration** (S3 cp → SSM put-parameter → verify → rm /tmp → terraform import). User runs these themselves.
- Task 12: terraform plan inspection (only after user confirms Task 11 complete).
- Task 13: final overall code review (optional; user choice).

---

## Task 1: Create `function/src/ssm.js`

**Files:**
- Create: `function/src/ssm.js`

- [ ] **Step 1: Create the file with exact contents**

```javascript
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
      Overwrite: true,
    }),
  );
  logger.info(`Account Key generated + saved to SSM.`);
  return privateKey;
};
```

- [ ] **Step 2: Lint the function package**

```bash
yarn --cwd function lint
```

Expected: exits 0, no warnings. ESLint already exempts `^@aws-sdk/` from `import/no-unresolved`, so the new SSM client import resolves cleanly without bundling.

- [ ] **Step 3: Confirm file is untracked (no commits, no staging)**

```bash
git status --short function/src/ssm.js
```

Expected: `?? function/src/ssm.js` (untracked).

---

## Task 2: Slim `function/src/s3.js` to PEM writes only

**Files:**
- Modify: `function/src/s3.js` (full rewrite — narrower scope)

- [ ] **Step 1: Replace the file with the new contents**

```javascript
import acme from 'acme-client';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

import { getLogger } from './logger';

const {
  PEM_BUCKET_PREFIX: pemBucketPrefix,
  AWS_ACCOUNT_ID: awsAccountId,
  TAG_APPLICATION: tagApplication,
  TAG_OWNER: tagOwner,
} = process.env;

const logger = getLogger('s3');

// Sanitize common name for use as S3 key prefix: '*' is not allowed in keys, replace with '_'.
const sanitizePrefix = (commonName) => commonName.replace('*', '_');

// Per-region PEM bucket naming convention: '<prefix>-<accountId>-<region>-an' (account-regional namespace).
const pemBucketName = (targetRegion) => `${pemBucketPrefix}-${awsAccountId}-${targetRegion}-an`;

export const saveFullCertificate = async (commonName, targetRegion, fullCertificate, certificatePrivateKey) => {
  const bucket = pemBucketName(targetRegion);
  const prefix = sanitizePrefix(commonName);
  const s3 = new S3Client({ region: targetRegion });

  const saveObject = async (name, content) => {
    await s3.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: `${prefix}/${name}`,
        Body: content,
        ServerSideEncryption: 'AES256',
        Tagging: `application=${tagApplication}&owner=${tagOwner}`,
      }),
    );
  };

  const [certificate, intermediate, root] = acme.crypto.splitPemChain(fullCertificate);
  await Promise.all([
    saveObject('full', fullCertificate),
    saveObject('certificate', certificate),
    saveObject('intermediate', intermediate),
    saveObject('root', root),
    saveObject('certificateKey', certificatePrivateKey),
  ]);

  logger.info(`PEM saved for ${commonName} in ${targetRegion} (s3://${bucket}/${prefix}/).`);
};
```

Removed (vs. previous file):
- `GetObjectCommand` import (no longer needed without `loadAccountKey`).
- `REGION`, `ACCOUNT_KEY_BUCKET`, `ACCOUNT_KEY_NAME` env-var reads.
- The module-scope `accountKeyClient`.
- The `loadAccountKey` function and its `acme.crypto.createPrivateKey` auto-create path.

Kept:
- The `acme` import (still used by `saveFullCertificate` for `splitPemChain`).
- `PutObjectCommand` import.
- `sanitizePrefix` and `pemBucketName` helpers.
- The `saveFullCertificate` function (signature unchanged).

- [ ] **Step 2: Verify the legacy account-key references are gone**

```bash
cd /Users/jrsue/dev/repos/letsencrypt-lambda
grep -nE 'loadAccountKey|accountKeyClient|ACCOUNT_KEY_BUCKET|ACCOUNT_KEY_NAME|GetObjectCommand' function/src/s3.js
```

Expected: empty result (no matches).

- [ ] **Step 3: Verify `saveFullCertificate` is still exported**

```bash
grep -n 'export const saveFullCertificate' function/src/s3.js
```

Expected: exactly one match.

- [ ] **Step 4: Lint**

```bash
yarn --cwd function lint
```

Expected: exits 0.

- [ ] **Step 5: Confirm file shows as modified (unstaged)**

```bash
git status --short function/src/s3.js
```

Expected: ` M function/src/s3.js`.

---

## Task 3: Update `function/src/main.js` import + `function/esbuild.config.mjs` externals

**Files:**
- Modify: `function/src/main.js` (one import line change)
- Modify: `function/esbuild.config.mjs` (one entry added to `external` list)

- [ ] **Step 1: Update the import in `function/src/main.js`**

Find the existing line:

```javascript
import { loadAccountKey, saveFullCertificate } from './s3';
```

Replace it with TWO lines:

```javascript
import { loadAccountKey } from './ssm';
import { saveFullCertificate } from './s3';
```

No other change to `main.js`.

- [ ] **Step 2: Update `function/esbuild.config.mjs` externals**

Find the existing block:

```javascript
external: [
  '@aws-sdk/client-acm',
  '@aws-sdk/client-route-53',
  '@aws-sdk/client-s3',
  '@aws-sdk/client-sns',
],
```

Replace with:

```javascript
external: [
  '@aws-sdk/client-acm',
  '@aws-sdk/client-route-53',
  '@aws-sdk/client-s3',
  '@aws-sdk/client-sns',
  '@aws-sdk/client-ssm',
],
```

- [ ] **Step 3: Verify the import line in main.js**

```bash
cd /Users/jrsue/dev/repos/letsencrypt-lambda
grep -n "from './ssm'" function/src/main.js
```

Expected: exactly one match — the `loadAccountKey` import.

```bash
grep -n "loadAccountKey, saveFullCertificate" function/src/main.js
```

Expected: empty (the old combined import is gone).

- [ ] **Step 4: Verify the esbuild externals**

```bash
grep "@aws-sdk/client-ssm" function/esbuild.config.mjs
```

Expected: exactly one match.

- [ ] **Step 5: Lint**

```bash
yarn --cwd function lint
```

Expected: exits 0. (Tasks 1, 2, 3 must all be complete for this lint to pass — the new `./ssm` resolves to `function/src/ssm.js` from Task 1.)

- [ ] **Step 6: Confirm both files modified, unstaged**

```bash
git status --short function/src/main.js function/esbuild.config.mjs
```

Expected: ` M function/src/main.js` and ` M function/esbuild.config.mjs`.

---

## Task 4: Create `infrastructure/ssm.tf`

**Files:**
- Create: `infrastructure/ssm.tf`

- [ ] **Step 1: Create the file with exact contents**

```hcl
resource "aws_ssm_parameter" "account_key" {
  name        = var.account_key_parameter
  type        = "SecureString"
  value       = " " # placeholder; populated by migration step (Task 11) before apply, or by Lambda auto-generate on fresh deploys
  description = "ACME account key (PEM) for letsencrypt-lambda"

  lifecycle {
    ignore_changes = [value]
  }
}
```

- [ ] **Step 2: Format check**

```bash
cd /Users/jrsue/dev/repos/letsencrypt-lambda
terraform -chdir=infrastructure fmt -check
```

Expected: exits 0. If diff, run `terraform -chdir=infrastructure fmt` (without `-check`) to auto-format.

- [ ] **Step 3: Confirm file is untracked**

```bash
git status --short infrastructure/ssm.tf
```

Expected: `?? infrastructure/ssm.tf`.

---

## Task 5: Update `infrastructure/iam.tf` — swap S3 statement for SSM

**Files:**
- Modify: `infrastructure/iam.tf`

The legacy `S3AccountKey` statement (read+write on the account-key S3 bucket) is replaced by `SSMAccountKey` (read+write on the new SSM parameter ARN). The `S3PemWrite` dynamic block, `SNSPublish`, `Route53`, `ACM` statements are unchanged.

- [ ] **Step 1: Replace the file with the new contents**

Overwrite `infrastructure/iam.tf` with exactly:

```hcl
# IAM policy for Lambda functions (role managed by lambda-function module)

data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "SNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [data.aws_sns_topic.alerting.arn]
  }

  statement {
    sid    = "SSMAccountKey"
    effect = "Allow"
    actions = [
      "ssm:GetParameter",
      "ssm:PutParameter",
    ]
    resources = [aws_ssm_parameter.account_key.arn]
  }

  # PEM buckets — write only. Emitted only when at least one domain has
  # pem_storage_regions populated (otherwise IAM rejects `resources = []`).
  dynamic "statement" {
    for_each = length(local.pem_regions) > 0 ? [1] : []
    content {
      sid    = "S3PemWrite"
      effect = "Allow"
      actions = [
        "s3:PutObject",
        "s3:PutObjectTagging",
      ]
      resources = [for b in aws_s3_bucket.pem : "${b.arn}/*"]
    }
  }

  statement {
    sid    = "Route53"
    effect = "Allow"
    actions = [
      "route53:GetChange",
      "route53:ListHostedZones",
      "route53:ListResourceRecordSets",
      "route53:ChangeResourceRecordSets",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "ACM"
    effect = "Allow"
    actions = [
      "acm:ImportCertificate",
      "acm:ListCertificates",
      "acm:DescribeCertificate",
      "acm:AddTagsToCertificate",
      "acm:GetCertificate",
      "acm:ListTagsForCertificate",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "lambda" {
  name   = "letsencrypt-lambda"
  policy = data.aws_iam_policy_document.lambda.json
}
```

- [ ] **Step 2: Verify the legacy S3AccountKey is gone**

```bash
cd /Users/jrsue/dev/repos/letsencrypt-lambda
grep -nE 'S3AccountKey|aws_s3_bucket\.account_key' infrastructure/iam.tf
```

Expected: empty (no matches).

- [ ] **Step 3: Verify the new SSMAccountKey is present**

```bash
grep -n 'SSMAccountKey' infrastructure/iam.tf
```

Expected: exactly one match.

- [ ] **Step 4: Format check**

```bash
terraform -chdir=infrastructure fmt -check
```

Expected: exits 0. If diff, run `terraform -chdir=infrastructure fmt`.

- [ ] **Step 5: Confirm file modified, unstaged**

```bash
git status --short infrastructure/iam.tf
```

Expected: ` M infrastructure/iam.tf`.

---

## Task 6: Update `infrastructure/lambda.tf` — env-var rewrite

**Files:**
- Modify: `infrastructure/lambda.tf`

In `local.lambda_environment_variables`, remove `ACCOUNT_KEY_BUCKET` and `ACCOUNT_KEY_NAME`; add `ACCOUNT_KEY_PARAMETER`. All other env vars and module configurations are unchanged.

- [ ] **Step 1: Replace the file with the new contents**

Overwrite `infrastructure/lambda.tf` with exactly:

```hcl
# Pre-built zip from function/dist/lambda.zip (run: cd function && yarn build && yarn package)
locals {
  lambda_zip_path = "${path.module}/../function/dist/lambda.zip"

  lambda_environment_variables = {
    REGION                = var.region
    DOMAINS_CONFIG        = jsonencode(var.domains)
    PEM_BUCKET_PREFIX     = var.pem_bucket_prefix
    AWS_ACCOUNT_ID        = data.aws_caller_identity.current.account_id
    ACCOUNT_KEY_PARAMETER = aws_ssm_parameter.account_key.name
    TOPIC_ARN             = var.topic_arn
    TAG_APPLICATION       = var.tag_application
    TAG_OWNER             = var.tag_owner
    DIRECTORY             = var.directory
    ACME_EMAIL            = "maeval.nightingale@gmail.com"
  }
}

# Lambda function: renew certificates
module "renew_certificates" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.6.0"

  function_name = "renew-certificates"
  zip = {
    filename = local.lambda_zip_path
    runtime  = "nodejs22.x"
    handler  = "main.renewCertificates"
    hash     = filebase64sha256("../function/bin/main.js")
  }
  architecture           = "arm64"
  memory_size            = var.lambda_memory_size
  timeout                = var.lambda_timeout
  log_retention_in_days  = 7
  additional_policy_arns = [aws_iam_policy.lambda.arn]
  environment_variables  = local.lambda_environment_variables
}

# Lambda function: revoke certificate
module "revoke_certificate" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.6.0"

  function_name = "revoke-certificate"
  zip = {
    filename = local.lambda_zip_path
    runtime  = "nodejs22.x"
    handler  = "main.revokeCertificate"
    hash     = filebase64sha256("../function/bin/main.js")
  }
  architecture           = "arm64"
  memory_size            = var.lambda_memory_size
  timeout                = var.lambda_timeout
  log_retention_in_days  = 7
  additional_policy_arns = [aws_iam_policy.lambda.arn]
  environment_variables  = local.lambda_environment_variables
}

# EventBridge Scheduler trigger for certificate renewal
module "renew_certificates_scheduler" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-trigger-scheduler?ref=v1.6.0"

  function_name       = module.renew_certificates.function_name
  function_arn        = module.renew_certificates.function_arn
  schedule_name       = "renew-certificates-schedule"
  schedule_expression = var.schedule_rate
  description         = "Trigger certificate renewal"
}
```

- [ ] **Step 2: Verify the legacy env-var keys are gone from the locals block**

```bash
cd /Users/jrsue/dev/repos/letsencrypt-lambda
grep -nE '^\s*(ACCOUNT_KEY_BUCKET|ACCOUNT_KEY_NAME)\s*=' infrastructure/lambda.tf
```

Expected: empty (no matches).

- [ ] **Step 3: Verify the new env-var key is present**

```bash
grep -n 'ACCOUNT_KEY_PARAMETER' infrastructure/lambda.tf
```

Expected: exactly one match.

- [ ] **Step 4: Format check**

```bash
terraform -chdir=infrastructure fmt -check
```

Expected: exits 0. If diff, run `terraform -chdir=infrastructure fmt`.

- [ ] **Step 5: Confirm file modified, unstaged**

```bash
git status --short infrastructure/lambda.tf
```

Expected: ` M infrastructure/lambda.tf`.

---

## Task 7: Update `infrastructure/variables.tf` + `infrastructure/outputs.tf`

**Files:**
- Modify: `infrastructure/variables.tf`
- Modify: `infrastructure/outputs.tf`

Two small files — combined into one task because the changes are tightly coupled (drop S3-bucket variable + drop S3-bucket output; add SSM-parameter variable).

- [ ] **Step 1: Replace `infrastructure/variables.tf` with the new contents**

Overwrite `infrastructure/variables.tf` with exactly:

```hcl
variable "region" {
  description = "AWS region for the deployment (Lambda + Route53 client)."
  type        = string
  default     = "eu-central-1"
}

variable "domains" {
  description = "Per-domain certificate configuration. Each entry produces one cert."
  type = list(object({
    common_name         = string
    hosted_zone_id      = string
    acm_regions         = list(string)              # primary first, then secondaries
    pem_storage_regions = optional(list(string), []) # empty = no PEM storage
  }))

  # Default preserves the existing single-domain deployment.
  default = [
    {
      common_name         = "*.isnan.eu"
      hosted_zone_id      = "ZWC66FN0XU6P9"
      acm_regions         = ["us-east-1", "eu-central-1"]
      pem_storage_regions = []
    },
  ]
}

variable "pem_bucket_prefix" {
  description = "Prefix for per-region PEM buckets in the account-regional namespace. Final bucket name: '<prefix>-<accountId>-<region>-an'."
  type        = string
  default     = "letsencrypt-pems"
}

variable "account_key_parameter" {
  description = "SSM Parameter Store name for the ACME account key (SecureString)."
  type        = string
  default     = "letsencrypt-lambda-account-key"
}

variable "topic_arn" {
  description = "SNS topic ARN for alerting."
  type        = string
  default     = "arn:aws:sns:eu-central-1:671123374425:alerting-events"
}

variable "tag_application" {
  description = "Application tag value."
  type        = string
  default     = "letsencrypt-lambda"
}

variable "tag_owner" {
  description = "Owner tag value."
  type        = string
  default     = "terraform"
}

variable "directory" {
  description = "Let's Encrypt directory (production or staging) — runtime default; per-invocation override via event payload."
  type        = string
  default     = "production"
}

variable "lambda_memory_size" {
  description = "Lambda function memory size in MB."
  type        = number
  default     = 128
}

variable "lambda_timeout" {
  description = "Lambda function timeout in seconds."
  type        = number
  default     = 180
}

variable "schedule_rate" {
  description = "Schedule rate for certificate renewal."
  type        = string
  default     = "rate(7 days)"
}
```

Removed (vs. previous): `variable "account_key_bucket"` and `variable "s3_letsencrypt_account_key_name"`.
Added: `variable "account_key_parameter"`.
The `region` description was minorly tightened (drops "+ account-key bucket" since that bucket is going away).

- [ ] **Step 2: Replace `infrastructure/outputs.tf` with the new contents**

Overwrite `infrastructure/outputs.tf` with exactly:

```hcl
output "lambda_renew_certificates_arn" {
  description = "ARN of the renew-certificates Lambda function"
  value       = module.renew_certificates.function_arn
}

output "lambda_revoke_certificate_arn" {
  description = "ARN of the revoke-certificate Lambda function"
  value       = module.revoke_certificate.function_arn
}

output "iam_role_arn" {
  description = "ARN of the Lambda IAM role"
  value       = module.renew_certificates.role_arn
}
```

Removed (vs. previous): `output "account_key_bucket_name"`.
The new SSM parameter doesn't get an output — its name is captured in the Lambda env var; no consumers need it externally.

- [ ] **Step 3: Verify legacy variables are gone**

```bash
cd /Users/jrsue/dev/repos/letsencrypt-lambda
grep -nE 'variable "account_key_bucket"|variable "s3_letsencrypt_account_key_name"' infrastructure/variables.tf
```

Expected: empty.

- [ ] **Step 4: Verify legacy output is gone**

```bash
grep -n 'account_key_bucket_name' infrastructure/outputs.tf
```

Expected: empty.

- [ ] **Step 5: Format check both files**

```bash
terraform -chdir=infrastructure fmt -check
```

Expected: exits 0. If diff, run `terraform -chdir=infrastructure fmt`.

- [ ] **Step 6: Confirm both files modified, unstaged**

```bash
git status --short infrastructure/variables.tf infrastructure/outputs.tf
```

Expected: ` M infrastructure/variables.tf` and ` M infrastructure/outputs.tf`.

---

## Task 8: Update `infrastructure/s3.tf` — drop account_key resources, keep PEM resources

**Files:**
- Modify: `infrastructure/s3.tf`

Remove the four `account_key`-named resources entirely. The `pem` resources (per-region account-regional namespace, used by `saveFullCertificate`) are unchanged.

- [ ] **Step 1: Replace the file with the new contents**

Overwrite `infrastructure/s3.tf` with exactly:

```hcl
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
```

Removed (vs. previous): the four `account_key` resource blocks (`aws_s3_bucket.account_key`, `aws_s3_bucket_server_side_encryption_configuration.account_key`, `aws_s3_bucket_public_access_block.account_key`, `aws_s3_bucket_policy.account_key`).

Kept: `local.pem_regions` definition and all four `pem` resources (unchanged).

- [ ] **Step 2: Verify all `account_key` references are gone**

```bash
cd /Users/jrsue/dev/repos/letsencrypt-lambda
grep -nE 'account_key' infrastructure/s3.tf
```

Expected: empty.

- [ ] **Step 3: Verify all `pem` resources retained**

```bash
grep -cE '^resource "aws_s3_bucket(\b|_)' infrastructure/s3.tf
```

Expected: `4` (one bucket + three companion resource types, all with `pem` suffix).

- [ ] **Step 4: Format check**

```bash
terraform -chdir=infrastructure fmt -check
```

Expected: exits 0. If diff, run `terraform -chdir=infrastructure fmt`.

- [ ] **Step 5: Confirm file modified, unstaged**

```bash
git status --short infrastructure/s3.tf
```

Expected: ` M infrastructure/s3.tf`.

---

## Task 9: Update foundation doc

**Files:**
- Modify: `docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md`

Three sub-edits to keep the foundation doc accurate after this work. The `verified-against-commit:` frontmatter line is left UNTOUCHED — it bumps when the user actually commits this work.

### Sub-edit 1: §2 Repo layout — add `ssm.js` to `function/src/` listing

In §2's directory tree, find this exact line:

```
│   │   ├── config.js              loadDomains() — parse + validate DOMAINS_CONFIG on cold start.
```

Use Edit to replace it with these TWO lines (original preserved + new line added immediately after):

```
│   │   ├── config.js              loadDomains() — parse + validate DOMAINS_CONFIG on cold start.
│   │   ├── ssm.js                 loadAccountKey() — read/auto-generate ACME account key in SSM Parameter Store.
```

### Sub-edit 2: §2 Repo layout — update `s3.tf` description and add `ssm.tf` entry

In §2's directory tree, find this exact line:

```
    ├── s3.tf                      Account-key bucket (legacy global namespace) + per-region PEM buckets (account-regional namespace) via for_each over var.domains.
```

Use Edit to replace it with these TWO lines:

```
    ├── s3.tf                      Per-region PEM buckets (account-regional namespace) via for_each over var.domains.
    ├── ssm.tf                     aws_ssm_parameter.account_key — SecureString holding the ACME account key (encrypted via alias/aws/ssm).
```

### Sub-edit 3: §3 Runtime architecture — update step 4.i (account-key load)

In §3 (Runtime architecture), find the existing line about loadAccountKey in the `renewCertificates` flow:

```
   1. `loadAccountKey()` from `s3://BUCKET_NAME/S3_LETSENCRYPT_ACCOUNT_KEY_NAME`;
      auto-generate via `acme.crypto.createPrivateKey()` and persist (SSE-AES256, tagged) if `NoSuchKey`.
```

Use Edit to replace it with:

```
   1. `loadAccountKey()` from SSM Parameter Store (parameter name from `ACCOUNT_KEY_PARAMETER` env var; SecureString decrypted via `alias/aws/ssm`); auto-generate via `acme.crypto.createPrivateKey()` and persist via `PutParameter` if `ParameterNotFound` or empty value.
```

### Sub-edit 4: §3 Runtime architecture — update §3 `revokeCertificate` flow line 2

(NB: the multi-domain spec implementation already changed `loadAccountKey()` from S3 reads to abstract loads; this sub-edit reflects the SSM source explicitly.)

In §3 (Runtime architecture), find the existing line in the `revokeCertificate` flow:

```
2. `loadAccountKey()` from S3.
```

Use Edit to replace it with:

```
2. `loadAccountKey()` from SSM (same module as renew flow).
```

### Sub-edit 5: §4 Environment variables — replace ACCOUNT_KEY_BUCKET / ACCOUNT_KEY_NAME rows with ACCOUNT_KEY_PARAMETER

In §4's table, find this two-row block:

```
| `ACCOUNT_KEY_BUCKET`  | `var.account_key_bucket`                              | `s3.js`                         | `letsencrypt-lambda-storage`                            |
| `ACCOUNT_KEY_NAME`    | `var.s3_letsencrypt_account_key_name`                 | `s3.js`                         | `account-key`                                           |
```

Use Edit to replace it with this single row:

```
| `ACCOUNT_KEY_PARAMETER` | `var.account_key_parameter` (or `aws_ssm_parameter.account_key.name`) | `ssm.js`                        | `letsencrypt-lambda-account-key`                        |
```

### Sub-edit 6: §4 Notes block — add SSM-related note

In §4's Notes block, find this exact existing line:

```
- `event.common_name` (renew event) filters to a single configured domain; absent / empty = process all.
```

Use Edit to insert a new bullet IMMEDIATELY AFTER it (preserving the existing line + adding the new one below):

```
- `event.common_name` (renew event) filters to a single configured domain; absent / empty = process all.
- `ACCOUNT_KEY_PARAMETER` resolves to the SSM parameter ARN inside `ssm.js`. Lambda has `ssm:GetParameter` + `ssm:PutParameter` on that ARN; the `PutParameter` permission supports the auto-generate path and is invoked only on `ParameterNotFound` or empty placeholder.
```

### Final verification (after all 6 sub-edits)

- [ ] **Step 1: Apply each sub-edit using the Edit tool**

Apply sub-edits 1 through 6 in order. For each, use the Edit tool's old_string / new_string mechanism with the exact strings above.

- [ ] **Step 2: Verify all sub-edits landed via grep counts**

```bash
cd /Users/jrsue/dev/repos/letsencrypt-lambda
grep -c "ssm.js" docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md
grep -c "ssm.tf" docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md
grep -c "ACCOUNT_KEY_PARAMETER" docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md
grep -c "alias/aws/ssm" docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md
grep -c "ParameterNotFound" docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md
grep -c "ACCOUNT_KEY_BUCKET\b" docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md
```

Expected:
- `ssm.js` ≥ 2 (repo layout + env-var consumer + flow steps)
- `ssm.tf` ≥ 1 (repo layout)
- `ACCOUNT_KEY_PARAMETER` ≥ 2 (env-var table row + Notes block bullet)
- `alias/aws/ssm` ≥ 1 (flow step)
- `ParameterNotFound` ≥ 1 (flow step)
- `ACCOUNT_KEY_BUCKET\b` = 0 (legacy env var fully removed; the `\b` word boundary excludes `ACCOUNT_KEY_BUCKET_NAME` etc.)

- [ ] **Step 3: Confirm file modified, unstaged**

```bash
git status --short docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md
```

Expected: ` M docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md`.

---

## Task 10: Build + lint verification (read-only — no migration, no plan)

This task verifies the JS package builds cleanly and Terraform code parses. It does NOT run `terraform plan` (that requires the migration to be done first — see Task 11) and does NOT touch any AWS API.

- [ ] **Step 1: Lint the function package**

```bash
yarn --cwd function lint
```

Expected: exits 0, no warnings.

- [ ] **Step 2: Build + package the Lambda zip**

```bash
yarn --cwd function package
```

Expected: produces `function/bin/main.js` (esbuild bundle including the new `ssm.js`) and `function/dist/lambda.zip`.

- [ ] **Step 3: Confirm the bundle includes the new SSM client (as an external reference)**

```bash
grep -c '@aws-sdk/client-ssm' function/bin/main.js
```

Expected: ≥ 1 (the bundled JS imports SSM client by name; runtime resolves at execution).

- [ ] **Step 4: Terraform fmt + validate (no plan)**

```bash
terraform -chdir=infrastructure fmt -check
terraform -chdir=infrastructure init -input=false -upgrade=false
terraform -chdir=infrastructure validate
```

Expected: `fmt` exits 0, `init` succeeds (no provider download needed), `validate` reports `Success! The configuration is valid.`

- [ ] **Step 5: Confirm working tree state**

```bash
git status --short
```

Expected to show all the changes from Tasks 1–9:
- `?? function/src/ssm.js` (untracked, from Task 1)
- ` M function/src/s3.js` (modified, Task 2)
- ` M function/src/main.js` (modified, Task 3)
- ` M function/esbuild.config.mjs` (modified, Task 3)
- `?? infrastructure/ssm.tf` (untracked, Task 4)
- ` M infrastructure/iam.tf` (modified, Task 5)
- ` M infrastructure/lambda.tf` (modified, Task 6)
- ` M infrastructure/variables.tf` (modified, Task 7)
- ` M infrastructure/outputs.tf` (modified, Task 7)
- ` M infrastructure/s3.tf` (modified, Task 8)
- ` M docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md` (modified, Task 9)

- [ ] **Step 6: HALT for user review of all working-tree changes**

Surface to the user:
- The list of staged/unstaged/untracked files.
- The lint + build pass.
- An explicit reminder: **do NOT run `terraform plan` yet** — the Lambda's auto-generate path would write a fresh key into an empty SSM parameter, abandoning the LE account. The next step (Task 11) is the user-driven migration.

---

## Task 11: USER-DRIVEN MIGRATION (manual — do NOT run from a subagent)

> **CRITICAL HALT POINT.** This task involves reading an unencrypted private key out of S3 to a local file, writing it to SSM, and importing into Terraform state. These commands must be run by the **human user**, NOT an implementer subagent. The migration touches live AWS state in unrecoverable ways if mis-ordered.
>
> An automated executor (subagent or `executing-plans`) reaching this task MUST:
> 1. Surface the commands below to the user.
> 2. STOP and wait for the user to confirm completion of each step.
> 3. NOT proceed to Task 12 until the user explicitly says the migration is done.

**Files (read by user; not modified by the plan):**
- Reads: `s3://letsencrypt-lambda-storage/account-key`.
- Writes: SSM parameter `letsencrypt-lambda-account-key` (creates new SecureString).
- Writes: Terraform remote state in `s3://global-tf-states/letsencrypt-lambda/terraform.tfstate` (via `terraform import`).
- Writes + deletes: `/tmp/account-key` (local unencrypted PEM, lifetime ~30 seconds).

### Step 1 — Copy the existing key out of S3

User runs:

```bash
aws s3 cp s3://letsencrypt-lambda-storage/account-key /tmp/account-key --region eu-central-1
```

Expected: `download: s3://...` line, then `/tmp/account-key` contains the PEM.

### Step 2 — Push it into SSM as a SecureString

User runs:

```bash
aws ssm put-parameter \
  --name letsencrypt-lambda-account-key \
  --type SecureString \
  --value "file:///tmp/account-key" \
  --region eu-central-1
```

Expected: JSON response with `Version: 1` and `Tier: "Standard"`.

### Step 3 — Confirm SSM holds the value

User runs:

```bash
aws ssm get-parameter \
  --name letsencrypt-lambda-account-key \
  --with-decryption \
  --region eu-central-1 \
  --query 'Parameter.Value' --output text | head -1
```

Expected: a line beginning `-----BEGIN PRIVATE KEY-----` (or `-----BEGIN RSA PRIVATE KEY-----` depending on OpenSSL/acme-client version).

### Step 4 — Remove the unencrypted local copy

User runs:

```bash
rm /tmp/account-key
```

Expected: silent success. The key now lives only in SSM (encrypted) and Terraform state.

### Step 5 — Import the parameter into Terraform state

User runs:

```bash
terraform -chdir=infrastructure import \
  aws_ssm_parameter.account_key \
  letsencrypt-lambda-account-key
```

Expected: `Import successful! The resources that were imported are shown above.`

### Step 6 — Confirm import succeeded

User runs:

```bash
terraform -chdir=infrastructure state show aws_ssm_parameter.account_key | head -10
```

Expected: shows the parameter's `id`, `name = "letsencrypt-lambda-account-key"`, `type = "SecureString"`. The `value` may be redacted in state output (Terraform marks SecureString values as sensitive).

- [ ] **Step 7: User confirms migration complete before plan runs**

After steps 1–6 succeed, the user explicitly says "migration done" or equivalent. Only then does the executor proceed to Task 12.

---

## Task 12: Terraform plan inspection (HALT for user review; no apply)

This task runs `terraform plan` to surface the diff. It does NOT run `terraform apply` — the user applies manually after reviewing the plan.

- [ ] **Step 1: Run `terraform plan`**

```bash
terraform -chdir=infrastructure plan -no-color -out=/tmp/letsencrypt-ssm-migration.tfplan
```

- [ ] **Step 2: Show the plan output to the user**

```bash
terraform -chdir=infrastructure show -no-color /tmp/letsencrypt-ssm-migration.tfplan | tail -100
```

Expected diff content (specifics will vary slightly with environment drift):

- **Destroys (4 resources):** `aws_s3_bucket.account_key`, `aws_s3_bucket_server_side_encryption_configuration.account_key`, `aws_s3_bucket_public_access_block.account_key`, `aws_s3_bucket_policy.account_key`. The bucket has `force_destroy = true`, so the bucket destroy implicitly empties the `account-key` object + 5 orphan PEM files (`certificate`, `certificateKey`, `full`, `intermediate`, `root`).
- **Updates (in-place):**
  - `aws_iam_policy.lambda` — `S3AccountKey` statement removed; `SSMAccountKey` statement added.
  - `module.renew_certificates.aws_lambda_function.this` — `source_code_hash` change (rebuilt zip), env-var diff (`ACCOUNT_KEY_PARAMETER` added, `ACCOUNT_KEY_BUCKET` / `ACCOUNT_KEY_NAME` removed).
  - `module.revoke_certificate.aws_lambda_function.this` — same `source_code_hash` and env-var diffs.
- **No-op:** `aws_ssm_parameter.account_key` (already in state from Task 11; `lifecycle.ignore_changes = [value]` prevents value diff).
- **Output diff:** `account_key_bucket_name` removed.
- **No PEM bucket diffs** (default `pem_storage_regions = []`; `local.pem_regions` is empty).
- **Pre-existing drift** (not caused by this work, may still appear): `aws_s3_bucket_server_side_encryption_configuration.pem` schema reshape (if any pem regions exist) and `aws_route53_record.acme_challenge["*.isnan.eu"]` value drift. With migration default these drifts shouldn't appear, but document them as expected if visible.

- [ ] **Step 3: HALT — surface plan summary to user; do NOT auto-apply**

Print the plan summary line (`Plan: X to add, Y to change, Z to destroy.`) to the user. The user reviews and runs `terraform apply /tmp/letsencrypt-ssm-migration.tfplan` themselves.

- [ ] **Step 4: No commits for this task**

Per repo convention (no auto-commit, no auto-push), nothing is committed. The user picks files to commit themselves at their own discretion.

---

## Task 13: Final overall code review (optional)

After Tasks 1–12 complete, the user may opt to dispatch a final code-reviewer subagent for a holistic sanity pass on the working tree (similar to the multi-domain plan's final review). Surface the choice; do not auto-dispatch.

If the user opts in, dispatch a Sonnet-class subagent with:
- The spec path: `docs/superpowers/specs/2026-05-09-letsencrypt-lambda-ssm-account-key-design.md`.
- The list of changed files (from `git status --short`).
- The terraform plan path (`/tmp/letsencrypt-ssm-migration.tfplan`).
- Instructions to compare working tree against spec end-to-end, surface integration issues, cross-file consistency, scope creep.

The reviewer's report goes back to the user; the user decides what (if anything) to act on.

---

## Self-review

I checked the plan against the spec; here is the coverage map.

| Spec section | Plan task(s) | Notes |
| --- | --- | --- |
| §1.1 New `ssm.js` module | Task 1 | Verbatim file content. |
| §1.2 Slim `s3.js` | Task 2 | Full new content shown; old removals enumerated. |
| §1.3 Update `main.js` import | Task 3 | One-line swap. |
| §1.4 Add SSM client to esbuild externals | Task 3 | Combined with main.js update. |
| §2.1 New `ssm.tf` | Task 4 | Verbatim resource block. |
| §2.2 Drop S3 account_key resources | Task 8 | Full s3.tf content shown without account_key blocks. |
| §2.3 Swap S3AccountKey for SSMAccountKey | Task 5 | Full iam.tf content. |
| §2.4 Lambda env-var rewrite | Task 6 | Full lambda.tf content. |
| §2.5 Variables rewrite | Task 7 | Full variables.tf content. |
| §2.6 Outputs cleanup | Task 7 | Full outputs.tf content. |
| §2.7 Provider version unchanged | (no task) | No change needed; plan header notes "constraint stays at ~> 6.37". |
| §3 Migration runbook | Task 11 | All 7 spec steps mapped to Task 11 sub-steps with HALT semantics. |
| §3 "Why this order" rationale | Task 11 header | Critical-halt block at the top of Task 11. |
| §3 Risk envelope | Task 11 + Task 12 | "noisy not silent" risk model is implicit in Task 12's plan inspection (mid-apply IAM transition). |
| §4 Acceptance criteria — lint | Task 10 step 1 | |
| §4 Acceptance criteria — package builds | Task 10 step 2 | |
| §4 Acceptance criteria — terraform plan output | Task 12 step 2 | Expected diff itemized. |
| §4 Acceptance criteria — bucket gone | Task 12 step 2 (post-apply) | User verifies after their own apply (out of plan scope). |
| §4 Acceptance criteria — SSM has migrated PEM | Task 11 step 3 | grep on PEM header. |
| §5 Manual verification post-rollout | Task 12 step 3 | User-side after apply. |
| §6 Foundation doc updates | Task 9 | Six sub-edits enumerated. |
| §7 Accepted gaps | (n/a) | Explicitly NOT in plan — tests/CI, ACME_EMAIL, customer KMS, Secrets Manager. |

**Placeholder scan:** No "TBD" / "TODO" / "implement later" / "Add appropriate error handling" / "Similar to Task N". Every code block is verbatim. Every command shows expected output.

**Type / symbol consistency:**
- `loadAccountKey()` signature unchanged across `ssm.js` (Task 1) and `main.js` (Task 3 — just changes the import path; usage unchanged).
- `saveFullCertificate(commonName, region, fullCert, privateKey)` unchanged in `s3.js` (Task 2) and `main.js` (caller unchanged from prior multi-domain spec).
- Env var name `ACCOUNT_KEY_PARAMETER` consistent across `ssm.js` (Task 1, reads it), `lambda.tf` (Task 6, sets it), and the foundation doc (Task 9 sub-edit 5).
- Terraform `aws_ssm_parameter.account_key` resource address consistent across `ssm.tf` (Task 4, defines), `lambda.tf` (Task 6, references `.name`), `iam.tf` (Task 5, references `.arn`), and `terraform import` command (Task 11 step 5).
- Var name `var.account_key_parameter` consistent across `variables.tf` (Task 7, defines) and `ssm.tf` (Task 4, references).

**Spec-to-task gap check:** Every spec section has at least one task. The user-driven migration (spec §3) is fully captured in Task 11 with explicit halt semantics. The optional final review is captured as Task 13.
