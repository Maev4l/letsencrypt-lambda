---
title: letsencrypt-lambda — multi-domain support
status: ready-for-plan
audience: AI agent (primary), maintainer (secondary)
created: 2026-05-08
foundation: docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md
---

# letsencrypt-lambda — multi-domain support spec

Refactor the Lambda from a single-domain runtime to a list-of-domains
runtime, where each domain is independently configured (hosted zone,
ACM destination regions, optional per-region PEM storage). Renewal is
sequential per domain, failures are isolated, and notifications carry
the domain name.

This spec ships the **migration of the existing deployment** (a single
domain, `*.isnan.eu`) onto the new architecture. The new architecture
supports adding more domains afterward via a `var.domains` config
change — no further code work needed.

---

## Goals

1. Replace single-domain env-var inputs (`DOMAIN_*`, `CERTIFICATE_REGION`,
   `SECONDARY_CERTIFICATE_REGIONS`) with a single `DOMAINS_CONFIG` JSON
   list driving per-domain behaviour.
2. Per-domain attributes: common name, hosted zone ID, ACM destination
   regions, opt-in PEM storage regions.
3. Sequential iteration; per-domain failure isolation; per-domain SNS
   notification (renewed / skipped / failed); Lambda throws at end if
   any domain failed (preserves CloudWatch error metric correctness).
4. PEM storage uses **AWS S3 Account Regional Namespaces** for
   per-region buckets — one bucket per unique opted-in region across
   all domains, named `${prefix}-${accountId}-${region}-an`. No global
   namespace squatting risk.
5. Fix the latent ACME challenge target bug — pass
   `authz.identifier.value` instead of the hardcoded zone name.
6. Migrate the existing `*.isnan.eu` deployment in place: same Lambda
   function names, same scheduler, same ACM ARN preserved.

## Non-goals

- Tests / CI (still accepted gap from the cleanup spec).
- `ACME_EMAIL` variable promotion (still accepted gap).
- Adding new domains in this spec — `*.isnan.eu` migration only.
  Adding domains later is a `var.domains` edit + apply, no code work.
- Parallel domain processing — sequential is sufficient at envisioned
  scale; revisit only if domain count exceeds ~30.
- Multi-account / cross-account renewal.
- HTTP-01 / TLS-ALPN-01 challenges (DNS-01 only).
- Migrating the account-key bucket (`letsencrypt-lambda-storage`) into
  account-regional namespace — YAGNI for a single 32-byte object.
- Migrating existing root-level PEM files to the new layout — they
  become orphan; manual deletion documented but optional.

---

## 1. Per-domain configuration shape

### 1.1 Terraform variable

```hcl
variable "domains" {
  description = "Per-domain certificate configuration. Each entry produces one cert."
  type = list(object({
    common_name          = string
    hosted_zone_id       = string
    acm_regions          = list(string)            # primary first, then secondaries
    pem_storage_regions  = optional(list(string), [])
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
```

### 1.2 Wire-format (JSON env var)

The list is `jsonencode`'d into a single env var:

```hcl
DOMAINS_CONFIG = jsonencode(var.domains)
```

Example value (the migration default):

```json
[
  {
    "common_name": "*.isnan.eu",
    "hosted_zone_id": "ZWC66FN0XU6P9",
    "acm_regions": ["us-east-1", "eu-central-1"],
    "pem_storage_regions": []
  }
]
```

### 1.3 Runtime parsing + validation

A new module `src/config.js` parses on cold start:

```js
// function/src/config.js
import { getLogger } from './logger';
const logger = getLogger('config');

export const loadDomains = () => {
  const raw = process.env.DOMAINS_CONFIG;
  if (!raw) throw new Error('DOMAINS_CONFIG env var is missing');
  const domains = JSON.parse(raw);
  if (!Array.isArray(domains) || domains.length === 0) {
    throw new Error('DOMAINS_CONFIG must be a non-empty array');
  }

  const seen = new Set();
  for (const d of domains) {
    if (!d.common_name || typeof d.common_name !== 'string') {
      throw new Error(`Invalid domain entry (missing common_name): ${JSON.stringify(d)}`);
    }
    if (!d.hosted_zone_id || typeof d.hosted_zone_id !== 'string') {
      throw new Error(`Invalid domain entry (missing hosted_zone_id): ${d.common_name}`);
    }
    if (!Array.isArray(d.acm_regions) || d.acm_regions.length === 0) {
      throw new Error(`Invalid domain entry (acm_regions must be a non-empty list): ${d.common_name}`);
    }
    if (seen.has(d.common_name)) {
      throw new Error(`Duplicate common_name: ${d.common_name}`);
    }
    seen.add(d.common_name);
    // pem_storage_regions is optional; treat undefined as []
    if (d.pem_storage_regions !== undefined && !Array.isArray(d.pem_storage_regions)) {
      throw new Error(`pem_storage_regions must be a list when present: ${d.common_name}`);
    }
  }

  logger.info(`Loaded ${domains.length} domain(s) from config.`);
  return domains;
};
```

Validation runs once on cold start; cached for the duration of the
container's life.

---

## 2. Architecture

**Single Lambda function, sequential iteration over domains.**

The existing `renewCertificates` handler stays as the entry point.
Inside, it:

1. Parses `DOMAINS_CONFIG` once.
2. Optionally filters to one domain by `event.common_name`.
3. Loads the ACME account key once (shared across all domains).
4. Iterates the filtered list sequentially, delegating each domain to
   a new helper `renewSingleDomain(domain, accountKey, directory, force)`.
5. After every iteration, publishes one SNS notification for that
   domain's outcome (renewed / skipped / failed).
6. After the loop, if any domain failed, throws an aggregate error
   (so CloudWatch error metric reflects the partial failure).

Why sequential: 4–10 domains complete in 30–100 s well within the
180 s Lambda timeout; per-domain ACME state is isolated; logs read
linearly. Parallel processing would add complexity (concurrent
Route53 UPSERTs on a shared zone, error aggregation) for marginal
benefit at this scale.

### 2.1 Per-domain regions for PEM writes

Inside `renewSingleDomain`, after a successful ACME issuance, PEM
writes across the domain's `pem_storage_regions` run in parallel
(`Promise.all`) — independent buckets, no rate-limit interaction.

---

## 3. Code architecture

### 3.1 Module deltas

| Module | Change |
|---|---|
| `src/main.js` | `renewCertificates` becomes the orchestrator (load config, filter, iterate, accumulate, notify, throw-if-any-failed). Renewal logic for one domain moves to a new top-level helper `renewSingleDomain`. `revokeCertificate` stops reading `CERTIFICATE_REGION` — derives region from the ARN (`arn.split(':')[3]`). |
| `src/config.js` | **NEW** — `loadDomains()` (Section 1.3). |
| `src/acm.js` | `findCertificate(commonName, region)` and `importCertificate(privateKey, fullCert, commonName, directory, regions)` accept region/regions as args (env-var reads removed). `getCertificate(arn)` derives region from ARN. |
| `src/route53.js` | Unchanged — already takes `zoneId` + `domain` as args. The CALLER changes: in `main.js`, the `challengeCreateFn` passes `authz.identifier.value` (the actual challenge target per cert) instead of a hardcoded zone name (this fixes the latent bug for non-wildcard certs). |
| `src/s3.js` | `loadAccountKey()` reads `ACCOUNT_KEY_BUCKET` + `ACCOUNT_KEY_NAME` (renamed env vars). New `saveFullCertificate(commonName, region, fullCert, privateKey)` writes 5 objects to `${PEM_BUCKET_PREFIX}-${AWS_ACCOUNT_ID}-${region}-an` under prefix `<sanitized-common-name>/`. Sanitization: `*` → `_`. Each call constructs a new S3 client in the target region. |
| `src/sns.js` | Signature unchanged — `notify(message)`. Callers in `main.js` build the message with domain context. |
| `src/logger.js` | Unchanged. |

### 3.2 Handler skeleton (renewCertificates)

```js
// function/src/main.js (key fragments — full file is the implementation deliverable)
export const renewCertificates = async (event = {}) => {
  const { directory = defaultDirectory, force, common_name } = event;
  const allDomains = loadDomains();
  const filtered = common_name
    ? allDomains.filter((d) => d.common_name === common_name)
    : allDomains;

  if (common_name && filtered.length === 0) {
    throw new Error(`Unknown common_name: ${common_name}`);
  }

  const accountKey = await loadAccountKey();
  const results = [];

  for (const domain of filtered) {
    let result;
    try {
      result = await renewSingleDomain(domain, accountKey, directory, force);
    } catch (e) {
      logger.error(`Renewal failed for ${domain.common_name}: ${e.message}`);
      result = { status: 'failed', error: e.message };
    }

    try {
      await notify(buildMessage(domain.common_name, directory, result));
    } catch (e) {
      logger.error(`SNS publish failed for ${domain.common_name}: ${e.message}`);
      // Notification failure does NOT escalate.
    }

    results.push({ domain: domain.common_name, ...result });
  }

  const failed = results.filter((r) => r.status === 'failed');
  if (failed.length > 0) {
    throw new Error(
      `Renewal failed for ${failed.length}/${results.length} domain(s): ` +
        failed.map((f) => `${f.domain} (${f.error})`).join('; '),
    );
  }

  return { statusCode: 200, results };
};
```

### 3.3 renewSingleDomain skeleton

```js
const renewSingleDomain = async (domain, accountKey, directory, force) => {
  const { common_name, hosted_zone_id, acm_regions, pem_storage_regions = [] } = domain;
  const [primaryRegion] = acm_regions;

  // 1. Existence + threshold check (same as today, but on primary acm_region)
  const existing = await findCertificate(common_name, primaryRegion);
  let needRenew = false;
  let daysRemaining = null;
  if (!existing) {
    needRenew = true;
  } else {
    daysRemaining = dayjs(existing.NotAfter).diff(dayjs(), 'day');
    // Scheduler runs weekly (rate(7 days), see infrastructure/lambda.tf).
    // We renew when < 30 days remain, giving ~3 weeks of retry budget if a
    // single run fails.
    if (daysRemaining < 30) needRenew = true;
  }

  if (!needRenew && !force) {
    return { status: 'skipped', daysRemaining };
  }

  // 2. ACME issuance (one client per domain — fully isolated)
  const [privateKey, csr] = await acme.crypto.createCsr({ commonName: common_name });
  const client = new acme.Client({
    directoryUrl: getDirectoryUrl(directory),
    accountKey,
    backoffAttempts: 20,
  });
  const fullCertificate = await client.auto({
    csr,
    email: acmeEmail,
    termsOfServiceAgreed: true,
    challengePriority: ['dns-01'],
    // FIX: use authz.identifier.value (the challenge target) instead of a
    // hardcoded zone name; required for non-wildcard certs.
    challengeCreateFn: async (authz, _challenge, keyAuthorization) => {
      await createRoute53AcmeRecords(hosted_zone_id, authz.identifier.value, keyAuthorization);
    },
  });

  // 3. Per-region PEM writes (parallel — independent buckets)
  if (pem_storage_regions.length > 0) {
    await Promise.all(
      pem_storage_regions.map((region) =>
        saveFullCertificate(common_name, region, fullCertificate, privateKey),
      ),
    );
  }

  // 4. Per-region ACM imports (parallel — independent regions)
  await importCertificate(privateKey, fullCertificate, common_name, directory, acm_regions);

  return { status: 'renewed' };
};
```

### 3.4 Notification format

```js
const buildMessage = (commonName, directory, result) => {
  const truncate = (s) => (s && s.length > 500 ? s.slice(0, 500) + '…' : s);
  switch (result.status) {
    case 'renewed':
      return `Certificate renewed for '${commonName}' (${directory}).`;
    case 'skipped':
      return `Certificate check for '${commonName}' (${directory}) — no renewal needed; expires in ${result.daysRemaining} day(s).`;
    case 'failed':
      return `Certificate renewal FAILED for '${commonName}' (${directory}): ${truncate(result.error)}.`;
    default:
      return `Certificate check for '${commonName}' (${directory}) — unknown status.`;
  }
};
```

The SNS payload envelope (`source`, `sourceDescription`, `target=slack`,
`content`) is unchanged — only `content` carries the new per-domain
text.

### 3.5 ACM module signatures

```js
// function/src/acm.js (new signatures)
export const findCertificate = async (commonName, region) => { /* ... */ };
export const importCertificate = async (privateKey, fullCert, commonName, directory, regions) => { /* ... */ };
export const getCertificate = async (arn) => {
  const region = arn.split(':')[3];   // arn:aws:acm:<region>:<account>:certificate/<id>
  /* ... */
};
```

`importCertificate` parallel-imports across `regions`; for each region
it does a `findCertificate` first and reuses the existing ARN if any
(unchanged behaviour, ARN preservation per-region).

### 3.6 S3 module signatures

```js
// function/src/s3.js (new signatures)
const sanitizePrefix = (commonName) => commonName.replace('*', '_'); // *.isnan.eu → _.isnan.eu
const pemBucketName = (region) => `${process.env.PEM_BUCKET_PREFIX}-${process.env.AWS_ACCOUNT_ID}-${region}-an`;

export const loadAccountKey = async () => {
  // Reads from process.env.ACCOUNT_KEY_BUCKET / ACCOUNT_KEY_NAME, region = process.env.REGION.
  // Auto-creates if NoSuchKey (unchanged behaviour).
};

export const saveFullCertificate = async (commonName, region, fullCertificate, certificatePrivateKey) => {
  const bucket = pemBucketName(region);
  const prefix = sanitizePrefix(commonName);
  const s3 = new S3Client({ region });
  // Save 5 objects: <prefix>/full, <prefix>/certificate, <prefix>/intermediate, <prefix>/root, <prefix>/certificateKey
  // SSE=AES256, tags = application/owner from env (unchanged).
};
```

---

## 4. Storage (Terraform)

### 4.1 Account-key bucket — unchanged

`aws_s3_bucket.account_key` (renamed from `aws_s3_bucket.letsencrypt`)
keeps the legacy global-namespace name (`letsencrypt-lambda-storage`),
in `eu-central-1`, with all existing security policies. Holds only
the `account-key` object now (the 5 root-level PEM objects from the
single-domain era become orphan; manual cleanup is documented).

### 4.2 PEM buckets — new, account-regional namespace

```hcl
locals {
  pem_regions = toset(flatten([for d in var.domains : d.pem_storage_regions]))
}

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
  rule { apply_server_side_encryption_by_default { sse_algorithm = "AES256" } }
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

# Same deny-non-TLS / deny-non-SSE / deny-public-ACL bucket policy as the account-key
# bucket, applied per-region via for_each = local.pem_regions with region = each.value.
```

For the migration default (`pem_storage_regions = []` for `*.isnan.eu`),
`local.pem_regions` is empty and **no PEM buckets are created**. Buckets
get created the moment the user opts a domain into PEM storage.

### 4.3 Provider version constraint

Account-regional namespaces require **AWS provider ≥ 6.37.0**. Bump
`infrastructure/main.tf`:

```hcl
required_providers {
  aws = {
    source  = "hashicorp/aws"
    version = "~> 6.37"
  }
}
```

The repo's lock file currently pins `v6.39.0`, so a fresh `init`
already satisfies this — but the explicit constraint makes the floor
self-documenting.

---

## 5. IAM

```hcl
# Existing: SNS Publish, Route53 (*), ACM (*) — unchanged.

# S3 — account key (read + write)
statement {
  sid     = "S3AccountKey"
  effect  = "Allow"
  actions = ["s3:GetObject", "s3:PutObject", "s3:PutObjectTagging", "s3:ListBucket"]
  resources = [
    aws_s3_bucket.account_key.arn,
    "${aws_s3_bucket.account_key.arn}/*",
  ]
}

# S3 — PEM buckets (write only; one statement covering all PEM bucket ARNs)
statement {
  sid       = "S3PemWrite"
  effect    = "Allow"
  actions   = ["s3:PutObject", "s3:PutObjectTagging"]
  resources = [for b in aws_s3_bucket.pem : "${b.arn}/*"]
}
```

The `S3PemWrite` statement is automatically empty (resources = []) when
no PEM buckets exist (migration default). Terraform handles this fine
— the statement's `resources = []` makes the policy element a no-op.

If empty `resources` causes IAM API rejection on apply, use a `dynamic
"statement"` block conditioned on `length(local.pem_regions) > 0`. This
will be verified during plan-writing; falling back to the dynamic block
is the contingency.

---

## 6. Manual operations + event shape

### 6.1 Renew event

```jsonc
{
  "force":       boolean | undefined,             // existing
  "directory":   "production" | "staging" | undefined,  // existing
  "common_name": string | undefined               // NEW: filter to one domain
}
```

If `common_name` is provided and matches no domain → throws `Unknown
common_name: <value>`. If provided and matches one domain → only that
domain is processed in this invocation.

### 6.2 Yarn scripts — unchanged

`yarn renew` and `yarn renew:force` keep their current signatures
(empty payload / `{"force":true}`). They process **all** domains.
There is no `yarn renew:domain` script; targeted invokes use the full
command:

```bash
aws lambda invoke \
  --function-name renew-certificates \
  --cli-binary-format raw-in-base64-out \
  --payload '{"force":true,"common_name":"*.isnan.eu","directory":"staging"}' \
  /dev/stdout 2>/dev/null
```

This will be added to the README under "Manual operations".

### 6.3 Revoke — unchanged interface, internals updated

`aws lambda invoke --function-name revoke-certificate --payload '{"arn":"..."}'`
still works. The handler now derives the cert's region from the ARN
(`arn.split(':')[3]`) instead of the removed `CERTIFICATE_REGION` env
var. No new event fields.

---

## 7. Route53 placeholder records

Replace the single `aws_route53_record.acme_challenge` with a
per-domain `for_each`:

```hcl
resource "aws_route53_record" "acme_challenge" {
  for_each = { for d in var.domains : d.common_name => d }
  zone_id  = each.value.hosted_zone_id
  name     = "_acme-challenge.${replace(each.value.common_name, "*.", "")}"
  type     = "TXT"
  ttl      = 60
  records  = ["dummy"]
}
```

Wildcard handling: `replace("*.isnan.eu", "*.", "")` → `isnan.eu`. The
challenge target for `*.isnan.eu` is `_acme-challenge.isnan.eu` (LE
strips the wildcard for DNS-01).

### Migration of the existing single-domain placeholder

On apply, Terraform sees:

- The old single resource `aws_route53_record.acme_challenge` (no
  for_each) being destroyed.
- A new resource `aws_route53_record.acme_challenge["*.isnan.eu"]`
  being created with `records = ["dummy"]`.

Net effect on the actual DNS record (`_acme-challenge.isnan.eu`):
briefly destroyed and re-created with value `"dummy"`, then UPSERTed
to a real challenge value at the next renewal. Same drift pattern as
today, just per-domain.

To avoid the destroy/create churn, use `terraform state mv` after the
plan-writing step:

```bash
terraform state mv \
  aws_route53_record.acme_challenge \
  'aws_route53_record.acme_challenge["*.isnan.eu"]'
```

This is documented in the rollout section but not enforced — the
apply works either way.

---

## 8. Renamed / removed / added Terraform variables

### 8.1 Removed

| Variable | Reason |
|---|---|
| `var.domain_name` | Subsumed by per-domain `hosted_zone_id`; zone-name lookup no longer needed. The `data "aws_route53_zone" "main"` block in `main.tf` is also removed. |
| `var.domain_certificate_common_name` | Now in `var.domains[*].common_name`. |
| `var.domain_hosted_zone_id` | Now in `var.domains[*].hosted_zone_id`. |
| `var.certificate_region` | Now `var.domains[*].acm_regions[0]` (primary). |
| `var.secondary_certificate_regions` | Now `var.domains[*].acm_regions[1..]`. |

### 8.2 Renamed

| Old | New | Default | Reason |
|---|---|---|---|
| `var.bucket_name` | `var.account_key_bucket` | `letsencrypt-lambda-storage` (unchanged value) | Now scoped to one purpose. |

### 8.3 Added

| Variable | Type | Default |
|---|---|---|
| `var.domains` | `list(object({ common_name, hosted_zone_id, acm_regions, pem_storage_regions? }))` | `[{ common_name = "*.isnan.eu", hosted_zone_id = "ZWC66FN0XU6P9", acm_regions = ["us-east-1", "eu-central-1"], pem_storage_regions = [] }]` |
| `var.pem_bucket_prefix` | `string` | `letsencrypt-pems` |

### 8.4 Unchanged

`region`, `topic_arn`, `tag_application`, `tag_owner`, `directory`,
`lambda_memory_size`, `lambda_timeout`, `schedule_rate`,
`s3_letsencrypt_account_key_name`.

---

## 9. Renamed / removed / added Lambda env vars

### 9.1 Removed

`DOMAIN_HOSTED_ZONE_NAME`, `DOMAIN_CERTIFICATE_COMMON_NAME`,
`DOMAIN_HOSTED_ZONE_ID`, `CERTIFICATE_REGION`,
`SECONDARY_CERTIFICATE_REGIONS`.

### 9.2 Renamed

| Old | New | Reason |
|---|---|---|
| `BUCKET_NAME` | `ACCOUNT_KEY_BUCKET` | Now scoped to the account-key store only. |
| `S3_LETSENCRYPT_ACCOUNT_KEY_NAME` | `ACCOUNT_KEY_NAME` | Brevity; same value. |

### 9.3 Added

| Env var | Source | Consumer |
|---|---|---|
| `DOMAINS_CONFIG` | `jsonencode(var.domains)` | `src/config.js` (parsed once on cold start) |
| `PEM_BUCKET_PREFIX` | `var.pem_bucket_prefix` | `src/s3.js` |
| `AWS_ACCOUNT_ID` | `data.aws_caller_identity.current.account_id` | `src/s3.js` |

### 9.4 Unchanged

`REGION`, `TOPIC_ARN`, `TAG_APPLICATION`, `TAG_OWNER`, `DIRECTORY`,
`ACME_EMAIL` (still hardcoded — accepted gap).

---

## 10. ACME challenge target — bug fix

Current code passes `domainZoneName` (env var `DOMAIN_HOSTED_ZONE_NAME`,
e.g. `isnan.eu`) to `createRoute53AcmeRecords`. This works only when
the certificate's challenge target equals the zone name — i.e. for
wildcard certs whose common name is `*.<zoneName>`.

For non-wildcard certs (e.g. `alexandria.isnan.eu`), the challenge
target is `_acme-challenge.alexandria.isnan.eu`, NOT
`_acme-challenge.isnan.eu`. The current code would write the wrong TXT
record and the ACME validation would fail.

**Fix in `main.js`:** use `authz.identifier.value`, which `acme-client`
populates with the canonical challenge identifier per cert:

```js
challengeCreateFn: async (authz, _challenge, keyAuthorization) => {
  await createRoute53AcmeRecords(domain.hosted_zone_id, authz.identifier.value, keyAuthorization);
},
```

For `*.isnan.eu`, `authz.identifier.value === "isnan.eu"` (LE strips
the wildcard for DNS challenges) — so the migration default still
works. For any non-wildcard cert added later, the fix is a
prerequisite.

---

## 11. Rollout

Single step (because the migration default keeps the existing single
domain, no new domains added in this spec):

1. **Apply.** `yarn backend:deploy` runs `yarn package` (rebuilds the
   zip with the new code) and `terraform apply`. Terraform shows:
   - Lambda code update (new `source_code_hash`).
   - Lambda env-var changes (added `DOMAINS_CONFIG` /
     `PEM_BUCKET_PREFIX` / `AWS_ACCOUNT_ID`; renamed
     `ACCOUNT_KEY_BUCKET` / `ACCOUNT_KEY_NAME`; removed the five
     `DOMAIN_*` / `*_REGION*` vars).
   - IAM policy update (replacing the old S3 bucket statements with
     the new `S3AccountKey` + empty `S3PemWrite` statements; SNS /
     Route53 / ACM unchanged).
   - Route53 record reshape (single `aws_route53_record.acme_challenge`
     replaced by `aws_route53_record.acme_challenge["*.isnan.eu"]`).
     Optional: `terraform state mv` beforehand to avoid destroy/create.
   - Provider version-constraint bump (`~> 6.0` → `~> 6.37`); no actual
     provider download change since the lock file is already at
     v6.39.0.
2. **Verify against staging.** Manually invoke renew with
   `directory=staging` to issue a staging cert end-to-end (avoids
   touching the production ACM cert, exercises the entire new code
   path):
   ```bash
   aws lambda invoke \
     --function-name renew-certificates \
     --cli-binary-format raw-in-base64-out \
     --payload '{"force":true,"common_name":"*.isnan.eu","directory":"staging"}' \
     /dev/stdout 2>/dev/null
   ```
   Confirm: SNS notification arrives in Slack with text `"Certificate
   renewed for '*.isnan.eu' (staging)."`; ACM has a fresh
   IMPORTED-typed staging cert in `us-east-1` and `eu-central-1` (the
   migration's `acm_regions`).
3. **Verify against production.** Repeat with `directory=production`.
   The existing production cert ARN is reused (because
   `findCertificate` finds and re-uses by common name in each region).
   Confirm: SNS notification with `(production)`; ACM cert's
   `NotAfter` advances; consumers see no ARN change.
4. **Optional cleanup.** Delete the orphan root-level objects in
   `letsencrypt-lambda-storage`:
   ```bash
   aws s3 rm s3://letsencrypt-lambda-storage/full
   aws s3 rm s3://letsencrypt-lambda-storage/certificate
   aws s3 rm s3://letsencrypt-lambda-storage/intermediate
   aws s3 rm s3://letsencrypt-lambda-storage/root
   aws s3 rm s3://letsencrypt-lambda-storage/certificateKey
   ```
   The `account-key` object stays.

Adding new domains afterwards (e.g. `alexandria.isnan.eu`,
`*.bleroux.com`, `blog.bleroux.com`) is a `var.domains` edit + apply —
no further code work. Each new entry must come with:

- A Route53 hosted zone that already exists in the AWS account (zone
  ID supplied in the entry).
- The chosen `acm_regions` and (optionally) `pem_storage_regions`.

---

## 12. Acceptance criteria

- `yarn --cwd function lint` passes.
- `yarn --cwd function package` produces a fresh `dist/lambda.zip`.
- `terraform -chdir=infrastructure plan` shows:
  - Lambda code update for both functions (new `source_code_hash`).
  - Lambda env-var diffs matching Section 9.
  - IAM policy diff matching Section 5 (`S3AccountKey` retained;
    legacy `S3Read` / `S3Write` replaced; `S3PemWrite` added with
    empty resources or guarded by dynamic; SNS / Route53 / ACM
    unchanged).
  - Route53 record reshape (single → for_each["*.isnan.eu"]) — or no
    diff if `terraform state mv` was run beforehand.
  - **No** PEM bucket creation (migration default has empty
    `pem_storage_regions`).
- After apply, `yarn renew:force --payload '{"common_name":"*.isnan.eu","directory":"staging"}'`
  produces a staging cert end-to-end, with one Slack notification
  carrying domain + directory.
- After production force-renew, the existing `*.isnan.eu` ACM cert
  ARN is preserved (compare ARN in `aws acm list-certificates --region
  us-east-1` before and after).
- `aws lambda get-function-configuration --function-name renew-certificates`
  shows the new env-var set; legacy `DOMAIN_*` / `CERTIFICATE_REGION`
  / `SECONDARY_CERTIFICATE_REGIONS` are absent.
- README updated with the targeted-renew `aws lambda invoke` command
  under "Manual operations" (the existing revoke command stays).

## 13. Manual verification (post-rollout)

1. Slack receives the staging-renewal notification with text matching
   the format in Section 3.4 (renewed / skipped / failed) and
   identifying `*.isnan.eu`.
2. Production renewal (force) succeeds; ACM ARN unchanged; consumers
   (e.g. CloudFront distributions referencing the cert ARN) need no
   reconfiguration.
3. Schedule next-fire time still set (`aws scheduler get-schedule
   --name renew-certificates-schedule`); `rate(7 days)` unchanged.
4. CloudWatch logs for `renew-certificates` show one log line per
   domain + final summary.

---

## 14. Accepted gaps (deliberately out of scope)

- **No tests, no CI.** Inherited from the cleanup spec. Reconsider if
  the multi-domain logic acquires non-trivial branching that hand
  testing struggles to cover.
- **`ACME_EMAIL` hardcoded in `infrastructure/lambda.tf`.** Inherited.
- **Account-key bucket stays in the legacy global namespace.** Single
  static object, no migration value, kept simple.
- **Existing root-level PEM files in `letsencrypt-lambda-storage`.**
  Become orphan; manual cleanup documented but optional.
- **No `yarn renew:<domain>` script.** Yarn arg-passing is awkward
  and targeted invokes are infrequent — the full
  `aws lambda invoke` command in the README suffices.
