# letsencrypt-lambda Multi-Domain Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor the single-domain Lambda runtime into a list-of-domains runtime, where each domain has independent hosted-zone, ACM-region, and (opt-in) per-region PEM-storage configuration. Sequential iteration; per-domain failure isolation; per-domain SNS notifications; CloudWatch error metric stays honest. Migration ships with the existing `*.isnan.eu` deployment unchanged in observable behaviour (same Lambda function names, same scheduler, same ACM ARN preserved).

**Architecture:** A new `src/config.js` parses `DOMAINS_CONFIG` JSON once on cold start. `src/main.js` becomes an orchestrator iterating sequentially over the parsed list, delegating per-domain renewal to a new `renewSingleDomain` helper. `src/acm.js` and `src/s3.js` lose their env-var reads in favour of explicit region/regions arguments. PEM storage uses **AWS S3 Account Regional Namespaces** for per-region buckets, named `${prefix}-${accountId}-${region}-an`, requiring AWS provider ≥ 6.37 (already at 6.39 in lock file). The existing `aws_s3_bucket.letsencrypt` / `aws_route53_record.acme_challenge` resources are renamed via `terraform state mv` to avoid destroy/create.

**Tech Stack:** Node.js 22 (ESM, esbuild → CJS), `acme-client@5.3.0`, AWS SDK v3 (provided by Lambda runtime), Terraform `>= 1.10` with AWS provider `~> 6.37`, custom modules from `github.com/Maev4l/terraform-modules`. No tests / no CI (accepted gap from cleanup spec); quality gate = `yarn lint` + grep guards + targeted manual verification commands + Terraform plan inspection.

> **Repo conventions:**
> - User's global rule forbids auto-commit and auto-push. Each task's commit step is **proposed** — the executing agent MUST surface the staged diff and proposed commit message to the user for explicit approval before running `git commit`. Never push.
> - Lambda is zip-based (esbuild → CJS → zip). The global CLAUDE.md "Docker based AWS lambdas" rules do NOT apply here.

> **Spec:** [`docs/superpowers/specs/2026-05-08-letsencrypt-lambda-multi-domain-design.md`](../specs/2026-05-08-letsencrypt-lambda-multi-domain-design.md)
> **Foundation reference:** [`docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md`](../specs/2026-05-08-letsencrypt-lambda-foundation.md)

---

## File structure

| Path | Action | Responsibility |
| --- | --- | --- |
| `function/src/config.js` | **Create** | `loadDomains()` — parse + validate `DOMAINS_CONFIG` env var on cold start. |
| `function/src/main.js` | Rewrite | `renewCertificates` orchestrator (load config, filter, iterate, accumulate, notify, throw-if-any-failed) + `renewSingleDomain` helper + `buildMessage`. `revokeCertificate` no longer reads `CERTIFICATE_REGION` (region derived from ARN). |
| `function/src/acm.js` | Refactor | `findCertificate(commonName, region)`, `importCertificate(privateKey, fullCert, commonName, directory, regions)`, `getCertificate(arn)` (region from ARN). |
| `function/src/s3.js` | Refactor | New env vars (`ACCOUNT_KEY_BUCKET`, `ACCOUNT_KEY_NAME`, `PEM_BUCKET_PREFIX`, `AWS_ACCOUNT_ID`); `saveFullCertificate(commonName, region, fullCert, privateKey)` writes to `${prefix}-${accountId}-${region}-an/<sanitized-common-name>/`. |
| `function/src/route53.js` | Unchanged (caller change in `main.js`) | Uses `authz.identifier.value` from acme-client as the challenge target — fixes a latent bug for non-wildcard certs. |
| `function/src/sns.js` | Unchanged | Signature stays `notify(message)`. |
| `function/src/logger.js` | Unchanged | — |
| `infrastructure/main.tf` | Modify | Bump AWS provider constraint to `~> 6.37`; remove `data "aws_route53_zone" "main"` (no longer needed). |
| `infrastructure/variables.tf` | Rewrite | Add `var.domains` + `var.pem_bucket_prefix`; rename `bucket_name` → `account_key_bucket`; remove 5 single-domain vars. |
| `infrastructure/s3.tf` | Rewrite | Rename `aws_s3_bucket.letsencrypt` → `aws_s3_bucket.account_key`; add `aws_s3_bucket.pem` per-region with `bucket_namespace = "account-regional"`; DRY the deny policy via `templatefile`. |
| `infrastructure/templates/bucket-security-policy.json.tpl` | **Create** | Reusable bucket-policy template (deny non-TLS, deny non-SSE, deny public-ACL grants). |
| `infrastructure/iam.tf` | Modify | Split S3 statements: `S3AccountKey` (read+write on account-key bucket) + dynamic `S3PemWrite` (write only on PEM buckets, conditional on non-empty `pem_regions`). |
| `infrastructure/lambda.tf` | Modify | Replace `local.lambda_environment_variables` with new env-var set (`DOMAINS_CONFIG`, `PEM_BUCKET_PREFIX`, `AWS_ACCOUNT_ID`, renamed `ACCOUNT_KEY_BUCKET` / `ACCOUNT_KEY_NAME`; remove 5 `DOMAIN_*` / `*_REGION*` vars). |
| `infrastructure/route53.tf` | Modify | `aws_route53_record.acme_challenge` becomes `for_each` over `var.domains`. |
| `infrastructure/outputs.tf` | Modify | Rename output `s3_bucket_name` → `account_key_bucket_name`; reference `aws_s3_bucket.account_key`. |
| `README.md` | Modify | Add the targeted-renew `aws lambda invoke` command under "Manual operations". |
| `docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md` | Modify | Reflect the multi-domain runtime in §3 (architecture), §4 (env vars), §2 (repo layout adds `config.js`); bump `verified-against-commit:` after the cleanup commits land. |

All edits are independent **except**: state-renames and `terraform plan` (Task 14) run last, after every code edit; the foundation doc bump (Task 13) only depends on the implementation tasks completing — independent of Task 14.

---

## Task 1: Create `function/src/config.js`

**Files:**
- Create: `function/src/config.js`

- [ ] **Step 1: Create the file with exact contents**

```javascript
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
    if (d.pem_storage_regions !== undefined && !Array.isArray(d.pem_storage_regions)) {
      throw new Error(`pem_storage_regions must be a list when present: ${d.common_name}`);
    }
  }

  logger.info(`Loaded ${domains.length} domain(s) from config.`);
  return domains;
};
```

- [ ] **Step 2: Lint the package**

Run from repo root:

```bash
yarn --cwd function lint
```

Expected: exits 0, no warnings. If lint fails on import resolution for `./logger`, confirm the relative import is correct.

- [ ] **Step 3: Stage the new file (DO NOT COMMIT)**

```bash
git add function/src/config.js
```

- [ ] **Step 4: Surface for user-approved commit**

Proposed commit message:

```
feat(config): Add loadDomains() — parse and validate DOMAINS_CONFIG env var
```

Show `git diff --cached function/src/config.js` to user; commit only after explicit approval.

---

## Task 2: Refactor `function/src/acm.js` for explicit region arguments

**Files:**
- Modify: `function/src/acm.js` (full rewrite of the file)

The refactor removes env-var reads (`CERTIFICATE_REGION`, `SECONDARY_CERTIFICATE_REGIONS`) and introduces:
- `findCertificate(commonName, region, client?)` — region as required arg.
- `importCertificate(privateKey, fullCert, commonName, directory, regions)` — regions as required arg (replaces the old internal env-var iteration).
- `getCertificate(arn)` — derives region from the ARN.

- [ ] **Step 1: Replace the file with the new contents**

Overwrite `function/src/acm.js` with exactly:

```javascript
import acme from 'acme-client';
import {
  ACMClient,
  ImportCertificateCommand,
  paginateListCertificates,
  DescribeCertificateCommand,
  GetCertificateCommand,
  ListTagsForCertificateCommand,
} from '@aws-sdk/client-acm';

import { getLogger } from './logger';

const logger = getLogger('acm');

const {
  TAG_OWNER: tagOwner,
  TAG_APPLICATION: tagApplication,
} = process.env;

// ARN format: arn:aws:acm:<region>:<account>:certificate/<id>
const regionFromArn = (arn) => arn.split(':')[3];

const readCertificate = async (client, arn) => {
  const { Certificate: certificate } = await client.send(
    new GetCertificateCommand({ CertificateArn: arn }),
  );
  return certificate;
};

const getCertificateDirectory = async (client, arn) => {
  const { Tags: tags } = await client.send(
    new ListTagsForCertificateCommand({ CertificateArn: arn }),
  );
  const tag = tags.find((t) => {
    const { Key: key } = t;
    return key === 'directory';
  });
  const { Value } = tag || {};
  return Value || 'production';
};

export const getCertificate = async (arn) => {
  try {
    const region = regionFromArn(arn);
    const client = new ACMClient({ region });
    const certificate = await readCertificate(client, arn);
    const directory = await getCertificateDirectory(client, arn);

    return { certificate, directory };
  } catch (e) {
    if (e.name === 'ResourceNotFoundException') {
      return null;
    }
    throw e;
  }
};

export const findCertificate = async (commonName, region, client) => {
  const acmClient = client || new ACMClient({ region });
  const paginatorConfig = {
    client: acmClient,
    pageSize: 25,
  };

  for await (const page of paginateListCertificates(paginatorConfig, {})) {
    const { CertificateSummaryList: summaries } = page;
    const certificates = summaries.filter((summary) => {
      const { DomainName: domainName } = summary;
      return commonName === domainName;
    });

    if (certificates.length > 0) {
      const certificateDetails = await Promise.all(
        certificates.map(async (c) => {
          const { CertificateArn } = c;
          const details = await acmClient.send(new DescribeCertificateCommand({ CertificateArn }));
          return details;
        }),
      );

      const certificate = certificateDetails.find((c) => {
        const {
          Certificate: { Type: type },
        } = c;
        return type === 'IMPORTED';
      });

      if (certificate) {
        const { Certificate } = certificate;
        const { CertificateArn } = Certificate;
        logger.info(
          `Found an existing certificate for common name '${commonName}': ${CertificateArn}.`,
        );
        return Certificate;
      }
    }
  }
  logger.info(`No existing certificate for common name '${commonName}'.`);
  return null;
};

export const importCertificate = async (
  certificatePrivateKey,
  fullCertificate,
  commonName,
  directory,
  regions,
) => {
  await Promise.all(
    regions.map(async (region) => {
      const client = new ACMClient({ region });
      const existingCertificate = await findCertificate(commonName, region, client);
      let existingCertificateArn = null;
      if (existingCertificate) {
        const { CertificateArn } = existingCertificate;
        existingCertificateArn = CertificateArn;
      }
      const [certificate, ...rest] = acme.crypto.splitPemChain(fullCertificate);
      const params = existingCertificateArn
        ? {
            CertificateArn: existingCertificateArn,
            Certificate: Buffer.from(certificate),
            CertificateChain: Buffer.from(rest.join()),
            PrivateKey: Buffer.from(certificatePrivateKey),
          }
        : {
            Certificate: Buffer.from(certificate),
            CertificateChain: Buffer.from(rest.join()),
            PrivateKey: Buffer.from(certificatePrivateKey),
            Tags: [
              { Key: 'application', Value: tagApplication },
              { Key: 'owner', Value: tagOwner },
              { Key: 'directory', Value: directory },
            ],
          };
      const { CertificateArn } = await client.send(new ImportCertificateCommand(params));
      logger.info(
        `Certificate ${CertificateArn} for common name '${commonName}' imported in region ${region}.`,
      );
    }),
  );
};
```

- [ ] **Step 2: Verify the env-var reads are gone**

Run from repo root:

```bash
grep -E 'CERTIFICATE_REGION|SECONDARY_CERTIFICATE_REGIONS' function/src/acm.js && echo "STILL PRESENT" || echo "OK: env-var reads removed"
```

Expected output: `OK: env-var reads removed`

- [ ] **Step 3: Lint the package**

```bash
yarn --cwd function lint
```

Expected: exits 0.

- [ ] **Step 4: Stage**

```bash
git add function/src/acm.js
```

- [ ] **Step 5: Surface for user-approved commit**

Proposed message:

```
refactor(acm): Pass region(s) as args; derive region from ARN in getCertificate
```

---

## Task 3: Refactor `function/src/s3.js` for renamed env vars + new `saveFullCertificate` signature

**Files:**
- Modify: `function/src/s3.js` (full rewrite)

- [ ] **Step 1: Replace the file with the new contents**

Overwrite `function/src/s3.js` with exactly:

```javascript
import acme from 'acme-client';
import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';

import { getLogger } from './logger';

const {
  REGION: region,
  ACCOUNT_KEY_BUCKET: accountKeyBucket,
  ACCOUNT_KEY_NAME: accountKeyName,
  PEM_BUCKET_PREFIX: pemBucketPrefix,
  AWS_ACCOUNT_ID: awsAccountId,
  TAG_APPLICATION: tagApplication,
  TAG_OWNER: tagOwner,
} = process.env;

const logger = getLogger('s3');

const accountKeyClient = new S3Client({ region });

// Sanitize common name for use as S3 key prefix: '*' is not allowed in keys, replace with '_'.
const sanitizePrefix = (commonName) => commonName.replace('*', '_');

// Per-region PEM bucket naming convention: '<prefix>-<accountId>-<region>-an' (account-regional namespace).
const pemBucketName = (targetRegion) => `${pemBucketPrefix}-${awsAccountId}-${targetRegion}-an`;

export const loadAccountKey = async () => {
  try {
    const { Body: body } = await accountKeyClient.send(
      new GetObjectCommand({
        Bucket: accountKeyBucket,
        Key: accountKeyName,
      }),
    );
    logger.info(`Account Key loaded.`);
    const accountKey = await body.transformToByteArray();
    return Buffer.from(accountKey);
  } catch (e) {
    if (e.name === 'NoSuchKey') {
      logger.info(`Account Key not found.`);
      const privateKey = await acme.crypto.createPrivateKey();
      logger.info(`Account Key generated.`);
      await accountKeyClient.send(
        new PutObjectCommand({
          Bucket: accountKeyBucket,
          Key: accountKeyName,
          Body: privateKey,
          ServerSideEncryption: 'AES256',
          Tagging: `application=${tagApplication}&owner=${tagOwner}`,
        }),
      );
      logger.info(`Account Key saved.`);
      return privateKey;
    }

    logger.error(`Failed to load account key: ${e.name}.`);
    throw e;
  }
};

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

- [ ] **Step 2: Verify the old env-var name is gone**

```bash
grep -E 'BUCKET_NAME|S3_LETSENCRYPT_ACCOUNT_KEY_NAME' function/src/s3.js && echo "STILL PRESENT" || echo "OK: legacy env-var names removed"
```

Expected: `OK: legacy env-var names removed`

- [ ] **Step 3: Lint**

```bash
yarn --cwd function lint
```

Expected: exits 0.

- [ ] **Step 4: Stage**

```bash
git add function/src/s3.js
```

- [ ] **Step 5: Surface for user-approved commit**

Proposed message:

```
refactor(s3): Rename env vars; saveFullCertificate(commonName, region, …) writes per-region with prefix
```

---

## Task 4: Rewrite `function/src/main.js` as the multi-domain orchestrator

**Files:**
- Modify: `function/src/main.js` (full rewrite)

The handler becomes an orchestrator with three pieces:
1. Per-domain helper `renewSingleDomain` — runs the existing renewal logic for one domain config.
2. Per-domain message builder `buildMessage` — generates Slack content carrying common name + directory + status.
3. Top-level `renewCertificates` — loads config, optional filter, sequential loop, accumulate results, throw if any failed.

`revokeCertificate` is unchanged in observable behaviour — it still relies on `getCertificate(arn)` from `acm.js`, which now derives region from the ARN.

- [ ] **Step 1: Replace the file with the new contents**

Overwrite `function/src/main.js` with exactly:

```javascript
import acme from 'acme-client';
import dayjs from 'dayjs';

import { getLogger } from './logger';
import { loadDomains } from './config';
import { importCertificate, findCertificate, getCertificate } from './acm';
import { loadAccountKey, saveFullCertificate } from './s3';
import { createRoute53AcmeRecords } from './route53';
import { notify } from './sns';

const logger = getLogger('handler');

const {
  DIRECTORY: defaultDirectory,
  ACME_EMAIL: acmeEmail,
} = process.env;

// Returns the Let's Encrypt directory URL based on environment
const getDirectoryUrl = (directory) =>
  directory === 'production'
    ? acme.directory.letsencrypt.production
    : acme.directory.letsencrypt.staging;

// Truncate long error messages to fit Slack constraints (Slack chokes on very long lines).
const truncate = (s) => (s && s.length > 500 ? `${s.slice(0, 500)}…` : s);

const buildMessage = (commonName, directory, result) => {
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

const renewSingleDomain = async (domain, accountKey, directory, force) => {
  const {
    common_name: commonName,
    hosted_zone_id: hostedZoneId,
    acm_regions: acmRegions,
    pem_storage_regions: pemStorageRegions = [],
  } = domain;
  const [primaryRegion] = acmRegions;

  const existing = await findCertificate(commonName, primaryRegion);
  let needRenew = false;
  let daysRemaining = null;
  if (!existing) {
    needRenew = true;
  } else {
    daysRemaining = dayjs(existing.NotAfter).diff(dayjs(), 'day');
    if (daysRemaining >= 0) {
      logger.info(`Existing certificate for '${commonName}' will expire in ${daysRemaining} day(s).`);
    } else {
      logger.info(`Existing certificate for '${commonName}' expired since ${Math.abs(daysRemaining)} day(s).`);
    }
    // Scheduler runs weekly (rate(7 days), see infrastructure/lambda.tf).
    // We renew when < 30 days remain, giving ~3 weeks of retry budget if a
    // single run fails.
    if (daysRemaining < 30) needRenew = true;
  }

  if (!needRenew && !force) {
    return { status: 'skipped', daysRemaining };
  }

  const [privateKey, csr] = await acme.crypto.createCsr({ commonName });
  logger.info(`CSR generated for '${commonName}'.`);

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
    challengeCreateFn: async (authz, _challenge, keyAuthorization) => {
      // authz.identifier.value is the actual DNS name to challenge — works for
      // both wildcards (LE strips '*.') and non-wildcard certs.
      await createRoute53AcmeRecords(hostedZoneId, authz.identifier.value, keyAuthorization);
    },
  });
  logger.info(`Account url for '${commonName}': ${client.getAccountUrl()}`);

  if (pemStorageRegions.length > 0) {
    await Promise.all(
      pemStorageRegions.map((r) =>
        saveFullCertificate(commonName, r, fullCertificate, privateKey),
      ),
    );
  }

  await importCertificate(privateKey, fullCertificate, commonName, directory, acmRegions);

  return { status: 'renewed' };
};

export const renewCertificates = async (event = {}) => {
  const { directory = defaultDirectory, force, common_name: commonNameFilter } = event;

  logger.info(
    `Certificate renewal (force: ${force ? 'yes' : 'no'}) (directory: '${directory}')${
      commonNameFilter ? ` (filter: '${commonNameFilter}')` : ''
    } started ...`,
  );

  const allDomains = loadDomains();
  const filtered = commonNameFilter
    ? allDomains.filter((d) => d.common_name === commonNameFilter)
    : allDomains;

  if (commonNameFilter && filtered.length === 0) {
    throw new Error(`Unknown common_name: ${commonNameFilter}`);
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
      // SNS publish failure does NOT escalate — we don't want a Slack outage to
      // mask a successful renewal. Logged only.
      logger.error(`SNS publish failed for ${domain.common_name}: ${e.message}`);
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

  logger.info(`Certificate renewal completed (${results.length} domain(s)).`);
  return { statusCode: 200, results };
};

export const revokeCertificate = async (event) => {
  const { arn, ...rest } = event;

  if (!arn) {
    logger.info(`No ARN was specified.`);
    return { statusCode: 400, message: 'No ARN was specified' };
  }

  logger.info(`Revoking certificate (arn: ${arn})`);

  const accountKey = await loadAccountKey();

  const result = await getCertificate(arn);
  if (!result) {
    const message = `Certificate with ARN ${arn} does not exist.`;
    logger.error(message);
    return { statusCode: 404, message };
  }

  const { certificate, ...other } = result;
  const { directory } = { ...other, ...rest };

  logger.info(`Directory: ${directory}`);

  const client = new acme.Client({
    directoryUrl: getDirectoryUrl(directory),
    accountKey,
  });

  await client.createAccount({
    email: acmeEmail,
    termsOfServiceAgreed: true,
  });

  const accountUrl = client.getAccountUrl();
  logger.info(`Account url: ${accountUrl}`);

  const revokation = await client.revokeCertificate(certificate);
  logger.info(
    `Revoked (certificate: ${arn} - directory: ${directory}): ${JSON.stringify(revokation)}.`,
  );

  return { statusCode: 200, message: `Certificate ${arn} revoked successfully` };
};
```

- [ ] **Step 2: Verify the legacy env-var reads are gone**

```bash
grep -E 'DOMAIN_HOSTED_ZONE_NAME|DOMAIN_CERTIFICATE_COMMON_NAME|DOMAIN_HOSTED_ZONE_ID' function/src/main.js && echo "STILL PRESENT" || echo "OK: single-domain env-var reads removed"
```

Expected: `OK: single-domain env-var reads removed`

- [ ] **Step 3: Verify the challenge-target fix is in place**

```bash
grep -n "authz.identifier.value" function/src/main.js
```

Expected: exactly one hit, on the line inside `challengeCreateFn`.

- [ ] **Step 4: Lint**

```bash
yarn --cwd function lint
```

Expected: exits 0.

- [ ] **Step 5: Stage**

```bash
git add function/src/main.js
```

- [ ] **Step 6: Surface for user-approved commit**

Proposed message:

```
feat(handler): Multi-domain orchestrator with per-domain failure isolation
```

---

## Task 5: Update `infrastructure/main.tf` — provider constraint bump + remove zone data source

**Files:**
- Modify: `infrastructure/main.tf` (full rewrite)

- [ ] **Step 1: Replace the file with the new contents**

Overwrite `infrastructure/main.tf` with exactly:

```hcl
terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      # >= 6.37 required for S3 bucket account-regional namespace support.
      version = "~> 6.37"
    }
  }

  backend "s3" {
    bucket       = "global-tf-states"
    key          = "letsencrypt-lambda/terraform.tfstate"
    region       = "eu-central-1"
    use_lockfile = true # S3 native locking (no DynamoDB needed)
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      application = "letsencrypt-lambda"
      owner       = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
```

The `data "aws_route53_zone" "main"` block is removed — multi-domain config carries `hosted_zone_id` per entry, no zone-name lookup needed.

- [ ] **Step 2: Verify the zone data source is gone**

```bash
grep -n 'data "aws_route53_zone"' infrastructure/main.tf && echo "STILL PRESENT" || echo "OK: zone data source removed"
```

Expected: `OK: zone data source removed`

- [ ] **Step 3: Stage**

```bash
git add infrastructure/main.tf
```

- [ ] **Step 4: Surface for user-approved commit**

Proposed message:

```
chore(tf): Bump AWS provider constraint to ~> 6.37 (account-regional namespaces); drop unused zone data source
```

---

## Task 6: Rewrite `infrastructure/variables.tf`

**Files:**
- Modify: `infrastructure/variables.tf` (full rewrite)

- [ ] **Step 1: Replace the file with the new contents**

Overwrite `infrastructure/variables.tf` with exactly:

```hcl
variable "region" {
  description = "AWS region for the deployment (Lambda + account-key bucket + Route53 client)."
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

variable "account_key_bucket" {
  description = "S3 bucket for the ACME account key (legacy global namespace, eu-central-1)."
  type        = string
  default     = "letsencrypt-lambda-storage"
}

variable "s3_letsencrypt_account_key_name" {
  description = "S3 key name for the ACME account key."
  type        = string
  default     = "account-key"
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

- [ ] **Step 2: Verify the removed variables are gone**

```bash
grep -nE 'variable "domain_name"|variable "domain_certificate_common_name"|variable "domain_hosted_zone_id"|variable "certificate_region"|variable "secondary_certificate_regions"|variable "bucket_name"' infrastructure/variables.tf && echo "STILL PRESENT" || echo "OK: legacy variables removed"
```

Expected: `OK: legacy variables removed`

- [ ] **Step 3: Format check**

```bash
terraform -chdir=infrastructure fmt -check
```

Expected: exits 0 (no diff). If the file isn't formatted, run `terraform -chdir=infrastructure fmt` (without `-check`) to auto-format and re-stage.

- [ ] **Step 4: Stage**

```bash
git add infrastructure/variables.tf
```

- [ ] **Step 5: Surface for user-approved commit**

Proposed message:

```
feat(tf): Replace single-domain variables with var.domains list + var.pem_bucket_prefix
```

---

## Task 7: Rewrite `infrastructure/s3.tf` and add `infrastructure/templates/bucket-security-policy.json.tpl`

**Files:**
- Create: `infrastructure/templates/bucket-security-policy.json.tpl`
- Modify: `infrastructure/s3.tf` (full rewrite)

The bucket security policy (deny non-TLS, deny non-SSE, deny public-ACL grants) is identical across the account-key bucket and every PEM bucket. We extract it into a templatefile to keep `s3.tf` readable and avoid duplication.

- [ ] **Step 1: Create the templatefile**

Create `infrastructure/templates/bucket-security-policy.json.tpl` with exactly:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublishingUnencryptedResources",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "${bucket_arn}/*",
      "Condition": {
        "Null": {
          "s3:x-amz-server-side-encryption": "true"
        }
      }
    },
    {
      "Sid": "DenyIncorrectEncryptionHeader",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "${bucket_arn}/*",
      "Condition": {
        "ForAllValues:StringNotEquals": {
          "s3:x-amz-server-side-encryption": ["AES256", "aws:kms"]
        }
      }
    },
    {
      "Sid": "DenyUnencryptedConnections",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "${bucket_arn}/*",
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "DenyPublicReadAcl",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:PutBucketAcl", "s3:PutObject", "s3:PutObjectAcl"],
      "Resource": ["${bucket_arn}", "${bucket_arn}/*"],
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": ["authenticated-read", "public-read", "public-read-write"]
        }
      }
    },
    {
      "Sid": "DenyGrantingPublicRead",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:PutBucketAcl", "s3:PutObject", "s3:PutObjectAcl"],
      "Resource": ["${bucket_arn}", "${bucket_arn}/*"],
      "Condition": {
        "StringLike": {
          "s3:x-amz-grant-read": [
            "*http://acs.amazonaws.com/groups/global/AllUsers*",
            "*http://acs.amazonaws.com/groups/global/AuthenticatedUsers*"
          ]
        }
      }
    }
  ]
}
```

- [ ] **Step 2: Replace `infrastructure/s3.tf` with the new contents**

Overwrite with exactly:

```hcl
locals {
  # Union of all regions any domain has opted into for PEM storage.
  pem_regions = toset(flatten([for d in var.domains : d.pem_storage_regions]))
}

# ---------- Account-key bucket (legacy global namespace, preserved) ----------

resource "aws_s3_bucket" "account_key" {
  bucket        = var.account_key_bucket
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "account_key" {
  bucket = aws_s3_bucket.account_key.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "account_key" {
  bucket = aws_s3_bucket.account_key.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "account_key" {
  bucket = aws_s3_bucket.account_key.id
  policy = templatefile("${path.module}/templates/bucket-security-policy.json.tpl", {
    bucket_arn = aws_s3_bucket.account_key.arn
  })
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

- [ ] **Step 3: Format check**

```bash
terraform -chdir=infrastructure fmt -check
```

Expected: exits 0. If not, run `terraform -chdir=infrastructure fmt` and re-stage both files.

- [ ] **Step 4: Stage**

```bash
git add infrastructure/s3.tf infrastructure/templates/bucket-security-policy.json.tpl
```

- [ ] **Step 5: Surface for user-approved commit**

Proposed message:

```
feat(tf): Rename letsencrypt bucket to account_key + add per-region PEM buckets via account-regional namespace
```

---

## Task 8: Update `infrastructure/iam.tf` — split S3 statements

**Files:**
- Modify: `infrastructure/iam.tf` (full rewrite)

The legacy single S3 read + S3 write statements (scoped to `aws_s3_bucket.letsencrypt`) are replaced by:
1. `S3AccountKey` — read+write on the account-key bucket (covers the `loadAccountKey` + auto-create paths).
2. `S3PemWrite` — write only on PEM buckets, **dynamically emitted** only when `local.pem_regions` is non-empty (avoids an empty `resources = []` IAM API rejection).

Other statements (SNS, Route53, ACM) are unchanged.

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
    sid    = "S3AccountKey"
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject",
      "s3:PutObjectTagging",
      "s3:ListBucket",
    ]
    resources = [
      aws_s3_bucket.account_key.arn,
      "${aws_s3_bucket.account_key.arn}/*",
    ]
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

- [ ] **Step 2: Format check**

```bash
terraform -chdir=infrastructure fmt -check
```

Expected: exits 0.

- [ ] **Step 3: Stage**

```bash
git add infrastructure/iam.tf
```

- [ ] **Step 4: Surface for user-approved commit**

Proposed message:

```
feat(tf): Split S3 IAM statements; dynamic S3PemWrite for opt-in PEM buckets
```

---

## Task 9: Update `infrastructure/lambda.tf` — env var rewrite

**Files:**
- Modify: `infrastructure/lambda.tf` (full rewrite)

Replaces the env-var set: removes 5 single-domain vars, renames 2, adds 3 new ones (`DOMAINS_CONFIG`, `PEM_BUCKET_PREFIX`, `AWS_ACCOUNT_ID`). Function modules (renew + revoke) and scheduler module are otherwise unchanged.

- [ ] **Step 1: Replace the file with the new contents**

Overwrite `infrastructure/lambda.tf` with exactly:

```hcl
# Pre-built zip from function/dist/lambda.zip (run: cd function && yarn build && yarn package)
locals {
  lambda_zip_path = "${path.module}/../function/dist/lambda.zip"

  lambda_environment_variables = {
    REGION             = var.region
    DOMAINS_CONFIG     = jsonencode(var.domains)
    PEM_BUCKET_PREFIX  = var.pem_bucket_prefix
    AWS_ACCOUNT_ID     = data.aws_caller_identity.current.account_id
    ACCOUNT_KEY_BUCKET = var.account_key_bucket
    ACCOUNT_KEY_NAME   = var.s3_letsencrypt_account_key_name
    TOPIC_ARN          = var.topic_arn
    TAG_APPLICATION    = var.tag_application
    TAG_OWNER          = var.tag_owner
    DIRECTORY          = var.directory
    ACME_EMAIL         = "maeval.nightingale@gmail.com"
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

- [ ] **Step 2: Verify the legacy env vars are gone from the locals block**

```bash
grep -nE 'DOMAIN_HOSTED_ZONE_NAME|DOMAIN_CERTIFICATE_COMMON_NAME|DOMAIN_HOSTED_ZONE_ID|CERTIFICATE_REGION|SECONDARY_CERTIFICATE_REGIONS|BUCKET_NAME[^_]|S3_LETSENCRYPT_ACCOUNT_KEY_NAME' infrastructure/lambda.tf && echo "STILL PRESENT" || echo "OK: legacy env vars removed"
```

Expected: `OK: legacy env vars removed`

(Note: the regex `BUCKET_NAME[^_]` matches `BUCKET_NAME =` but NOT `ACCOUNT_KEY_BUCKET` — confirming we removed only the legacy variable.)

- [ ] **Step 3: Format check**

```bash
terraform -chdir=infrastructure fmt -check
```

Expected: exits 0.

- [ ] **Step 4: Stage**

```bash
git add infrastructure/lambda.tf
```

- [ ] **Step 5: Surface for user-approved commit**

Proposed message:

```
feat(tf): Lambda env vars — DOMAINS_CONFIG, PEM_BUCKET_PREFIX, AWS_ACCOUNT_ID; rename ACCOUNT_KEY_*
```

---

## Task 10: Update `infrastructure/route53.tf` — per-domain placeholder via for_each

**Files:**
- Modify: `infrastructure/route53.tf` (full rewrite)

- [ ] **Step 1: Replace the file with the new contents**

Overwrite with exactly:

```hcl
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
```

- [ ] **Step 2: Format check**

```bash
terraform -chdir=infrastructure fmt -check
```

Expected: exits 0.

- [ ] **Step 3: Stage**

```bash
git add infrastructure/route53.tf
```

- [ ] **Step 4: Surface for user-approved commit**

Proposed message:

```
feat(tf): Per-domain ACME challenge placeholder via for_each
```

---

## Task 11: Update `infrastructure/outputs.tf`

**Files:**
- Modify: `infrastructure/outputs.tf` (full rewrite)

Renames the output and the resource reference (account-key bucket).

- [ ] **Step 1: Replace the file with the new contents**

Overwrite with exactly:

```hcl
output "lambda_renew_certificates_arn" {
  description = "ARN of the renew-certificates Lambda function"
  value       = module.renew_certificates.function_arn
}

output "lambda_revoke_certificate_arn" {
  description = "ARN of the revoke-certificate Lambda function"
  value       = module.revoke_certificate.function_arn
}

output "account_key_bucket_name" {
  description = "Name of the account-key S3 bucket"
  value       = aws_s3_bucket.account_key.id
}

output "iam_role_arn" {
  description = "ARN of the Lambda IAM role"
  value       = module.renew_certificates.role_arn
}
```

- [ ] **Step 2: Format check**

```bash
terraform -chdir=infrastructure fmt -check
```

Expected: exits 0.

- [ ] **Step 3: Stage**

```bash
git add infrastructure/outputs.tf
```

- [ ] **Step 4: Surface for user-approved commit**

Proposed message:

```
chore(tf): Rename s3_bucket_name output to account_key_bucket_name
```

---

## Task 12: Update `README.md` — targeted-renew command

**Files:**
- Modify: `README.md`

Append a third `aws lambda invoke` block under "Manual operations" → between the renew yarn scripts and the existing "Revoke" section.

- [ ] **Step 1: Apply the edit**

Read the current `README.md`. Locate the `### Renew` block and the `### Revoke` block. Insert a new sub-section **between them** (after the renew scripts code fence and before the `### Revoke` heading) titled `### Renew a single domain`:

```markdown
### Renew a single domain

For ad-hoc renewal of one specific domain (e.g., when validating a
new domain in staging without touching the others):

\`\`\`bash
aws lambda invoke \
  --function-name renew-certificates \
  --cli-binary-format raw-in-base64-out \
  --payload '{"force":true,"common_name":"*.isnan.eu","directory":"staging"}' \
  /dev/stdout 2>/dev/null
\`\`\`

The `common_name` filters to a single configured domain; `directory`
overrides the default (production / staging) for that invocation only.
```

(Use real triple-backticks in the actual file, not the escaped variant above. The escapes are only to embed the snippet in this plan.)

- [ ] **Step 2: Verify the new section is present**

```bash
grep -n "Renew a single domain" README.md
```

Expected: exactly one hit.

- [ ] **Step 3: Stage**

```bash
git add README.md
```

- [ ] **Step 4: Surface for user-approved commit**

Proposed message:

```
docs(readme): Document targeted single-domain renew command
```

---

## Task 13: Update foundation doc to reflect the multi-domain runtime

**Files:**
- Modify: `docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md`

The foundation doc is the agent-first reference. Three sections need updates:

- §1 Purpose & scope — drop "for one Route53 hosted zone" (now per-domain).
- §2 Repo layout — add `function/src/config.js` row; mention `infrastructure/templates/bucket-security-policy.json.tpl`; rename `aws_s3_bucket.letsencrypt` to `aws_s3_bucket.account_key` in the `s3.tf` description; note `aws_s3_bucket.pem` for_each.
- §3 Runtime architecture — rewrite the `renewCertificates` flow to describe sequential per-domain iteration, per-domain notifications, throw-if-any-failed.
- §4 Environment variables — table updated: remove 5 legacy vars, rename 2, add 3 new.

The `verified-against-commit:` frontmatter line is left untouched here — it bumps when the user actually commits this plan's changes (per the cleanup-spec convention).

- [ ] **Step 1: Apply edits to §1**

In `docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md`, find the §1 first paragraph that begins:

```
A single-purpose AWS Lambda (Node.js, ESM) that automates Let's Encrypt
certificate issuance, renewal, and revocation for **one** Route53 hosted
zone, using the **ACME DNS-01** challenge.
```

Replace with:

```
A single-purpose AWS Lambda (Node.js, ESM) that automates Let's Encrypt
certificate issuance, renewal, and revocation for a **list of domains**
(each with its own Route53 hosted zone, ACM destination regions, and
optional per-region PEM storage), using the **ACME DNS-01** challenge.
```

Find the non-goals bullet:

```
- Support multiple domains / multiple hosted zones per deployment.
```

Replace with:

```
- Multi-account / cross-account renewal (single AWS account only).
```

(The "Support multiple domains" non-goal is no longer accurate — multi-domain is now in scope.)

- [ ] **Step 2: Apply edits to §2 (repo layout)**

Find the line in the `function/src/` directory listing:

```
│   │   ├── main.js                Two handlers: renewCertificates, revokeCertificate.
```

Insert immediately AFTER it:

```
│   │   ├── config.js              loadDomains() — parse + validate DOMAINS_CONFIG on cold start.
```

Find the line in the `infrastructure/` directory listing:

```
    ├── s3.tf                      Bucket (force_destroy=true) + SSE + public-access-block + deny policies.
```

Replace with:

```
    ├── s3.tf                      Account-key bucket (legacy global namespace) + per-region PEM buckets (account-regional namespace) via for_each over var.domains.
    ├── templates/
    │   └── bucket-security-policy.json.tpl   Reusable bucket policy (deny non-TLS / non-SSE / public-ACL).
```

- [ ] **Step 3: Replace §3 (runtime architecture) — `renewCertificates` flow**

Find the heading `### \`renewCertificates\` (\`main.renewCertificates\`)` and replace the entire subsection (everything from that heading down to but NOT including the `### \`revokeCertificate\`` heading) with:

```markdown
### `renewCertificates` (`main.renewCertificates`)

**Event shape:** `{ directory?: 'production' | 'staging', force?: boolean, common_name?: string }` — all optional.

**Flow:**

1. Resolve directory: event arg → fallback to `DIRECTORY` env.
2. `loadDomains()` (cold-start cached) — parses + validates `DOMAINS_CONFIG`.
3. Optional filter to a single domain by `event.common_name`. If filter matches no entry → throws `Unknown common_name: <value>`.
4. `loadAccountKey()` once (shared across all domains).
5. **Sequential** iteration over the filtered list. For each domain, call `renewSingleDomain(domain, accountKey, directory, force)`:
   1. `findCertificate(common_name, primaryRegion)` in `acm_regions[0]`.
   2. Decide:
      - No cert → renew.
      - `dayjs(NotAfter).diff(dayjs(), 'day') < 30` → renew.
      - `force === true` → renew.
      - Else → return `{ status: 'skipped', daysRemaining }`.
   3. On renew: generate CSR; run `acme-client` `auto()` with `challengeCreateFn` that UPSERTs `_acme-challenge.<authz.identifier.value>` TXT in the domain's `hosted_zone_id` (uses `authz.identifier.value` — the canonical challenge target — not a hardcoded zone name).
   4. If `pem_storage_regions.length > 0`: parallel `saveFullCertificate(common_name, region, …)` across each region — writes 5 objects to `${PEM_BUCKET_PREFIX}-${AWS_ACCOUNT_ID}-${region}-an/<sanitized-common-name>/`.
   5. `importCertificate(privateKey, fullCert, common_name, directory, acm_regions)` — parallel ACM imports across the configured regions, reusing existing ARN per-region when found.
   6. Return `{ status: 'renewed' }`.
6. Per-domain result handling (inside the same loop):
   - Wrap step 5 in try/catch; on throw, log and set `result = { status: 'failed', error: e.message }`.
   - Always publish one SNS notification carrying common name + directory + status text. SNS publish failures are logged but do NOT escalate.
   - Push `{ domain: common_name, ...result }` into the results array.
7. After the loop: if any result has `status: 'failed'`, throw an aggregate error (so CloudWatch error metric reflects partial failures). Otherwise return `{ statusCode: 200, results }`.
```

- [ ] **Step 4: Replace §4 (environment variables) table**

Find the §4 table (starts after `## 4. Environment variables` heading) and replace the entire table block with:

```markdown
| Name                  | Source                                                | Consumer module(s)              | Example / default                                       |
| --------------------- | ----------------------------------------------------- | ------------------------------- | ------------------------------------------------------- |
| `REGION`              | `var.region`                                          | `route53.js`, `s3.js`, `sns.js` | `eu-central-1`                                          |
| `DOMAINS_CONFIG`      | `jsonencode(var.domains)`                             | `config.js`                     | `[{"common_name":"*.isnan.eu","hosted_zone_id":"ZWC66FN0XU6P9","acm_regions":["us-east-1","eu-central-1"],"pem_storage_regions":[]}]` |
| `PEM_BUCKET_PREFIX`   | `var.pem_bucket_prefix`                               | `s3.js`                         | `letsencrypt-pems`                                      |
| `AWS_ACCOUNT_ID`      | `data.aws_caller_identity.current.account_id`         | `s3.js`                         | `671123374425`                                          |
| `ACCOUNT_KEY_BUCKET`  | `var.account_key_bucket`                              | `s3.js`                         | `letsencrypt-lambda-storage`                            |
| `ACCOUNT_KEY_NAME`    | `var.s3_letsencrypt_account_key_name`                 | `s3.js`                         | `account-key`                                           |
| `TOPIC_ARN`           | `var.topic_arn`                                       | `sns.js`                        | `arn:aws:sns:eu-central-1:671123374425:alerting-events` |
| `TAG_APPLICATION`     | `var.tag_application`                                 | `acm.js`, `s3.js`               | `letsencrypt-lambda`                                    |
| `TAG_OWNER`           | `var.tag_owner`                                       | `acm.js`, `s3.js`               | `terraform`                                             |
| `DIRECTORY`           | `var.directory`                                       | `main.js`                       | `production` (or `staging`)                             |
| `ACME_EMAIL`          | **Hardcoded in `infrastructure/lambda.tf`** (not a variable) | `main.js`                | `maeval.nightingale@gmail.com` (accepted gap)           |
```

Also update the "Notes:" block immediately below the table to read:

```markdown
Notes:

- `DOMAINS_CONFIG` is parsed once per cold start by `config.js#loadDomains()`. Each entry validates `common_name`, `hosted_zone_id`, non-empty `acm_regions`, optional `pem_storage_regions` (default `[]`), and uniqueness of `common_name`.
- `DIRECTORY` is the runtime default; the renew event payload can override it per-invocation.
- `event.common_name` (renew event) filters to a single configured domain; absent / empty = process all.
- `ACME_EMAIL` is the only value not exposed as a Terraform variable.
```

- [ ] **Step 5: Verify all four sub-edits applied**

```bash
grep -c "loadDomains" docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md
grep -c "DOMAINS_CONFIG" docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md
grep -c "account-regional namespace" docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md
grep -c "authz.identifier.value" docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md
```

Expected: all four counts ≥ 1. If any is 0, the corresponding edit was missed; re-run that step.

- [ ] **Step 6: Stage**

```bash
git add docs/superpowers/specs/2026-05-08-letsencrypt-lambda-foundation.md
```

- [ ] **Step 7: Surface for user-approved commit**

Proposed message:

```
docs(foundation): Update foundation doc for multi-domain runtime
```

---

## Task 14: Build, state migration, and Terraform plan inspection (HALT for user review)

This task does NOT modify source. It (a) verifies the JS package builds clean, (b) renames Terraform state entries to avoid destroy/create churn, and (c) produces a Terraform plan for user review **without applying**.

**Files:**
- Read-only inspection of `function/bin/main.js`, `function/dist/lambda.zip`, Terraform plan output.
- Modifies remote Terraform state (S3 backend) via `terraform state mv` — no source-code edits.

- [ ] **Step 1: Lint the function package**

```bash
yarn --cwd function lint
```

Expected: exits 0.

- [ ] **Step 2: Build + package the Lambda zip**

```bash
yarn --cwd function package
```

Expected: produces `function/bin/main.js` and `function/dist/lambda.zip`. No build errors. The bundle should be visibly larger than before (config.js + larger main.js orchestrator); both Lambda modules will get a new `source_code_hash`.

- [ ] **Step 3: Initialize Terraform**

```bash
terraform -chdir=infrastructure init -input=false
```

Expected: succeeds. Provider plugin reuse from lock (v6.39.0) — no download needed because v6.39.0 satisfies `~> 6.37`.

- [ ] **Step 4: Migrate Terraform state to preserve resources**

Critical: without these renames, Terraform plan would show **destroy + create** for the account-key bucket and the Route53 challenge record. `force_destroy = true` means the bucket destroy would also delete the `account-key` S3 object — losing the ACME account key.

Run each command. If a command errors with "did not match" / "no matching resource" the resource may have been previously moved or didn't exist in state — log the error and proceed to the next command (do NOT abort the entire migration).

```bash
terraform -chdir=infrastructure state mv aws_s3_bucket.letsencrypt aws_s3_bucket.account_key
terraform -chdir=infrastructure state mv aws_s3_bucket_server_side_encryption_configuration.letsencrypt aws_s3_bucket_server_side_encryption_configuration.account_key
terraform -chdir=infrastructure state mv aws_s3_bucket_public_access_block.letsencrypt aws_s3_bucket_public_access_block.account_key
terraform -chdir=infrastructure state mv aws_s3_bucket_policy.letsencrypt aws_s3_bucket_policy.account_key
terraform -chdir=infrastructure state mv 'aws_route53_record.acme_challenge' 'aws_route53_record.acme_challenge["*.isnan.eu"]'
```

Expected: each command prints `Move "<source>" to "<dest>"` followed by `Successfully moved 1 object(s).`

- [ ] **Step 5: Run Terraform plan**

```bash
terraform -chdir=infrastructure plan -no-color -out=/tmp/letsencrypt-multi-domain.tfplan
```

Show the user the last 80 lines of the plan output:

```bash
terraform -chdir=infrastructure show -no-color /tmp/letsencrypt-multi-domain.tfplan | tail -80
```

**Expected diffs:**

- Both `aws_lambda_function.this` resources (under `module.renew_certificates` and `module.revoke_certificate`) update in place — `source_code_hash` change driven by the rebuilt `bin/main.js`, plus `environment` block diffs (added `DOMAINS_CONFIG`, `PEM_BUCKET_PREFIX`, `AWS_ACCOUNT_ID`; removed five legacy `DOMAIN_*` / `*_REGION*` vars; renamed two; same value for the rest).
- `aws_iam_policy.lambda` updates — body changes from legacy S3Read+S3Write split to `S3AccountKey` + (no `S3PemWrite` since `pem_regions` is empty for the migration default).
- **No** Route53 record diff (the state mv preserved it).
- **No** S3 bucket diff for the renamed account-key bucket (state mv preserved it).
- **No** PEM bucket creation (migration default has `pem_storage_regions = []` for the only domain).
- **No** scheduler diff.
- **No** SNS data-source diff.

The 2 pre-existing drift items observed during the cleanup spec's plan (the `aws_route53_record.acme_challenge` value reverting to "dummy", and the `aws_s3_bucket_server_side_encryption_configuration.account_key` reshape) **may still appear** here as upstream state issues — that's fine, they're not caused by this work.

- [ ] **Step 6: HALT for user review**

Do NOT run `terraform apply`. Do NOT auto-commit. Surface to the user:

1. The plan summary (final `Plan: X to add, Y to change, Z to destroy.` line).
2. The full plan output saved to `/tmp/letsencrypt-multi-domain.tfplan`.
3. A summary of staged code changes (`git status --short`).

The user reviews, picks files to commit, runs `terraform apply` themselves, and verifies post-apply per the spec's rollout instructions:

```bash
# After apply: validate the new code path against the staging directory
aws lambda invoke \
  --function-name renew-certificates \
  --cli-binary-format raw-in-base64-out \
  --payload '{"force":true,"common_name":"*.isnan.eu","directory":"staging"}' \
  /dev/stdout 2>/dev/null

# Then production
aws lambda invoke \
  --function-name renew-certificates \
  --cli-binary-format raw-in-base64-out \
  --payload '{"force":true,"common_name":"*.isnan.eu","directory":"production"}' \
  /dev/stdout 2>/dev/null

# Confirm ARN preservation
aws acm list-certificates --region us-east-1 --query 'CertificateSummaryList[?DomainName==`*.isnan.eu`]'
aws acm list-certificates --region eu-central-1 --query 'CertificateSummaryList[?DomainName==`*.isnan.eu`]'
```

- [ ] **Step 7: No commit for this task**

This task only verifies; nothing of its own to commit. The user commits the prior tasks' staged changes at their discretion.

---

## Self-review

I checked the plan against the spec; here is the coverage map.

| Spec section | Plan task(s) | Notes |
| --- | --- | --- |
| §1.1 Terraform `var.domains` + `var.pem_bucket_prefix` | Task 6 | Full file content shown; default preserves single-domain. |
| §1.2 Wire-format env var (`DOMAINS_CONFIG`) | Task 9 | `jsonencode(var.domains)` in lambda.tf locals. |
| §1.3 Runtime parsing + validation (`config.js`) | Task 1 | New file, exact content. |
| §2 Sequential iteration architecture | Task 4 | `for...of` loop in `renewCertificates`. |
| §2.1 Parallel per-region PEM writes | Task 4 | `Promise.all` over `pem_storage_regions` inside `renewSingleDomain`. |
| §3 Module deltas (config, main, acm, s3, route53) | Tasks 1–4 | Per-module: full file content where rewritten; `route53.js` unchanged but caller updated in `main.js`. |
| §3.4 Notification format | Task 4 | `buildMessage` switch on status; truncate(500). |
| §3.5 ACM signature changes (region/regions args; ARN-derived region) | Task 2 | `findCertificate(commonName, region, ?client)`, `importCertificate(...regions)`, `regionFromArn(arn)`. |
| §3.6 S3 signature changes (renamed env, sanitize, pemBucketName) | Task 3 | `saveFullCertificate(commonName, targetRegion, ...)`, `sanitizePrefix`, `pemBucketName`. |
| §4.1 Account-key bucket unchanged (resource renamed) | Task 7 | `aws_s3_bucket.account_key` (renamed). |
| §4.2 Per-region PEM buckets (account-regional) | Task 7 | `for_each = local.pem_regions` with `bucket_namespace = "account-regional"`. |
| §4.3 Provider constraint bump | Task 5 | `~> 6.37`. |
| §5 IAM (S3AccountKey + dynamic S3PemWrite) | Task 8 | Dynamic statement guarded by `length(local.pem_regions) > 0`. |
| §6.1 Renew event shape (`common_name` filter) | Task 4 | Filter logic in `renewCertificates`. |
| §6.2 Yarn scripts unchanged + targeted-renew documented | Task 12 | README "Renew a single domain" section. |
| §6.3 Revoke uses ARN-derived region | Tasks 2, 4 | `regionFromArn` in `acm.js`; `getCertificate(arn)` consumed in `main.js`. |
| §7 Route53 placeholder per-domain (for_each + state mv) | Tasks 10, 14 | Code in Task 10; `terraform state mv` in Task 14 step 4. |
| §8 Renamed/removed/added Terraform variables | Task 6 | Full file content shows the new + renamed; removed ones explicitly absent. |
| §9 Renamed/removed/added Lambda env vars | Task 9 | New locals block in `lambda.tf`. |
| §10 ACME challenge target fix (`authz.identifier.value`) | Task 4 | `challengeCreateFn` body. |
| §11 Rollout (build, plan, halt for user review) | Task 14 | Full sequence with state-mv preservation. |
| §12 Acceptance criteria | Tasks 1–14 | All criteria mapped to verification commands within tasks. |
| §13 Manual verification (post-apply staging + production force-renew) | Task 14 step 6 | Surfaced commands for user. |
| §14 Accepted gaps | (n/a) | Explicitly NOT in plan — tests / CI / `ACME_EMAIL` / account-key-bucket migration / yarn revoke script. |
| **Foundation doc update (user-added requirement)** | Task 13 | §1, §2, §3, §4 edits. |

**Placeholder scan:** No "TBD" / "TODO" / "implement later". Every code block is concrete. The substituted backtick-blocks in Task 12 (escaped `\`\`\`bash`) are explicitly called out as embedding-only artifacts; the executing agent writes real triple-backticks.

**Type / symbol consistency:**
- Function signatures used in Task 4 (`findCertificate`, `importCertificate`, `getCertificate`, `loadAccountKey`, `saveFullCertificate`, `loadDomains`, `notify`, `createRoute53AcmeRecords`) match definitions in Tasks 1, 2, 3 exactly.
- Env-var names match across `lambda.tf` (Task 9), `s3.js` (Task 3), `main.js` (Task 4), `config.js` (Task 1), `acm.js` (Task 2): `DOMAINS_CONFIG`, `PEM_BUCKET_PREFIX`, `AWS_ACCOUNT_ID`, `ACCOUNT_KEY_BUCKET`, `ACCOUNT_KEY_NAME`, `REGION`, `TOPIC_ARN`, `TAG_APPLICATION`, `TAG_OWNER`, `DIRECTORY`, `ACME_EMAIL`.
- Terraform local `pem_regions` defined in `s3.tf` (Task 7) and consumed in `iam.tf` (Task 8) — same name, same type.
- Resource references: `aws_s3_bucket.account_key` (Task 7) consumed by `outputs.tf` (Task 11) and `iam.tf` (Task 8); `aws_s3_bucket.pem` (Task 7) consumed by `iam.tf` (Task 8).
- `var.domains` defined in `variables.tf` (Task 6); consumed in `s3.tf` (Task 7), `lambda.tf` (Task 9), `route53.tf` (Task 10).

**Spec-to-task gap check:** Every spec section has at least one task. The user's mid-stream addition ("update the foundation md accordingly") is covered by Task 13.
