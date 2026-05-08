# letsencrypt-lambda — foundation reference

Fact-dense reference of the current state of this repo. Future
`/brainstorm` and `/plan` sessions should read this first. Not a
runbook, not narrative onboarding — terse facts only.

When the code drifts from this doc, update the doc and bump
`verified-against-commit`.

---

## 1. Purpose & scope

A single-purpose AWS Lambda (Node.js, ESM) that automates Let's Encrypt
certificate issuance, renewal, and revocation for a **list of domains**
(each with its own Route53 hosted zone, ACM destination regions, and
optional per-region PEM storage), using the **ACME DNS-01** challenge. Renewed certificates are
imported into AWS Certificate Manager in a primary region and replicated
to zero-or-more secondary regions. Renewal is triggered weekly by
EventBridge Scheduler; revocation is invoked manually.

**Non-goals.** The repo does NOT:

- Multi-account / cross-account renewal (single AWS account only).
- Support multiple AWS accounts (single-tenant).
- Use HTTP-01 or TLS-ALPN-01 challenges — DNS-01 only.
- Distribute certs to non-ACM consumers (no CloudFront/ELB/IoT wiring).
- Issue or manage client/intermediate certificates.
- Manage the SNS alerting topic (`alerting-events`) — it is consumed via
  data source and assumed to exist.
- Serve traffic — no API Gateway, no public HTTP endpoint.

---

## 2. Repo layout

```
letsencrypt-lambda/
├── README.md                     Stale (Serverless-era); see gaps doc.
├── package.json                  Root yarn scripts (no deps): backend:build, backend:deploy, infra:apply.
├── .prettierrc.js                trailingComma=all, printWidth=100, singleQuote.
├── .gitignore                    Ignores node_modules, dist/, bin/, .terraform/, *.tfstate*.
│
├── function/                     Lambda code package (the only npm package).
│   ├── package.json              Deps: acme-client@5.3.0, dayjs@1.11.13, winston@3.3.3 (strict pins).
│   ├── eslint.config.js          ESLint 9 flat config + prettier; ignores @aws-sdk/* for import/no-unresolved.
│   ├── esbuild.config.mjs        Bundle src/main.js → bin/main.js, CJS, node22, AWS SDK external.
│   ├── yarn.lock
│   ├── src/
│   │   ├── main.js               Two handlers: renewCertificates, revokeCertificate.
│   │   ├── config.js              loadDomains() — parse + validate DOMAINS_CONFIG on cold start.
│   │   ├── acm.js                ACM: findCertificate, importCertificate (multi-region), getCertificate (+ directory tag).
│   │   ├── route53.js            Route53: createRoute53AcmeRecords (UPSERT), resetRoute53AcmeRecords (UNUSED).
│   │   ├── s3.js                 S3: loadAccountKey (auto-creates), saveFullCertificate.
│   │   ├── sns.js                SNS: notify() — publishes JSON alert to alerting-events topic, target=slack.
│   │   └── logger.js             winston factory: getLogger(category) → singleton per category.
│   ├── bin/                      esbuild output (gitignored).
│   └── dist/                     lambda.zip (gitignored).
│
└── infrastructure/               Terraform root module.
    ├── main.tf                   Terraform >=1.10, AWS provider ~>6.0, S3 backend (use_lockfile=true), default_tags.
    ├── variables.tf              Inputs (region, domain_name, schedule_rate, lambda_memory_size, etc.).
    ├── outputs.tf                Lambda ARNs, S3 bucket name, IAM role ARN.
    ├── lambda.tf                 Two lambda-function modules + lambda-trigger-scheduler. ACME_EMAIL hardcoded here.
    ├── iam.tf                    aws_iam_policy 'letsencrypt-lambda': SNS + S3 + Route53 + ACM.
    ├── route53.tf                Placeholder _acme-challenge TXT record (ttl 60, value "dummy").
    ├── s3.tf                     Account-key bucket (legacy global namespace) + per-region PEM buckets (account-regional namespace) via for_each over var.domains.
    ├── templates/
    │   └── bucket-security-policy.json.tpl   Reusable bucket policy (deny non-TLS / non-SSE / public-ACL).
    └── sns.tf                    data "aws_sns_topic" "alerting" — references shared alerting-events topic.
```

---

## 3. Runtime architecture

Two handlers in one zip, two Lambda functions deployed.

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

### `revokeCertificate` (`main.revokeCertificate`)

**Event shape:** `{ arn: string, directory?: 'production' | 'staging' }`.

**Flow:**

1. If no `arn` → return `{ statusCode: 400, message: 'No ARN was specified' }`.
2. `loadAccountKey()` from S3.
3. `getCertificate(arn)` (derives region from the ARN via `arn.split(':')[3]`): returns `null` on
   `ResourceNotFoundException` → handler returns 404. Otherwise returns
   `{ certificate: PEM, directory: <tag value or 'production'> }`.
4. Final directory = event `directory` arg if present, else tag value.
5. `new acme.Client({ directoryUrl, accountKey })`, `createAccount({ email, termsOfServiceAgreed: true })` (idempotent).
6. `client.revokeCertificate(certificate)`.
7. Returns `{ statusCode: 200, message: 'Certificate <arn> revoked successfully' }`.

### Triggers

| Function             | Trigger                                                                                            |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| `renew-certificates` | EventBridge Scheduler `rate(7 days)` (schedule name `renew-certificates-schedule`); manual invoke. |
| `revoke-certificate` | Manual `aws lambda invoke` only (no scheduler, no event source).                                   |

Manual invoke shortcuts in `function/package.json`:

- `yarn renew` → `aws lambda invoke --function-name renew-certificates …`
- `yarn renew:force` → same with `--payload '{"force":true}'`

### Data flow

```
EventBridge Scheduler ── rate(7d) ──▶ renewCertificates
                                            │
                                            ├── ACM[primary]    ListCertificates / DescribeCertificate
                                            ├── S3              GetObject  account-key  (PutObject if absent)
                                            ├── acme-client     client.auto({ challengePriority: ['dns-01'] })
                                            │       │
                                            │       └── challengeCreateFn ──▶ Route53  ChangeResourceRecordSets
                                            │                                 (UPSERT TXT _acme-challenge.<zone>)
                                            ├── S3              PutObject × 5 per region (if pem_storage_regions configured)
                                            ├── ACM[acm_regions…]  ImportCertificate (parallel)
                                            └── SNS             Publish → alerting-events (target=slack)

aws lambda invoke ─▶ revokeCertificate
                            │
                            ├── S3   GetObject account-key
                            ├── ACM  GetCertificate + ListTagsForCertificate
                            └── ACME revokeCertificate
```

---

## 4. Environment variables

All env vars are set by Terraform from `infrastructure/lambda.tf` `local.lambda_environment_variables`. Both Lambda functions receive the same set.

| Name                 | Source                                                       | Consumer module(s)              | Example / default                                                                                                                     |
| -------------------- | ------------------------------------------------------------ | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `REGION`             | `var.region`                                                 | `route53.js`, `s3.js`, `sns.js` | `eu-central-1`                                                                                                                        |
| `DOMAINS_CONFIG`     | `jsonencode(var.domains)`                                    | `config.js`                     | `[{"common_name":"*.isnan.eu","hosted_zone_id":"ZWC66FN0XU6P9","acm_regions":["us-east-1","eu-central-1"],"pem_storage_regions":[]}]` |
| `PEM_BUCKET_PREFIX`  | `var.pem_bucket_prefix`                                      | `s3.js`                         | `letsencrypt-pems`                                                                                                                    |
| `AWS_ACCOUNT_ID`     | `data.aws_caller_identity.current.account_id`                | `s3.js`                         | `671123374425`                                                                                                                        |
| `ACCOUNT_KEY_BUCKET` | `var.account_key_bucket`                                     | `s3.js`                         | `letsencrypt-lambda-storage`                                                                                                          |
| `ACCOUNT_KEY_NAME`   | `var.s3_letsencrypt_account_key_name`                        | `s3.js`                         | `account-key`                                                                                                                         |
| `TOPIC_ARN`          | `var.topic_arn`                                              | `sns.js`                        | `arn:aws:sns:eu-central-1:671123374425:alerting-events`                                                                               |
| `TAG_APPLICATION`    | `var.tag_application`                                        | `acm.js`, `s3.js`               | `letsencrypt-lambda`                                                                                                                  |
| `TAG_OWNER`          | `var.tag_owner`                                              | `acm.js`, `s3.js`               | `terraform`                                                                                                                           |
| `DIRECTORY`          | `var.directory`                                              | `main.js`                       | `production` (or `staging`)                                                                                                           |
| `ACME_EMAIL`         | **Hardcoded in `infrastructure/lambda.tf`** (not a variable) | `main.js`                       | `maeval.nightingale@gmail.com` (accepted gap)                                                                                         |

Notes:

- `DOMAINS_CONFIG` is parsed once per cold start by `config.js#loadDomains()`. Each entry validates `common_name`, `hosted_zone_id`, non-empty `acm_regions`, optional `pem_storage_regions` (default `[]`), and uniqueness of `common_name`.
- `DIRECTORY` is the runtime default; the renew event payload can override it per-invocation.
- `event.common_name` (renew event) filters to a single configured domain; absent / empty = process all.
- `ACME_EMAIL` is the only value not exposed as a Terraform variable.

---

## 7. Conventions

### JavaScript

- **ESM only.** `function/package.json` has `"type": "module"`. No TypeScript.
- **Fat arrows** for all functions, including exported handlers
  (`export const renewCertificates = async (event) => …`).
- **Strict semver pinning** in `function/package.json` — exact versions,
  no `^` / `~` (e.g. `"acme-client": "5.3.0"`).
- **Date math via `dayjs`** only — never `moment`.
- **Yarn** (not npm). Yarn workspaces are NOT used (single package under
  `function/`); root `package.json` has no `dependencies` and just shells
  out to `yarn --cwd function`.
- **Logger:** `winston` with category labels per module —
  `getLogger('handler')`, `getLogger('acm')`, `getLogger('route53')`,
  `getLogger('s3')`, `getLogger('sns')`. One logger per module, created
  at module load.
- **Module ↔ AWS service**: each `src/<service>.js` wraps exactly one
  AWS service (`acm.js`, `route53.js`, `s3.js`, `sns.js`).
- **AWS SDK v3** clients are imported per service from `@aws-sdk/client-*`.
  Each module instantiates its own client at module scope. Region comes
  from `REGION` env, except `acm.js` which constructs per-region
  `ACMClient` instances from the region arguments passed by callers,
  and `s3.js#saveFullCertificate` which constructs a per-call
  `S3Client` for the target PEM-storage region.
- **Tagging** of S3 objects and ACM certs uses `TAG_APPLICATION` /
  `TAG_OWNER` env vars; ACM cert also carries a `directory` tag used by
  the revoke handler to pick the right LE directory.

### Terraform

- **Custom modules** from `github.com/Maev4l/terraform-modules`, pinned
  by ref:
  - `modules/lambda-function` — manages role, log group, function (one
    instance per Lambda).
  - `modules/lambda-trigger-scheduler` — EventBridge Scheduler trigger.
- **Lambda architecture:** `arm64` (Graviton). Memory 128 MB, timeout 180 s.
- **Log retention:** 7 days.
- **Deployment style:** **zip-based** (not Docker). The zip is built
  locally (`yarn package`) before `terraform apply`. The Docker / ECR
  guidance in the global CLAUDE.md does NOT apply here.
- **S3 bucket:** `force_destroy = true` (per global rules). SSE-AES256
  enforced. Public access fully blocked. Bucket policy denies
  unencrypted PUT, non-AES256/KMS encryption, non-TLS access, and
  public-read ACL grants.
- **ACM:** certificates imported into the regions listed in each
  domain's `acm_regions` (primary first, then secondaries). Existing
  cert ARN is reused per-region when the domain matches (in-place
  renewal — same ARN, no consumer churn).
- **IAM:** scoped where API allows — S3 actions on bucket ARN + objects,
  SNS `Publish` on the alerting topic ARN. Route53 and ACM use `*`
  (action-level only). Single `aws_iam_policy` `letsencrypt-lambda`
  attached to both functions via `additional_policy_arns`.
- **Backend:** S3 with `use_lockfile = true` (S3 native locking, no
  DynamoDB).
- **Versions:** Terraform `>= 1.10.0`, AWS provider `~> 6.37` (≥ 6.37
  required for S3 account-regional namespaces).
- **Default tags** applied at provider level: `application = letsencrypt-lambda`,
  `owner = terraform` — supplemented per-resource where the global Lambda
  module needs explicit tagging.

### Build & packaging

- **esbuild** bundles `function/src/main.js` → `function/bin/main.js`,
  format **CJS**, target `node22`, minified.
- **`@aws-sdk/client-{acm,route-53,s3,sns}`** marked `external` in the
  esbuild config — provided by the Lambda Node.js 22 runtime, not
  bundled.
- **Lambda zip** built by `yarn package` (clean → build → `zip -r dist/lambda.zip .`
  from `bin/`). The zip contains a single bundled `main.js`.
- **ESLint 9 flat config** + `eslint-config-prettier`; relaxes
  `import/prefer-default-export`, `no-console`, `no-restricted-syntax`,
  `no-await-in-loop`, `no-constant-condition`. `import/no-unresolved`
  ignores `^@aws-sdk/`. `import/no-extraneous-dependencies` allows
  devDependencies in `*.config.js` / `*.config.mjs`.
- **Build hash** for Lambda code change detection: `filebase64sha256("../function/bin/main.js")`
  passed as `zip.hash` to the lambda-function module — the bundled JS
  drives diff detection, not the zip itself. **Why:** `dist/lambda.zip`
  hashes are NOT stable — zip metadata (file timestamps, entry ordering)
  changes between builds even when the bundled JS is identical. Hashing
  `bin/main.js` (esbuild's stable output) is the only reliable
  change-detection signal.
