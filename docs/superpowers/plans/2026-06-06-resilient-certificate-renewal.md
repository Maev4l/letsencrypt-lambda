# Resilient Multi-Domain Certificate Renewal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Git note:** This repo's policy is *never commit automatically*. The commit steps below define task granularity; obtain the user's go-ahead before actually committing.

**Goal:** Replace the single sequential renewal loop with a fan-out dispatcher that async-invokes one renewal per domain, plus a dedicated handler that surfaces hard failures to Slack.

**Architecture:** A new `dispatch-certificate-renewals` Lambda reads the domain config and fires one asynchronous (`Event`) invoke of the existing `renew-certificates` worker per domain — so each cert gets its own full 180 s timeout and Lambda's built-in async retries. A new `handle-certificate-renewal-failure` Lambda is wired as the worker's async OnFailure destination and reshapes the failure record into a Slack message. The EventBridge scheduler retargets from the worker to the dispatcher.

**Tech Stack:** Node.js 22 ESM, AWS SDK v3 (`@aws-sdk/client-lambda`), esbuild (CJS bundle), Node built-in test runner (`node --test`), Terraform (`Maev4l/terraform-modules`), AWS Lambda async invocation destinations.

**Spec:** `docs/superpowers/specs/2026-06-06-resilient-certificate-renewal-design.md`

---

## File Structure

**Create:**
- `function/src/format.js` — pure, dependency-free helpers: `truncate`, `selectDispatchTargets`, `buildFailureMessage`. Isolated so they're unit-testable without loading AWS-client modules.
- `function/src/lambda.js` — wraps `@aws-sdk/client-lambda`; exports `invokeRenewal(commonName, directory, force)` (async `Event` invoke).
- `function/test/format.test.js` — `node --test` unit tests for `format.js`.

**Modify:**
- `function/src/main.js` — import `truncate`/`selectDispatchTargets`/`buildFailureMessage` from `./format`; reuse `selectDispatchTargets` in `renewCertificates`; add `dispatchRenewals` and `handleRenewalFailure` handlers.
- `function/esbuild.config.mjs` — add `@aws-sdk/client-lambda` to `external`.
- `function/package.json` — add `test` script; repoint `renew`/`renew:force` to the dispatcher.
- `infrastructure/iam.tf` — two scoped policies (dispatcher, failure handler) + `lambda:InvokeFunction` on the shared policy.
- `infrastructure/lambda.tf` — two new function modules, `event_invoke_config`, scheduler retarget, tailored env maps.
- `infrastructure/outputs.tf` — ARNs for the two new functions.
- `CLAUDE.md`, `README.md` — document the new architecture.

---

## Task 1: Pure helpers in `format.js` (TDD)

**Files:**
- Create: `function/src/format.js`
- Test: `function/test/format.test.js`

- [ ] **Step 1: Write the failing tests**

Create `function/test/format.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { truncate, selectDispatchTargets, buildFailureMessage } from '../src/format.js';

test('truncate leaves short strings unchanged', () => {
  assert.equal(truncate('short'), 'short');
});

test('truncate clips strings longer than 500 chars and appends an ellipsis', () => {
  const out = truncate('x'.repeat(600));
  assert.equal(out.length, 501); // 500 chars + '…'
  assert.ok(out.endsWith('…'));
});

test('selectDispatchTargets returns all domains when no filter is given', () => {
  const domains = [{ common_name: 'a' }, { common_name: 'b' }];
  assert.deepEqual(selectDispatchTargets(domains), domains);
});

test('selectDispatchTargets returns only the matching domain', () => {
  const domains = [{ common_name: 'a' }, { common_name: 'b' }];
  assert.deepEqual(selectDispatchTargets(domains, 'b'), [{ common_name: 'b' }]);
});

test('selectDispatchTargets throws on an unknown common_name', () => {
  assert.throws(
    () => selectDispatchTargets([{ common_name: 'a' }], 'zzz'),
    /Unknown common_name: zzz/,
  );
});

test('buildFailureMessage uses payload fields and the error message', () => {
  const record = {
    requestContext: { condition: 'RetriesExhausted', approximateInvokeCount: 3 },
    requestPayload: { common_name: '*.isnan.eu', directory: 'production' },
    responsePayload: { errorType: 'Error', errorMessage: 'boom' },
  };
  assert.match(
    buildFailureMessage(record),
    /CRASHED for '\*\.isnan\.eu' \(production\) after 3 attempt\(s\): boom\./,
  );
});

test('buildFailureMessage falls back to the condition when responsePayload is sparse', () => {
  const record = {
    requestContext: { condition: 'EventAgeExceeded' },
    requestPayload: { common_name: 'x.example', directory: 'staging' },
  };
  assert.match(
    buildFailureMessage(record),
    /CRASHED for 'x\.example' \(staging\) after \? attempt\(s\): EventAgeExceeded\./,
  );
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd function && node --test`
Expected: FAIL — `Cannot find module '../src/format.js'` (file does not exist yet).

- [ ] **Step 3: Implement `format.js`**

Create `function/src/format.js`:

```js
// Pure, dependency-free helpers. Kept free of relative/AWS imports so they can
// be unit-tested with `node --test` directly — the rest of src/ instantiates
// AWS SDK clients at module load, which we don't want to pull into unit tests.

// Truncate long error messages to fit Slack constraints (Slack chokes on very long lines).
export const truncate = (s) => (s && s.length > 500 ? `${s.slice(0, 500)}…` : s);

// Choose which configured domains to act on. Empty/absent filter selects all;
// a filter matching nothing is a caller error (same contract as the renew handler).
export const selectDispatchTargets = (domains, commonNameFilter) => {
  if (!commonNameFilter) return domains;
  const filtered = domains.filter((d) => d.common_name === commonNameFilter);
  if (filtered.length === 0) {
    throw new Error(`Unknown common_name: ${commonNameFilter}`);
  }
  return filtered;
};

// Reshape a Lambda async OnFailure invocation record into a Slack-ready line.
// Defensive: timeout/OOM crashes deliver a sparse responsePayload, so fall back
// errorMessage -> errorType -> the delivery condition.
export const buildFailureMessage = (record) => {
  const cn = record?.requestPayload?.common_name ?? 'unknown';
  const directory = record?.requestPayload?.directory ?? 'unknown';
  const condition = record?.requestContext?.condition ?? 'Failed';
  const attempts = record?.requestContext?.approximateInvokeCount ?? '?';
  const reason =
    record?.responsePayload?.errorMessage ??
    record?.responsePayload?.errorType ??
    condition;
  return `Certificate renewal CRASHED for '${cn}' (${directory}) after ${attempts} attempt(s): ${truncate(reason)}.`;
};
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd function && node --test`
Expected: PASS — 7 tests passing.

- [ ] **Step 5: Lint**

Run: `cd function && yarn lint`
Expected: no errors (lint scope is `src/`; `format.js` resolves cleanly, `test/` is not linted).

- [ ] **Step 6: Commit**

```bash
git add function/src/format.js function/test/format.test.js
git commit -m "feat: add pure renewal helpers (truncate, target selection, failure message)"
```

---

## Task 2: Lambda invoke wrapper `lambda.js`

**Files:**
- Create: `function/src/lambda.js`
- Modify: `function/esbuild.config.mjs`

- [ ] **Step 1: Implement `lambda.js`**

Create `function/src/lambda.js`:

```js
import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';

import { getLogger } from './logger';

const { REGION: region, RENEW_FUNCTION_NAME: renewFunctionName } = process.env;

const lambda = new LambdaClient({ region });

const logger = getLogger('lambda');

// Fire-and-forget async invoke (InvocationType 'Event') of the per-domain renew
// worker. Each domain thus gets its own full timeout plus Lambda's built-in
// async retries, instead of sharing one sequential invocation that can time out.
// Undefined directory/force are dropped by JSON.stringify; the renew handler
// applies its own defaults (DIRECTORY env, force=false).
export const invokeRenewal = async (commonName, directory, force) => {
  const payload = { common_name: commonName, directory, force };
  const command = new InvokeCommand({
    FunctionName: renewFunctionName,
    InvocationType: 'Event',
    Payload: Buffer.from(JSON.stringify(payload)),
  });
  await lambda.send(command);
  logger.info(`Dispatched renewal for '${commonName}'.`);
};
```

- [ ] **Step 2: Mark the new SDK client external in esbuild**

In `function/esbuild.config.mjs`, add `@aws-sdk/client-lambda` to the `external` array (it is provided by the Node 22 runtime, like the other clients):

```js
  external: [
    '@aws-sdk/client-acm',
    '@aws-sdk/client-lambda',
    '@aws-sdk/client-route-53',
    '@aws-sdk/client-s3',
    '@aws-sdk/client-sns',
    '@aws-sdk/client-ssm',
  ],
```

- [ ] **Step 3: Lint**

Run: `cd function && yarn lint`
Expected: no errors (`import/no-unresolved` ignores `^@aws-sdk/`, so the new client needs no package.json dependency).

- [ ] **Step 4: Build to confirm the bundle resolves and excludes the client**

Run: `cd function && yarn build`
Expected: `bin/main.js` produced with no errors. (Optional check: `grep -c "@aws-sdk/client-lambda" bin/main.js` returns a small number — only the `require` reference, not the bundled library.)

- [ ] **Step 5: Commit**

```bash
git add function/src/lambda.js function/esbuild.config.mjs
git commit -m "feat: add async Lambda invoke wrapper for per-domain renewal"
```

---

## Task 3: `dispatchRenewals` handler + reuse helper in `renewCertificates`

**Files:**
- Modify: `function/src/main.js`

- [ ] **Step 1: Update imports and remove the local `truncate`**

In `function/src/main.js`, replace the import block (lines 4–10) and delete the local `truncate` definition (line 26). New import block:

```js
import { getLogger } from './logger';
import { loadDomains } from './config';
import { importCertificate, findCertificate, getCertificate } from './acm';
import { loadAccountKey } from './ssm';
import { saveFullCertificate } from './s3';
import { createRoute53AcmeRecords } from './route53';
import { notify } from './sns';
import { invokeRenewal } from './lambda';
import { truncate, selectDispatchTargets, buildFailureMessage } from './format';
```

Then delete this now-duplicated line (formerly line 26):

```js
const truncate = (s) => (s && s.length > 500 ? `${s.slice(0, 500)}…` : s);
```

(`buildMessage` keeps using the imported `truncate` unchanged.)

- [ ] **Step 2: Reuse `selectDispatchTargets` in `renewCertificates`**

In `renewCertificates`, replace the inline filter + unknown-name throw (the block that builds `filtered` and throws `Unknown common_name`) with:

```js
  const allDomains = loadDomains();
  const filtered = selectDispatchTargets(allDomains, commonNameFilter);
```

(Removes the duplicated filtering logic; behavior is identical — unknown filter still throws `Unknown common_name: <value>`.)

- [ ] **Step 3: Add the `dispatchRenewals` handler**

Append to `function/src/main.js`:

```js
// Scheduler entry point. Reads the domain config and fans out one async invoke
// of the renew worker per domain, so each certificate gets its own full timeout
// and retry budget instead of sharing one sequential, timeout-prone invocation.
export const dispatchRenewals = async (event = {}) => {
  const { directory, force, common_name: commonNameFilter } = event;

  const allDomains = loadDomains();
  const targets = selectDispatchTargets(allDomains, commonNameFilter);

  logger.info(
    `Dispatching renewals for ${targets.length} domain(s)${
      commonNameFilter ? ` (filter: '${commonNameFilter}')` : ''
    }${force ? ' (force)' : ''}.`,
  );

  // Fire all invocations in parallel; each is fire-and-forget ('Event').
  await Promise.all(targets.map((d) => invokeRenewal(d.common_name, directory, force)));

  const dispatched = targets.map((d) => d.common_name);
  logger.info(`Dispatched ${dispatched.length} renewal invocation(s).`);
  return { statusCode: 200, dispatched };
};
```

- [ ] **Step 4: Lint**

Run: `cd function && yarn lint`
Expected: no errors.

- [ ] **Step 5: Build**

Run: `cd function && yarn build`
Expected: `bin/main.js` produced, no errors.

- [ ] **Step 6: Commit**

```bash
git add function/src/main.js
git commit -m "feat: add dispatchRenewals fan-out handler"
```

---

## Task 4: `handleRenewalFailure` handler

**Files:**
- Modify: `function/src/main.js`

- [ ] **Step 1: Add the handler**

Append to `function/src/main.js`:

```js
// Async OnFailure destination for renew-certificates. Runs only after Lambda's
// async auto-retries are exhausted — including timeout/OOM crashes that kill the
// renew handler before it can send its own SNS alert — so hard failures still
// reach Slack with the offending domain identified. Receives Lambda's invocation
// record, not the original event.
export const handleRenewalFailure = async (record) => {
  const message = buildFailureMessage(record);
  logger.error(message);
  await notify(message);
  return { statusCode: 200 };
};
```

- [ ] **Step 2: Lint**

Run: `cd function && yarn lint`
Expected: no errors.

- [ ] **Step 3: Build**

Run: `cd function && yarn build`
Expected: `bin/main.js` produced, no errors.

- [ ] **Step 4: Re-run unit tests (regression)**

Run: `cd function && node --test`
Expected: PASS — 7 tests still passing (`buildFailureMessage` unchanged).

- [ ] **Step 5: Commit**

```bash
git add function/src/main.js
git commit -m "feat: add handleRenewalFailure OnFailure destination handler"
```

---

## Task 5: package.json — test script + repoint manual-invoke shortcuts

**Files:**
- Modify: `function/package.json`

- [ ] **Step 1: Add a `test` script and repoint `renew`/`renew:force`**

In `function/package.json` `scripts`, add `test` and change the two `renew` scripts to target the dispatcher:

```json
  "scripts": {
    "clean": "rm -rf bin",
    "build": "yarn clean && mkdir -p bin && node esbuild.config.mjs",
    "package": "yarn build && cd bin && zip -r ../dist/lambda.zip .",
    "lint": "eslint src/",
    "lint:fix": "eslint src/ --fix",
    "test": "node --test",
    "renew": "aws lambda invoke --function-name dispatch-certificate-renewals /dev/stdout 2>/dev/null",
    "renew:force": "aws lambda invoke --function-name dispatch-certificate-renewals --cli-binary-format raw-in-base64-out --payload '{\"force\":true}' /dev/stdout 2>/dev/null"
  },
```

- [ ] **Step 2: Verify the test script works through yarn**

Run: `cd function && yarn test`
Expected: PASS — 7 tests passing.

- [ ] **Step 3: Commit**

```bash
git add function/package.json
git commit -m "chore: add test script and point renew shortcuts at the dispatcher"
```

---

## Task 6: IAM policies (`iam.tf`)

**Files:**
- Modify: `infrastructure/iam.tf`

- [ ] **Step 1: Grant the shared policy permission to deliver to the OnFailure destination**

In `infrastructure/iam.tf`, add a statement to `data.aws_iam_policy_document.lambda` (the shared `letsencrypt-lambda` policy attached to the worker). Lambda delivers to the destination using the *source* function's role, so the worker role needs invoke on the failure handler:

```hcl
  statement {
    sid       = "InvokeFailureHandler"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [module.handle_certificate_renewal_failure.function_arn]
  }
```

(Note: `revoke-certificate` shares this policy and thus also gains this permission — harmless, accepted for simplicity.)

- [ ] **Step 2: Add the dispatcher policy**

Append to `infrastructure/iam.tf`:

```hcl
# Dispatcher needs only to async-invoke the renew worker — no ACME/ACM/Route53/S3/SNS.
data "aws_iam_policy_document" "dispatcher" {
  statement {
    sid       = "InvokeRenewWorker"
    effect    = "Allow"
    actions   = ["lambda:InvokeFunction"]
    resources = [module.renew_certificates.function_arn]
  }
}

resource "aws_iam_policy" "dispatcher" {
  name   = "dispatch-certificate-renewals"
  policy = data.aws_iam_policy_document.dispatcher.json
}
```

- [ ] **Step 3: Add the failure-handler policy**

Append to `infrastructure/iam.tf`:

```hcl
# Failure handler needs only to publish to the alerting topic.
data "aws_iam_policy_document" "failure_handler" {
  statement {
    sid       = "SNSPublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [data.aws_sns_topic.alerting.arn]
  }
}

resource "aws_iam_policy" "failure_handler" {
  name   = "handle-certificate-renewal-failure"
  policy = data.aws_iam_policy_document.failure_handler.json
}
```

- [ ] **Step 4: Format**

Run: `terraform -chdir=infrastructure fmt`
Expected: files formatted (exit 0).

- [ ] **Step 5: Commit**

```bash
git add infrastructure/iam.tf
git commit -m "feat: add scoped IAM policies for dispatcher and failure handler"
```

---

## Task 7: Lambda functions, OnFailure wiring, scheduler retarget (`lambda.tf`)

**Files:**
- Modify: `infrastructure/lambda.tf`

- [ ] **Step 1: Add tailored env maps**

In `infrastructure/lambda.tf`, inside the existing `locals` block (after `lambda_environment_variables`), add:

```hcl
  # Dispatcher does no certificate work — only reads config and invokes the worker.
  dispatcher_environment_variables = {
    REGION              = var.region
    DOMAINS_CONFIG      = jsonencode(var.domains)
    RENEW_FUNCTION_NAME = module.renew_certificates.function_name
  }

  # Failure handler only publishes to the alerting topic.
  failure_handler_environment_variables = {
    REGION    = var.region
    TOPIC_ARN = var.topic_arn
  }
```

- [ ] **Step 2: Add the dispatcher function module**

Append to `infrastructure/lambda.tf`:

```hcl
# Lambda function: fan-out dispatcher (scheduler entry point)
module "dispatch_certificate_renewals" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.7.1"

  function_name = "dispatch-certificate-renewals"
  zip = {
    filename = local.lambda_zip_path
    runtime  = "nodejs22.x"
    handler  = "main.dispatchRenewals"
    hash     = filebase64sha256("../function/bin/main.js")
  }
  architecture           = "arm64"
  memory_size            = var.lambda_memory_size
  timeout                = var.lambda_timeout
  log_retention_in_days  = 7
  additional_policy_arns = [aws_iam_policy.dispatcher.arn]
  environment_variables  = local.dispatcher_environment_variables
}
```

- [ ] **Step 3: Add the failure-handler function module**

Append to `infrastructure/lambda.tf`:

```hcl
# Lambda function: OnFailure destination for renew-certificates
module "handle_certificate_renewal_failure" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-function?ref=v1.7.1"

  function_name = "handle-certificate-renewal-failure"
  zip = {
    filename = local.lambda_zip_path
    runtime  = "nodejs22.x"
    handler  = "main.handleRenewalFailure"
    hash     = filebase64sha256("../function/bin/main.js")
  }
  architecture           = "arm64"
  memory_size            = var.lambda_memory_size
  timeout                = var.lambda_timeout
  log_retention_in_days  = 7
  additional_policy_arns = [aws_iam_policy.failure_handler.arn]
  environment_variables  = local.failure_handler_environment_variables
}
```

- [ ] **Step 4: Wire the OnFailure destination on the worker**

Append to `infrastructure/lambda.tf`:

```hcl
# Route renew-certificates async failures (incl. timeout/OOM) to the failure
# handler after the 2 built-in async retries are exhausted.
resource "aws_lambda_function_event_invoke_config" "renew" {
  function_name                = module.renew_certificates.function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 3600

  destination_config {
    on_failure {
      destination = module.handle_certificate_renewal_failure.function_arn
    }
  }
}
```

- [ ] **Step 5: Retarget the scheduler to the dispatcher**

In `infrastructure/lambda.tf`, change `module.renew_certificates_scheduler` to point at the dispatcher:

```hcl
module "renew_certificates_scheduler" {
  source = "github.com/Maev4l/terraform-modules//modules/lambda-trigger-scheduler?ref=v1.7.1"

  function_name       = module.dispatch_certificate_renewals.function_name
  function_arn        = module.dispatch_certificate_renewals.function_arn
  schedule_name       = "renew-certificates-schedule"
  schedule_expression = var.schedule_rate
  description         = "Trigger certificate renewal dispatch"
}
```

- [ ] **Step 6: Format and validate**

Run: `terraform -chdir=infrastructure fmt`
Expected: exit 0.

Run: `terraform -chdir=infrastructure validate`
Expected: "Success! The configuration is valid." (If it errors with "provider not installed", run `terraform -chdir=infrastructure init -backend=false` first, then re-run validate.)

- [ ] **Step 7: Commit**

```bash
git add infrastructure/lambda.tf
git commit -m "feat: deploy dispatcher + failure handler, retarget scheduler"
```

---

## Task 8: Outputs (`outputs.tf`)

**Files:**
- Modify: `infrastructure/outputs.tf`

- [ ] **Step 1: Add ARNs for the two new functions**

Append to `infrastructure/outputs.tf`:

```hcl
output "lambda_dispatch_certificate_renewals_arn" {
  description = "ARN of the dispatch-certificate-renewals Lambda function"
  value       = module.dispatch_certificate_renewals.function_arn
}

output "lambda_handle_certificate_renewal_failure_arn" {
  description = "ARN of the handle-certificate-renewal-failure Lambda function"
  value       = module.handle_certificate_renewal_failure.function_arn
}
```

- [ ] **Step 2: Format and validate**

Run: `terraform -chdir=infrastructure fmt && terraform -chdir=infrastructure validate`
Expected: exit 0 / "Success! The configuration is valid."

- [ ] **Step 3: Commit**

```bash
git add infrastructure/outputs.tf
git commit -m "chore: output new Lambda function ARNs"
```

---

## Task 9: Documentation

**Files:**
- Modify: `CLAUDE.md`
- Modify: `README.md`

- [ ] **Step 1: Update `CLAUDE.md`**

Update `CLAUDE.md` to reflect the new architecture. Make these specific edits:

- **Repo layout (`function/src/` list):** add
  - `lambda.js` — `invokeRenewal()`: async ('Event') invoke of renew worker per domain.
  - `format.js` — pure helpers (truncate, selectDispatchTargets, buildFailureMessage); unit-tested.
- **Repo layout (`function/` list):** add `test/` — `node --test` unit tests for `format.js`.
- **Runtime architecture:** add a third handler section `dispatchRenewals (main.dispatchRenewals)` describing: scheduler entry point, `loadDomains()`, `selectDispatchTargets`, parallel async `Event` invokes via `invokeRenewal`, returns `{ statusCode: 200, dispatched }`. Add a fourth `handleRenewalFailure (main.handleRenewalFailure)` section: async OnFailure destination of `renew-certificates`, reshapes the invocation record via `buildFailureMessage`, publishes via `notify()`.
- **Triggers table:** change the `renew-certificates` row trigger to "Async invoke from `dispatch-certificate-renewals` (+ manual)"; add a `dispatch-certificate-renewals` row triggered by EventBridge Scheduler `rate(7 days)`; add a `handle-certificate-renewal-failure` row triggered by "renew-certificates async OnFailure destination".
- **Data flow diagram:** prepend `EventBridge Scheduler ─▶ dispatch-certificate-renewals ─(Event invoke ×N)─▶ renewCertificates`, and add `renewCertificates ─(OnFailure, retries exhausted)─▶ handleRenewalFailure ─▶ SNS`.
- **Environment variables table:** add `RENEW_FUNCTION_NAME` (source `module.renew_certificates.function_name`, consumer `lambda.js`, example `renew-certificates`). Note the dispatcher uses only `REGION`/`DOMAINS_CONFIG`/`RENEW_FUNCTION_NAME` and the failure handler only `REGION`/`TOPIC_ARN`.
- **Conventions (Terraform):** note `aws_lambda_function_event_invoke_config` wires the OnFailure destination and that delivery uses the worker's execution role (`lambda:InvokeFunction` on the failure handler).
- **Manual invoke shortcuts:** `yarn renew` / `yarn renew:force` now target `dispatch-certificate-renewals`.

- [ ] **Step 2: Update `README.md`**

Update `README.md` to describe the dispatcher/fan-out flow and the failure-handler path (replace any stale single-loop description).

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md README.md
git commit -m "docs: document fan-out dispatch and failure-handler architecture"
```

---

## Task 10: Full build + deploy verification

**Files:** none (verification only)

- [ ] **Step 1: Clean build + package + tests + lint**

Run: `cd function && yarn lint && yarn test && yarn package`
Expected: lint clean; 7 tests pass; `dist/lambda.zip` produced.

- [ ] **Step 2: Terraform plan**

Run: `terraform -chdir=infrastructure plan`
Expected: plan shows — 2 new `aws_lambda_function` (dispatcher, failure handler) + their roles/log groups/policies, 1 new `aws_lambda_function_event_invoke_config`, 2 new `aws_iam_policy`, 1 added statement on the shared policy, and the scheduler target changing from `renew-certificates` to `dispatch-certificate-renewals`. No destruction of `renew-certificates` or `revoke-certificate`.

- [ ] **Step 3: Apply (with user go-ahead)**

Run: `terraform -chdir=infrastructure apply`
Expected: apply completes; new functions exist.

- [ ] **Step 4: Functional smoke test — dispatch a single domain in staging**

Run:
```bash
aws lambda invoke --function-name dispatch-certificate-renewals \
  --cli-binary-format raw-in-base64-out \
  --payload '{"directory":"staging","common_name":"<one-configured-cn>"}' \
  /dev/stdout 2>/dev/null
```
Expected: response `{"statusCode":200,"dispatched":["<one-configured-cn>"]}`. Then confirm in CloudWatch Logs that `renew-certificates` was invoked for that domain, and a Slack message arrived for it.

- [ ] **Step 5: Failure-path check (optional, staging)**

Temporarily invoke `renew-certificates` with a bogus `common_name` to force the worker's `Unknown common_name` throw, let the 2 async retries exhaust, and confirm `handle-certificate-renewal-failure` posts a "CRASHED for 'unknown' …" Slack message. Revert any temporary change afterward.

---

## Self-Review

**Spec coverage:**
- Fan-out dispatcher (`dispatch-certificate-renewals`, `main.dispatchRenewals`) → Tasks 3, 7. ✔
- Async direct `Event` invoke reusing `{ common_name }` contract → Task 2 (`lambda.js`). ✔
- `function/src/lambda.js` wrapping `@aws-sdk/client-lambda`, marked external → Task 2. ✔
- `RENEW_FUNCTION_NAME` env var → Tasks 2, 7. ✔
- Failure handler (`handle-certificate-renewal-failure`, `main.handleRenewalFailure`) as OnFailure destination → Tasks 4, 7. ✔
- `event_invoke_config` + scheduler retarget → Task 7. ✔
- Two scoped IAM policies + `lambda:InvokeFunction` on shared policy → Task 6. ✔
- `package.json` shortcut repointing → Task 5. ✔
- Acyclic dependency note (failure handler ⟶ shared policy ⟶ renew ⟶ dispatcher policy ⟶ dispatcher) holds: Task 6/7 module references introduce no cycle. ✔
- Docs (CLAUDE.md, README.md) → Task 9. ✔

**Placeholder scan:** No TBD/TODO; every code step shows complete code; doc edits are itemized rather than "update docs". ✔

**Type/name consistency:** `selectDispatchTargets`, `buildFailureMessage`, `truncate`, `invokeRenewal`, `dispatchRenewals`, `handleRenewalFailure`, `RENEW_FUNCTION_NAME`, function names `dispatch-certificate-renewals` / `handle-certificate-renewal-failure`, module names `dispatch_certificate_renewals` / `handle_certificate_renewal_failure`, policy names matching — all used identically across tasks. ✔
