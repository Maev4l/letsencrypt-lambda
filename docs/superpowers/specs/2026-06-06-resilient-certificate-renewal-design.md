# Resilient multi-domain certificate renewal — design

Date: 2026-06-06
Status: Approved (pending spec review)

## 1. Problem

`renewCertificates` iterates domains **sequentially** in one Lambda invocation
(`function/src/main.js:128`), bounded by a **180 s** timeout
(`infrastructure/variables.tf:60`). The slow part is `client.auto()` per domain
(DNS-01: write TXT, wait for Route53 propagation, ACME polling) — 30–90 s per
cert that actually renews.

On timeout the whole invocation is killed: already-imported certs survive, the
in-flight domain is abandoned (its `_acme-challenge` TXT may be left behind), and
**all remaining domains never run** — with no aggregate error and no SNS summary
for the un-reached domains (only a CloudWatch timeout metric).

A built-in self-healing exists (renew-if-`<30 days` + weekly schedule + skip of
already-fresh certs), but at the target scale of **5–30 domains** a single run
can renew only 1–3 before timing out, so convergence across weeks is not
guaranteed and each timeout is partly silent.

## 2. Goals / non-goals

**Goals**
- Each certificate gets its own full time budget — one domain's slow/failed
  renewal can never starve another (no head-of-line blocking).
- Scale cleanly to 5–30 domains (and beyond) on the existing weekly schedule.
- Hard failures (including timeout/OOM that crash before the handler's own SNS
  notify) are surfaced to Slack, with the failing domain identified.

**Non-goals**
- No change to ACME / ACM / Route53 / S3 renewal logic itself.
- No SQS main-flow queue, no Step Functions, no cross-account work.
- No change to the `revokeCertificate` handler.

## 3. Approach: fan-out dispatch + dedicated failure handler

Chosen over (a) in-function time-aware self-continuation — rejected for keeping
the slow sequential chain and risking self-invoke loops — and (b) SQS-based
dispatch — rejected as over-engineered for weekly renewal of ~30 domains.

### Topology

```
EventBridge Scheduler ─rate(7d)─▶ dispatch-certificate-renewals
                                       │  loadDomains()
                                       │  per domain: Lambda Invoke (Event)
                  ┌────────────────────┼────────────────────┐
                  ▼                     ▼                     ▼
        renew-certificates    renew-certificates    renew-certificates
        {common_name: A}      {common_name: B}      {common_name: …}
        (full 180s each)
                  │ fails all async retries (RetriesExhausted / timeout / OOM)
                  ▼  [OnFailure destination]
        handle-certificate-renewal-failure
                  │ parse invocation record → notify()
                  ▼
        alerting-events (Slack)
```

The dispatch is a **one-level fan, not a chain** — worker invocations invoke
nothing, so there is no cycle and no infinite-loop risk. The two new functions
are **separate** from the worker, making the no-loop property architectural.

### Why async direct invoke (not SNS / not sync)

- **Async `Event` invoke** reuses the existing `{ common_name }` event contract
  verbatim — `renewSingleDomain` and the `common_name` filter are untouched.
- Provides Lambda's built-in **2 automatic async retries** per domain for free
  (today a mid-loop failure gets no retry until next week).
- SNS fan-out would add a topic + subscription and wrap the event in an
  `Records[].Sns.Message` envelope (breaking the clean contract) for **no**
  decoupling benefit — there is only one consumer.
- Sync `RequestResponse` would block the dispatcher and lose auto-retry.

## 4. Components

### 4.1 `dispatch-certificate-renewals` (new function, handler `main.dispatchRenewals`)

Same zip as the existing functions; does **no** ACME/ACM/Route53/S3/SNS work.

Event shape (forwarded verbatim): `{ directory?, force?, common_name? }`.

Flow:
1. `loadDomains()` (reuses cold-start cache).
2. If `event.common_name` present → dispatch just that one (preserves the
   single-domain manual path); unknown `common_name` → throw, as today.
   Otherwise → dispatch all.
3. Per target domain: `InvokeCommand` with `InvocationType: 'Event'`, payload
   `{ common_name, directory, force }` (passes `directory`/`force` through).
4. Return `{ statusCode: 200, dispatched: [...commonNames] }`. Fire-and-forget;
   does not wait on worker results.

New env var: `RENEW_FUNCTION_NAME` (= `renew-certificates`) so the dispatcher
knows what to invoke. Reuses `REGION` for the `LambdaClient`.

New module file: `function/src/lambda.js` wrapping `@aws-sdk/client-lambda`
(one-module-per-AWS-service convention), exporting `invokeRenewal(commonName,
directory, force)`. Mark `@aws-sdk/client-lambda` external in
`esbuild.config.mjs` (runtime-provided).

### 4.2 `handle-certificate-renewal-failure` (new function, handler `main.handleRenewalFailure`)

Wired as `renew-certificates`' async OnFailure destination. Runs only after the
2 async retries are exhausted (so not on transient blips).

Receives the Lambda **invocation record** (not the original event):

```jsonc
{
  "requestContext": { "condition": "RetriesExhausted", "approximateInvokeCount": 3,
                      "functionArn": "...:renew-certificates" },
  "requestPayload":  { "common_name": "...", "directory": "...", "force": false },
  "responsePayload": { "errorType": "...", "errorMessage": "..." }  // sparse on timeout/OOM
}
```

Handler (defensive — timeout/OOM give a thin `responsePayload`):

```js
export const handleRenewalFailure = async (record) => {
  const cn        = record?.requestPayload?.common_name ?? 'unknown';
  const directory = record?.requestPayload?.directory ?? 'unknown';
  const condition = record?.requestContext?.condition ?? 'Failed';
  const reason    = record?.responsePayload?.errorMessage
                 ?? record?.responsePayload?.errorType
                 ?? condition;
  await notify(
    `Certificate renewal CRASHED for '${cn}' (${directory}) after ${
      record?.requestContext?.approximateInvokeCount ?? '?'
    } attempt(s): ${truncate(reason)}.`,
  );
  return { statusCode: 200 };
};
```

Reuses `notify()` from `sns.js` and `truncate()` from `main.js` (export
`truncate` so both handlers share one definition). Needs `REGION` + `TOPIC_ARN`.

### 4.3 `renew-certificates` (existing — no logic change)

Already supports `common_name` filtering and already calls `notify()` per domain
(including on failure) before the aggregate `throw`. Now invoked one domain per
call. The existing `throw` on failure is what triggers the async auto-retry and,
ultimately, the OnFailure destination.

## 5. Terraform changes (`infrastructure/`)

`lambda.tf`:
- Add module `dispatch_certificate_renewals` → function `dispatch-certificate-renewals`,
  `handler = "main.dispatchRenewals"`, same zip + `hash = filebase64sha256("../function/bin/main.js")`,
  `additional_policy_arns = [aws_iam_policy.dispatcher.arn]`, env includes
  `RENEW_FUNCTION_NAME = module.renew_certificates.function_name`.
- Add module `handle_certificate_renewal_failure` → function
  `handle-certificate-renewal-failure`, `handler = "main.handleRenewalFailure"`,
  same zip + hash, `additional_policy_arns = [aws_iam_policy.failure_handler.arn]`,
  env = `REGION` + `TOPIC_ARN`.
- Add `aws_lambda_function_event_invoke_config` on `renew-certificates`:
  `maximum_retry_attempts = 2`, `on_failure.destination =
  module.handle_certificate_renewal_failure.function_arn`.
- **Retarget the scheduler** (`module.renew_certificates_scheduler`) from
  `renew-certificates` to `dispatch-certificate-renewals`
  (`function_name`/`function_arn` now reference the dispatcher).

`iam.tf`:
- New `aws_iam_policy.dispatcher`: single statement `lambda:InvokeFunction` on
  `module.renew_certificates.function_arn`.
- New `aws_iam_policy.failure_handler`: single statement `sns:Publish` on
  `data.aws_sns_topic.alerting.arn`.
- Add `lambda:InvokeFunction` on
  `module.handle_certificate_renewal_failure.function_arn` to the shared
  `letsencrypt-lambda` policy (so `renew-certificates`' role can deliver to its
  OnFailure destination). Note: `revoke-certificate` shares this policy and thus
  also gains this permission — harmless, accepted for simplicity.

No `aws_lambda_permission` (resource policy) on the new functions: the scheduler
trigger module already manages the dispatcher's invoke permission, and Lambda
destination delivery is identity-based via the source role.

Dependency graph is acyclic: `failure_handler` policy → failure-handler module →
shared policy (refs failure-handler ARN) → renew module / event_invoke_config;
dispatcher policy (refs renew ARN) → dispatcher module → scheduler.

## 6. Manual-invoke shortcuts (`function/package.json`)

- `yarn renew` → invoke `dispatch-certificate-renewals` (all domains).
- `yarn renew:force` → invoke `dispatch-certificate-renewals` with `{"force":true}`.
- Single-domain manual renew remains possible by invoking either
  `dispatch-certificate-renewals` or `renew-certificates` directly with
  `{"common_name":"..."}`.

## 7. Build

- `esbuild.config.mjs`: mark `@aws-sdk/client-lambda` external (new dependency
  used by the dispatcher; runtime-provided like the other AWS SDK clients).
- No change to bundling/packaging flow; all three handlers ship in the one zip.

## 8. Observability after this change

- Per-domain success/skip/failure → Slack via the existing `notify()` in
  `renew-certificates` (unchanged).
- Hard crashes (timeout/OOM, or failure after retries) → Slack via
  `handle-certificate-renewal-failure`, identifying the domain.
- Each domain has its own CloudWatch log stream and `Errors` metric data point.

## 9. Docs to update during implementation

- `CLAUDE.md`: add the two new handlers/functions, the new
  `function/src/lambda.js` module, the OnFailure wiring, the scheduler retarget,
  and the new env var `RENEW_FUNCTION_NAME`.
- `README.md`: dispatch/fan-out flow.

## 10. Open questions

None outstanding — dispatcher name (`dispatch-certificate-renewals`), failure
handler name (`handle-certificate-renewal-failure`), async-direct-invoke
mechanism, and 4th-handler failure visibility are all locked.
