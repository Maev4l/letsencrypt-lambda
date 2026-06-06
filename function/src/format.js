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
