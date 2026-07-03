// Pure, dependency-free helpers. Kept free of relative/AWS imports so they can
// be unit-tested with `node --test` directly — the rest of src/ instantiates
// AWS SDK clients at module load, which we don't want to pull into unit tests.

// Truncate long error messages to fit Slack constraints (Slack chokes on very long lines).
export const truncate = (s) => (s && s.length > 500 ? `${s.slice(0, 500)}…` : s);

// Wrap arbitrary text as Markdown inline code. The alerter now renders our
// messages as Markdown, so unpredictable ACME/AWS error strings (which routinely
// contain *, _, or `) must be fenced or they get mis-parsed as emphasis/code.
// A backtick inside the text would prematurely close the span, so neutralize it.
export const code = (s) => `\`${String(s ?? '').replace(/`/g, "'")}\``;

// Assemble the shared Markdown alert shape (H1 header + bold-label bullets) used
// by every certificate notification, so producers only supply the status line.
export const buildAlert = (commonName, directory, status) =>
  [
    '# 🔐 Certificate Renewal',
    '',
    `- **Domain:** ${commonName}`,
    `- **Directory:** ${directory}`,
    `- **Status:** ${status}`,
  ].join('\n');

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
  return buildAlert(
    cn,
    directory,
    `renewal CRASHED after ${attempts} attempt(s) — ${code(truncate(reason))}`,
  );
};
