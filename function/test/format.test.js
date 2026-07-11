import { test } from 'node:test';
import assert from 'node:assert/strict';

import { truncate, code, buildAlert, selectDispatchTargets, buildFailureMessage } from '../src/format.js';

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
  const out = buildFailureMessage(record);
  assert.match(out, /^# 🔐 Certificate Renewal\n/);
  assert.match(out, /- \*\*Domain:\*\* `\*\.isnan\.eu`/);
  assert.match(out, /- \*\*Directory:\*\* production/);
  assert.match(out, /- \*\*Status:\*\* renewal CRASHED after 3 attempt\(s\) — `boom`/);
});

test('buildFailureMessage falls back to the condition when responsePayload is sparse', () => {
  const record = {
    requestContext: { condition: 'EventAgeExceeded' },
    requestPayload: { common_name: 'x.example', directory: 'staging' },
  };
  const out = buildFailureMessage(record);
  assert.match(out, /- \*\*Domain:\*\* `x\.example`/);
  assert.match(out, /- \*\*Directory:\*\* staging/);
  assert.match(out, /- \*\*Status:\*\* renewal CRASHED after \? attempt\(s\) — `EventAgeExceeded`/);
});

test('buildAlert renders the shared header and bold-label bullets', () => {
  assert.equal(
    buildAlert('*.isnan.eu', 'production', 'renewed'),
    '# 🔐 Certificate Renewal\n\n- **Domain:** `*.isnan.eu`\n- **Directory:** production\n- **Status:** renewed',
  );
});

// A bare hostname like brigitte-le-roux.com is a live website; left as plain
// text, Slack linkifies + unfurls it and pastes the site's meta description into
// the alert. Fencing the domain as inline code stops Slack touching it.
test('buildAlert fences the domain so Slack does not unfurl bare hostnames', () => {
  assert.match(buildAlert('brigitte-le-roux.com', 'production', 'renewed'), /`brigitte-le-roux\.com`/);
});

test('code fences text and neutralizes embedded backticks', () => {
  assert.equal(code('boom'), '`boom`');
  assert.equal(code('a `b` c'), "`a 'b' c`");
  assert.equal(code(null), '``');
});

test('truncate returns falsy inputs unchanged', () => {
  assert.equal(truncate(null), null);
  assert.equal(truncate(undefined), undefined);
  assert.equal(truncate(''), '');
});

test('truncate leaves a string of exactly 500 chars unchanged', () => {
  assert.equal(truncate('x'.repeat(500)), 'x'.repeat(500));
});

test('buildFailureMessage falls back to errorType when errorMessage is absent', () => {
  const record = {
    responsePayload: { errorType: 'Sandbox.Timedout' },
    requestPayload: { common_name: 'y.example', directory: 'production' },
    requestContext: { condition: 'RetriesExhausted', approximateInvokeCount: 2 },
  };
  assert.match(
    buildFailureMessage(record),
    /- \*\*Status:\*\* renewal CRASHED after 2 attempt\(s\) — `Sandbox\.Timedout`/,
  );
});
