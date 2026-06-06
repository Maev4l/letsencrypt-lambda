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
    /CRASHED for 'y\.example' \(production\) after 2 attempt\(s\): Sandbox\.Timedout\./,
  );
});
