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
