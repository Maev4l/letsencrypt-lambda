import acme from 'acme-client';
import dayjs from 'dayjs';

import { getLogger } from './logger';
import { importCertificate, findCertificate, getCertificate } from './acm';
import { loadAccountKey, saveFullCertificate } from './s3';
import { createRoute53AcmeRecords } from './route53';
import { notify } from './sns';

const logger = getLogger('handler');

const {
  DOMAIN_HOSTED_ZONE_NAME: domainZoneName,
  DOMAIN_CERTIFICATE_COMMON_NAME: certificateCommonName,
  DOMAIN_HOSTED_ZONE_ID: domainZoneId,
  DIRECTORY: defaultDirectory,
  ACME_EMAIL: acmeEmail,
} = process.env;

// Returns the Let's Encrypt directory URL based on environment
const getDirectoryUrl = (directory) =>
  directory === 'production'
    ? acme.directory.letsencrypt.production
    : acme.directory.letsencrypt.staging;

export const renewCertificates = async (event) => {
  const { directory = defaultDirectory, force } = event || {};

  logger.info(
    `Certificate renewal (force: ${
      force ? 'yes' : 'no'
    }) (domain: '${domainZoneName}' - common name: '${certificateCommonName}') (${directory}) started ...`,
  );

  let requestCertificate = false;

  const existingCertificate = await findCertificate(certificateCommonName);
  if (!existingCertificate) {
    requestCertificate = true;
  } else {
    const { NotAfter } = existingCertificate;

    const diff = dayjs(NotAfter).diff(dayjs(), 'day');

    if (diff >= 0) {
      logger.info(`Existing certificate will expire in ${diff} day(s).`);
    } else {
      logger.info(`Existing certificate expired since ${Math.abs(diff)} day(s).`);
    }

    if (diff < 30) {
      // Certificate will expire in less than 30 days
      requestCertificate = true;
    }
  }

  if (requestCertificate || force) {
    const accountKey = await loadAccountKey();

    const [certificatePrivateKey, certificateCsr] = await acme.crypto.createCsr({
      commonName: certificateCommonName,
    });

    logger.info(`Certificate Signing Request generated.`);

    const client = new acme.Client({
      directoryUrl: getDirectoryUrl(directory),
      accountKey,
      backoffAttempts: 20,
    });

    const fullCertificate = await client.auto({
      csr: certificateCsr,
      email: acmeEmail,
      termsOfServiceAgreed: true,
      challengePriority: ['dns-01'],
      challengeCreateFn: async (authz, challenge, keyAuthorization) => {
        await createRoute53AcmeRecords(domainZoneId, domainZoneName, keyAuthorization);
      },
    });

    logger.info(`Account url: ${client.getAccountUrl()}`);

    await saveFullCertificate(fullCertificate, certificatePrivateKey);
    logger.info(`Certificate saved (domain: '${domainZoneName}') (${directory}).`);

    await importCertificate(
      certificatePrivateKey,
      fullCertificate,
      certificateCommonName,
      directory,
    );
    const successMessage = `Certificate renewed/created (domain: '${domainZoneName}') (${directory}).`;
    logger.info(successMessage);

    await notify(successMessage);

    return { statusCode: 200, message: successMessage };
  }

  return { statusCode: 200, message: 'No certificate renewal needed' };
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
