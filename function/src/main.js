import acme from 'acme-client';
import moment from 'moment';

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
} = process.env;

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

    const diff = moment(NotAfter).diff(moment(), 'days');

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

    const directoryUrl =
      directory === 'production'
        ? acme.directory.letsencrypt.production
        : acme.directory.letsencrypt.staging;

    const client = new acme.Client({
      directoryUrl,
      accountKey,
      backoffAttempts: 20,
    });

    try {
      const fullCertificate = await client.auto({
        csr: certificateCsr,
        email: 'maeval.nightingale@gmail.com',
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
    } catch (e) {
      const failureMessage = `Failed to renew certificate: ${e.toString()}.`;
      logger.error(failureMessage);
      await notify(failureMessage);
    }
  } else {
    logger.info('No need for certificate renewal.');
  }
};

export const revokeCertificate = async (event) => {
  const { arn, ...rest } = event;

  if (arn) {
    logger.info(`Revoking certificate (arn: ${arn})`);
    try {
      const accountKey = await loadAccountKey();

      const result = await getCertificate(arn);
      if (result) {
        const { certificate, ...other } = result;
        const { directory } = { ...other, ...rest };

        logger.info(`Directory: ${directory}`);

        const directoryUrl =
          directory === 'production'
            ? acme.directory.letsencrypt.production
            : acme.directory.letsencrypt.staging;

        const client = new acme.Client({
          directoryUrl,
          accountKey,
        });

        await client.createAccount({
          email: 'maeval.nightingale@gmail.com',
          termsOfServiceAgreed: true,
        });

        const accountUrl = client.getAccountUrl();
        logger.info(`Account url: ${accountUrl}`);

        const revokation = await client.revokeCertificate(certificate);
        logger.info(
          `Revoked (certificate: ${arn} - directory: ${directory}): ${JSON.stringify(revokation)}.`,
        );
      } else {
        logger.error(`Certificate with ARN ${arn} does not exists.`);
      }
    } catch (e) {
      logger.error(`Failed to revoke certificate (arn ${arn}): ${e.toString()}.`);
    }
  } else {
    logger.info(`No ARN was specfified.`);
  }
};
