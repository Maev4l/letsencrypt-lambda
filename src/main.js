import acme from 'acme-client';

import moment from 'moment';

import { getLogger } from './logger';
import config from '../config.json';
import { importCertificate, findCertificate } from './acm';
import { loadAccountKey } from './s3';
import { getZoneId, createRoute53AcmeRecords, resetRoute53AcmeRecords } from './route53';

const logger = getLogger('handler');

const { route53DomainName, certificateCommonName, letsEncryptDirectory } = config;

export const renewCertificates = async (event) => {
  const { force, directory } = event;

  const stage = directory || letsEncryptDirectory;

  logger.info(
    `Certificate renewal (force: ${
      force ? 'true' : 'false'
    }) (domain: '${route53DomainName}' - common name: '${certificateCommonName}') (${stage}) started ...`,
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

    if (diff < 10) {
      // Certificate will expire in less than 10 days
      requestCertificate = true;
    }
  }

  if (requestCertificate || force) {
    const accountKey = await loadAccountKey();

    const [certificatePrivateKey, certificateCsr] = await acme.forge.createCsr({
      commonName: certificateCommonName,
    });

    logger.info(`Certificate Signing Request generated.`);

    const zoneId = await getZoneId(route53DomainName);
    if (zoneId) {
      logger.info(`Zone ID found for domain '${route53DomainName}': ${zoneId}.`);

      const directoryUrl =
        stage === 'production'
          ? acme.directory.letsencrypt.production
          : acme.directory.letsencrypt.staging;

      const client = new acme.Client({
        directoryUrl,
        accountKey,
      });

      try {
        const certificate = await client.auto({
          csr: certificateCsr,
          email: 'maeval.nightingale@gmail.com',
          termsOfServiceAgreed: true,
          challengePriority: ['dns-01'],
          challengeCreateFn: async (authz, challenge, keyAuthorization) => {
            await createRoute53AcmeRecords(zoneId, route53DomainName, keyAuthorization);
          },
          challengeRemoveFn: async (/* authz, challenge, keyAuthorization */) => {
            await resetRoute53AcmeRecords(zoneId, route53DomainName);
          },
        });

        const chain = acme.forge.splitPemChain(certificate);

        await importCertificate(
          certificatePrivateKey,
          chain,
          certificateCommonName,
          existingCertificate,
        );
        logger.info(`Certificate renewed/created (domain: '${route53DomainName}') (${stage}).`);
      } catch (e) {
        logger.error(`Failed to renew certificate: ${e.toString()}.`);
      }
    } else {
      logger.error(`No Zone ID for domain '${route53DomainName}.`);
    }
  } else {
    logger.info('No need for certificate renewal.');
  }
};
