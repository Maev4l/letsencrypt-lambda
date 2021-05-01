import acme from 'acme-client';
import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';
import {
  Route53Client,
  ListResourceRecordSetsCommand,
  ChangeResourceRecordSetsCommand,
  paginateListHostedZones,
} from '@aws-sdk/client-route-53';
import {
  ACMClient,
  ImportCertificateCommand,
  paginateListCertificates,
  DescribeCertificateCommand,
} from '@aws-sdk/client-acm';
import moment from 'moment';

import { getLogger } from './logger';
import config from '../config.json';

const logger = getLogger('handler');

const {
  route53DomainName,
  certificateCommonName,
  region,
  certificateRegion,
  bucketName,
  tagApplication,
  tagOwner,
  letsEncryptDirectory,
  s3LetsEncryptAccountKeyName,
} = config;

const s3 = new S3Client({ region });
const r53 = new Route53Client({ region });
const acm = new ACMClient({ region: certificateRegion });

const streamToBuffer = (stream) => {
  const chunks = [];
  return new Promise((resolve, reject) => {
    stream.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    stream.on('error', (err) => reject(err));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
  });
};

const loadAccountKey = async () => {
  try {
    const { Body: body } = await s3.send(
      new GetObjectCommand({
        Bucket: bucketName,
        Key: s3LetsEncryptAccountKeyName,
      }),
    );
    logger.info(`Account Key loaded.`);
    const accountKey = await streamToBuffer(body);
    return accountKey;
  } catch (e) {
    if (e.name === 'NoSuchKey') {
      logger.info(`Account Key not found.`);
      const privateKey = await acme.forge.createPrivateKey();
      logger.info(`Account Key generated.`);
      await s3.send(
        new PutObjectCommand({
          Bucket: bucketName,
          Key: s3LetsEncryptAccountKeyName,
          Body: privateKey,
          ServerSideEncryption: 'AES256',
          Tagging: `application=${tagApplication}&owner=${tagOwner}`,
        }),
      );
      logger.info(`Account Key saved.`);
      return privateKey;
    }

    logger.error(`Failed to load account key: ${e.name}.`);
    throw e;
  }
};

const resetRoute53AcmeRecords = async (zoneId, domain) => {
  const acmeName = domain.endsWith('.')
    ? `_acme-challenge.${domain}`
    : `_acme-challenge.${domain}.`;
  let recordsSet = [];
  let result = await r53.send(
    new ListResourceRecordSetsCommand({
      HostedZoneId: zoneId,
      StartRecordType: 'TXT',
      StartRecordName: acmeName,
      MaxItems: 100,
    }),
  );

  while (true) {
    const {
      ResourceRecordSets: resourceRecordsSet,
      IsTruncated: hasMore,
      NextRecordName: nextRecordName,
    } = result;

    recordsSet = [...recordsSet, ...resourceRecordsSet];
    if (!hasMore) {
      break;
    }

    result = await r53.send(
      new ListResourceRecordSetsCommand({
        HostedZoneId: zoneId,
        StartRecordType: 'TXT',
        StartRecordName: nextRecordName,
        MaxItems: 100,
      }),
    );
  }

  const recordSet = recordsSet.find((r) => {
    const { Name: name, Type: type } = r;
    return name === acmeName && type === 'TXT';
  });

  if (recordSet) {
    const { Name, Type, TTL, ResourceRecords } = recordSet;
    await r53.send(
      new ChangeResourceRecordSetsCommand({
        HostedZoneId: zoneId,
        ChangeBatch: {
          Changes: [
            {
              Action: 'DELETE',
              ResourceRecordSet: {
                Name,
                Type,
                TTL,
                ResourceRecords,
              },
            },
          ],
        },
      }),
    );

    logger.info(`Removed resource record '${acmeName}' from domain '${domain}'.`);
  } else {
    logger.info(`No resource record to remove from domain '${domain}'.`);
  }
};

const createRoute53AcmeRecords = async (zoneId, domain, challengeText) => {
  const acmeName = domain.endsWith('.')
    ? `_acme-challenge.${domain}`
    : `_acme-challenge.${domain}.`;

  await r53.send(
    new ChangeResourceRecordSetsCommand({
      HostedZoneId: zoneId,
      ChangeBatch: {
        Changes: [
          {
            Action: 'UPSERT',
            ResourceRecordSet: {
              Name: acmeName,
              Type: 'TXT',
              TTL: 60,
              ResourceRecords: [
                {
                  Value: `"${challengeText}"`,
                },
              ],
            },
          },
        ],
      },
    }),
  );

  logger.info(`Create verification record '${acmeName}' in domain '${domain}'.`);
};

const getZoneId = async (domain) => {
  const zoneName = domain.endsWith('.') ? domain : `${domain}.`;

  const paginatorConfig = {
    client: r53,
    pageSize: 25,
  };

  for await (const page of paginateListHostedZones(paginatorConfig, {})) {
    const { HostedZones: zones } = page;
    const zone = zones.find((z) => {
      const { Name: name } = z;
      return name === zoneName;
    });
    if (zone) {
      const { Id: zoneId } = zone;
      return zoneId.replace('/hostedzone/', '');
    }
  }

  return null;
};

const findCertificate = async (commonName) => {
  const paginatorConfig = {
    client: acm,
    pageSize: 25,
  };

  for await (const page of paginateListCertificates(paginatorConfig, {})) {
    const { CertificateSummaryList: summaries } = page;
    const certificates = summaries.filter((summary) => {
      const { DomainName: domainName } = summary;
      return commonName === domainName;
    });

    if (certificates.length > 0) {
      const certificateDetails = await Promise.all(
        certificates.map(async (c) => {
          const { CertificateArn } = c;
          const details = await acm.send(new DescribeCertificateCommand({ CertificateArn }));
          return details;
        }),
      );

      const certificate = certificateDetails.find((c) => {
        const {
          Certificate: { Type: type },
        } = c;
        return type === 'IMPORTED';
      });

      if (certificate) {
        const { Certificate } = certificate;
        const { CertificateArn } = Certificate;
        logger.info(
          `Found an existing certificate for common name '${commonName}': ${CertificateArn}.`,
        );
        return Certificate;
      }
    }
  }
  logger.info(`No existing certificate for common name '${commonName}'.`);
  return null;
};

const importCertificate = async (
  certificatePrivateKey,
  certificateChain,
  commonName,
  existingCertificate,
) => {
  // const existingCertificate = await findCertificate(commonName);

  let existingCertificateArn = null;
  if (existingCertificate) {
    const { CertificateArn } = existingCertificate;
    existingCertificateArn = CertificateArn;
  }

  const [certificate, ...rest] = certificateChain;

  const params = existingCertificateArn
    ? {
        CertificateArn: existingCertificateArn,
        Certificate: Buffer.from(certificate),
        CertificateChain: Buffer.from(rest.join()),
        PrivateKey: Buffer.from(certificatePrivateKey),
      }
    : {
        Certificate: Buffer.from(certificate),
        CertificateChain: Buffer.from(rest.join()),
        PrivateKey: Buffer.from(certificatePrivateKey),
        Tags: [
          { Key: 'application', Value: tagApplication },
          { Key: 'owner', Value: tagOwner },
        ],
      };
  const { CertificateArn } = await acm.send(new ImportCertificateCommand(params));
  logger.info(
    `Certificate ${CertificateArn} for common name '${commonName}' imported in region ${certificateRegion}.`,
  );
};

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
