import acme from 'acme-client';
import {
  ACMClient,
  ImportCertificateCommand,
  paginateListCertificates,
  DescribeCertificateCommand,
  GetCertificateCommand,
  ListTagsForCertificateCommand,
} from '@aws-sdk/client-acm';

import config from '../config.json';

import { getLogger } from './logger';

const logger = getLogger('acm');

const { certificateRegion, tagOwner, tagApplication, secondaryCertificateRegions } = config;

const readCertificate = async (client, arn) => {
  const { Certificate: certificate } = await client.send(
    new GetCertificateCommand({ CertificateArn: arn }),
  );
  return certificate;
};

const getCertificateDirectory = async (client, arn) => {
  const { Tags: tags } = await client.send(
    new ListTagsForCertificateCommand({ CertificateArn: arn }),
  );
  const tag = tags.find((t) => {
    const { Key: key } = t;
    return key === 'directory';
  });
  const { Value } = tag || {};
  return Value || 'production';
};

export const getCertificate = async (arn) => {
  try {
    const client = new ACMClient({ region: certificateRegion });
    const certificate = await readCertificate(client, arn);
    const directory = await getCertificateDirectory(client, arn);

    return { certificate, directory };
  } catch (e) {
    if (e.name === 'ResourceNotFoundException') {
      return null;
    }
    throw e;
  }
};

export const findCertificate = async (commonName, client) => {
  const acmClient = client || new ACMClient({ region: certificateRegion });
  const paginatorConfig = {
    client: acmClient,
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
          const details = await acmClient.send(new DescribeCertificateCommand({ CertificateArn }));
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

export const importCertificate = async (
  certificatePrivateKey,
  fullCertificate,
  commonName,
  directory,
) => {
  const regions = [certificateRegion, ...secondaryCertificateRegions];
  await Promise.all(
    regions.map(async (region) => {
      const client = new ACMClient({ region });
      const existingCertificate = await findCertificate(commonName, client);
      let existingCertificateArn = null;
      if (existingCertificate) {
        const { CertificateArn } = existingCertificate;
        existingCertificateArn = CertificateArn;
      }
      const [certificate, ...rest] = acme.crypto.splitPemChain(fullCertificate);
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
              { Key: 'directory', Value: directory },
            ],
          };
      const { CertificateArn } = await client.send(new ImportCertificateCommand(params));
      logger.info(
        `Certificate ${CertificateArn} for common name '${commonName}' imported in region ${certificateRegion}.`,
      );
    }),
  );
};
