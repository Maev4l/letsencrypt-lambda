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

const { certificateRegion, tagOwner, tagApplication } = config;

const acm = new ACMClient({ region: certificateRegion });

const readCertificate = async (arn) => {
  const { Certificate: certificate } = await acm.send(
    new GetCertificateCommand({ CertificateArn: arn }),
  );
  return certificate;
};

const getCertificateDirectory = async (arn) => {
  const { Tags: tags } = await acm.send(new ListTagsForCertificateCommand({ CertificateArn: arn }));
  const tag = tags.find((t) => {
    const { Key: key } = t;
    return key === 'directory';
  });
  const { Value } = tag || {};
  return Value || 'production';
};

export const getCertificate = async (arn) => {
  try {
    const certificate = await readCertificate(arn);
    const directory = await getCertificateDirectory(arn);

    return { certificate, directory };
  } catch (e) {
    if (e.name === 'ResourceNotFoundException') {
      return null;
    }
    throw e;
  }
};

export const findCertificate = async (commonName) => {
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

export const importCertificate = async (
  certificatePrivateKey,
  fullCertificate,
  commonName,
  directory,
  existingCertificate,
) => {
  // const existingCertificate = await findCertificate(commonName);

  let existingCertificateArn = null;
  if (existingCertificate) {
    const { CertificateArn } = existingCertificate;
    existingCertificateArn = CertificateArn;
  }

  const [certificate, ...rest] = acme.forge.splitPemChain(fullCertificate);

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
  const { CertificateArn } = await acm.send(new ImportCertificateCommand(params));
  logger.info(
    `Certificate ${CertificateArn} for common name '${commonName}' imported in region ${certificateRegion}.`,
  );
};
