import acme from 'acme-client';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';

import { getLogger } from './logger';

const {
  PEM_BUCKET_PREFIX: pemBucketPrefix,
  AWS_ACCOUNT_ID: awsAccountId,
  TAG_APPLICATION: tagApplication,
  TAG_OWNER: tagOwner,
} = process.env;

const logger = getLogger('s3');

// Sanitize common name for use as S3 key prefix: '*' is not allowed in keys, replace with '_'.
const sanitizePrefix = (commonName) => commonName.replace('*', '_');

// Per-region PEM bucket naming convention: '<prefix>-<accountId>-<region>-an' (account-regional namespace).
const pemBucketName = (targetRegion) => `${pemBucketPrefix}-${awsAccountId}-${targetRegion}-an`;

export const saveFullCertificate = async (commonName, targetRegion, fullCertificate, certificatePrivateKey) => {
  const bucket = pemBucketName(targetRegion);
  const prefix = sanitizePrefix(commonName);
  const s3 = new S3Client({ region: targetRegion });

  const saveObject = async (name, content) => {
    await s3.send(
      new PutObjectCommand({
        Bucket: bucket,
        Key: `${prefix}/${name}`,
        Body: content,
        ServerSideEncryption: 'AES256',
        Tagging: `application=${tagApplication}&owner=${tagOwner}`,
      }),
    );
  };

  const [certificate, intermediate, root] = acme.crypto.splitPemChain(fullCertificate);
  await Promise.all([
    saveObject('full', fullCertificate),
    saveObject('certificate', certificate),
    saveObject('intermediate', intermediate),
    saveObject('root', root),
    saveObject('certificateKey', certificatePrivateKey),
  ]);

  logger.info(`PEM saved for ${commonName} in ${targetRegion} (s3://${bucket}/${prefix}/).`);
};
