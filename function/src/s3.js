import acme from 'acme-client';
import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';

import { getLogger } from './logger';

const {
  REGION: region,
  ACCOUNT_KEY_BUCKET: accountKeyBucket,
  ACCOUNT_KEY_NAME: accountKeyName,
  PEM_BUCKET_PREFIX: pemBucketPrefix,
  AWS_ACCOUNT_ID: awsAccountId,
  TAG_APPLICATION: tagApplication,
  TAG_OWNER: tagOwner,
} = process.env;

const logger = getLogger('s3');

const accountKeyClient = new S3Client({ region });

// Sanitize common name for use as S3 key prefix: '*' is not allowed in keys, replace with '_'.
const sanitizePrefix = (commonName) => commonName.replace('*', '_');

// Per-region PEM bucket naming convention: '<prefix>-<accountId>-<region>-an' (account-regional namespace).
const pemBucketName = (targetRegion) => `${pemBucketPrefix}-${awsAccountId}-${targetRegion}-an`;

export const loadAccountKey = async () => {
  try {
    const { Body: body } = await accountKeyClient.send(
      new GetObjectCommand({
        Bucket: accountKeyBucket,
        Key: accountKeyName,
      }),
    );
    logger.info(`Account Key loaded.`);
    const accountKey = await body.transformToByteArray();
    return Buffer.from(accountKey);
  } catch (e) {
    if (e.name === 'NoSuchKey') {
      logger.info(`Account Key not found.`);
      const privateKey = await acme.crypto.createPrivateKey();
      logger.info(`Account Key generated.`);
      await accountKeyClient.send(
        new PutObjectCommand({
          Bucket: accountKeyBucket,
          Key: accountKeyName,
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
