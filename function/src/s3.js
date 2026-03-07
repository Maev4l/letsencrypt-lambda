import acme from 'acme-client';
import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';

import { getLogger } from './logger';

const {
  REGION: region,
  BUCKET_NAME: bucketName,
  TAG_APPLICATION: tagApplication,
  TAG_OWNER: tagOwner,
  S3_LETSENCRYPT_ACCOUNT_KEY_NAME: s3LetsEncryptAccountKeyName,
} = process.env;

const logger = getLogger('s3');

const s3 = new S3Client({ region });

export const loadAccountKey = async () => {
  try {
    const { Body: body } = await s3.send(
      new GetObjectCommand({
        Bucket: bucketName,
        Key: s3LetsEncryptAccountKeyName,
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

const saveObject = async (name, content) => {
  await s3.send(
    new PutObjectCommand({
      Bucket: bucketName,
      Key: name,
      Body: content,
      ServerSideEncryption: 'AES256',
      Tagging: `application=${tagApplication}&owner=${tagOwner}`,
    }),
  );
};

export const saveFullCertificate = async (fullCertificate, certificatePrivateKey) => {
  const [certificate, intermediate, root] = acme.crypto.splitPemChain(fullCertificate);
  await Promise.all([
    saveObject('full', fullCertificate),
    saveObject('certificate', certificate),
    saveObject('intermediate', intermediate),
    saveObject('root', root),
    saveObject('certificateKey', certificatePrivateKey),
  ]);
};
