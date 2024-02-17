import acme from 'acme-client';
import { S3Client, GetObjectCommand, PutObjectCommand } from '@aws-sdk/client-s3';

import config from '../config.json';

import { getLogger } from './logger';

const { region, bucketName, tagApplication, tagOwner, s3LetsEncryptAccountKeyName } = config;

const logger = getLogger('s3');

const s3 = new S3Client({ region });

const streamToBuffer = (stream) => {
  const chunks = [];
  return new Promise((resolve, reject) => {
    stream.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
    stream.on('error', (err) => reject(err));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
  });
};

export const loadAccountKey = async () => {
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

const saveObject = async (name, content) =>
  new Promise((resolve) => {
    s3.send(
      new PutObjectCommand({
        Bucket: bucketName,
        Key: name,
        Body: content,
        ServerSideEncryption: 'AES256',
        Tagging: `application=${tagApplication}&owner=${tagOwner}`,
      }),
    ).then(() => resolve());
  });

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
