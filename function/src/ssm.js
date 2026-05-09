import acme from 'acme-client';
import { SSMClient, GetParameterCommand, PutParameterCommand } from '@aws-sdk/client-ssm';

import { getLogger } from './logger';

const {
  REGION: region,
  ACCOUNT_KEY_PARAMETER: parameterName,
} = process.env;

const logger = getLogger('ssm');

const ssm = new SSMClient({ region });

export const loadAccountKey = async () => {
  try {
    const { Parameter } = await ssm.send(
      new GetParameterCommand({ Name: parameterName, WithDecryption: true }),
    );
    if (Parameter.Value && Parameter.Value.trim().length > 0) {
      logger.info(`Account Key loaded from SSM.`);
      return Buffer.from(Parameter.Value);
    }
    // Empty placeholder (Terraform-created with `value = " "` and ignore_changes).
    // Fall through to auto-generate path.
    logger.info(`Account Key parameter exists but is empty — generating fresh key.`);
  } catch (e) {
    if (e.name !== 'ParameterNotFound') {
      logger.error(`Failed to load account key: ${e.name}.`);
      throw e;
    }
    logger.info(`Account Key parameter not found — generating fresh key.`);
  }

  const privateKey = await acme.crypto.createPrivateKey();
  await ssm.send(
    new PutParameterCommand({
      Name: parameterName,
      Value: privateKey.toString(),
      Type: 'SecureString',
      Overwrite: true,
    }),
  );
  logger.info(`Account Key generated + saved to SSM.`);
  return privateKey;
};
