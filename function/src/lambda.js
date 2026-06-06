import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';

import { getLogger } from './logger';

const { REGION: region, RENEW_FUNCTION_NAME: renewFunctionName } = process.env;

const lambda = new LambdaClient({ region });

const logger = getLogger('lambda');

// Fire-and-forget async invoke (InvocationType 'Event') of the per-domain renew
// worker. Each domain thus gets its own full timeout plus Lambda's built-in
// async retries, instead of sharing one sequential invocation that can time out.
// Undefined directory/force are dropped by JSON.stringify; the renew handler
// applies its own defaults (DIRECTORY env, force=false).
export const invokeRenewal = async (commonName, directory, force) => {
  const payload = { common_name: commonName, directory, force };
  const command = new InvokeCommand({
    FunctionName: renewFunctionName,
    InvocationType: 'Event',
    Payload: Buffer.from(JSON.stringify(payload)),
  });
  try {
    await lambda.send(command);
    logger.info(`Dispatched renewal for '${commonName}'.`);
  } catch (e) {
    logger.error(`Failed to dispatch renewal for '${commonName}': ${e.message}`);
    throw e;
  }
};
