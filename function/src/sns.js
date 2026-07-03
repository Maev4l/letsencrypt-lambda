import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

import { getLogger } from './logger';

const { REGION: region, TOPIC_ARN: topicArn } = process.env;

const sns = new SNSClient({ region });

const logger = getLogger('sns');

export const notify = async (message) => {
  const alert = {
    source: 'letsencrypt-lambda',
    sourceDescription: 'Letsencrypt certificate renewal',
    target: 'slack',
    content: message,
    // Messages are now authored as Markdown (see buildAlert/buildFailureMessage):
    // an H1 header plus bold-label bullets. Arbitrary error strings are fenced via
    // code() so wildcard names and stray * _ ` don't get mis-parsed as emphasis.
    format: 'markdown',
  };
  try {
    const command = new PublishCommand({
      TopicArn: topicArn,
      Message: JSON.stringify(alert),
    });
    await sns.send(command);
  } catch (e) {
    logger.error(`Failed to publish message.`);
    throw e;
  }
};
