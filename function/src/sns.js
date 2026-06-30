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
    // Pin plain rendering: certificate messages contain literal text (wildcard
    // common names like *.example.com, error strings) that must not be parsed
    // as Markdown — the alerter defaults to Markdown otherwise.
    format: 'plain',
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
