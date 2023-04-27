import { SNSClient, PublishCommand } from '@aws-sdk/client-sns';

import { getLogger } from './logger';

import config from '../config.json';

const { region, topicArn } = config;
const sns = new SNSClient({ region });

const logger = getLogger('sns');

export const notify = async (message) => {
  const alert = {
    source: 'letsencrypt-lambda',
    sourceDescription: 'Letsencrypt certificate renewal',
    target: 'slack',
    content: message,
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
