import axios from 'axios';

import { getLogger } from './logger';

const logger = getLogger('notifier');
const slackToken = process.env.SLACK_TOKEN;

export const notify = async (message) => {
  try {
    const { data } = await axios.post(
      'https://slack.com/api/chat.postMessage',
      {
        channel: '#alerts',
        text: message,
      },
      {
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${slackToken}`,
        },
      },
    );
    if (!data.ok) {
      logger.error(`Failed to notify Slack: ${data.error}.`);
    }
  } catch (e) {
    logger.error(`Failed to notify Slack: ${e.toString()}.`);
  }
};
