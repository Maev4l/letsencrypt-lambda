import {
  Route53Client,
  ListResourceRecordSetsCommand,
  ChangeResourceRecordSetsCommand,
} from '@aws-sdk/client-route-53';

import { getLogger } from './logger';
import config from '../config.json';

const { region } = config;

const logger = getLogger('route53');

const r53 = new Route53Client({ region });

export const resetRoute53AcmeRecords = async (zoneId, domain) => {
  const acmeName = domain.endsWith('.')
    ? `_acme-challenge.${domain}`
    : `_acme-challenge.${domain}.`;
  let recordsSet = [];
  let result = await r53.send(
    new ListResourceRecordSetsCommand({
      HostedZoneId: zoneId,
      StartRecordType: 'TXT',
      StartRecordName: acmeName,
      MaxItems: 100,
    }),
  );

  while (true) {
    const {
      ResourceRecordSets: resourceRecordsSet,
      IsTruncated: hasMore,
      NextRecordName: nextRecordName,
    } = result;

    recordsSet = [...recordsSet, ...resourceRecordsSet];
    if (!hasMore) {
      break;
    }

    result = await r53.send(
      new ListResourceRecordSetsCommand({
        HostedZoneId: zoneId,
        StartRecordType: 'TXT',
        StartRecordName: nextRecordName,
        MaxItems: 100,
      }),
    );
  }

  const recordSet = recordsSet.find((r) => {
    const { Name: name, Type: type } = r;
    return name === acmeName && type === 'TXT';
  });

  if (recordSet) {
    const { Name, Type, TTL, ResourceRecords } = recordSet;
    await r53.send(
      new ChangeResourceRecordSetsCommand({
        HostedZoneId: zoneId,
        ChangeBatch: {
          Changes: [
            {
              Action: 'DELETE',
              ResourceRecordSet: {
                Name,
                Type,
                TTL,
                ResourceRecords,
              },
            },
          ],
        },
      }),
    );

    logger.info(`Removed resource record '${acmeName}' from domain '${domain}'.`);
  } else {
    logger.info(`No resource record to remove from domain '${domain}'.`);
  }
};

export const createRoute53AcmeRecords = async (zoneId, domain, challengeText) => {
  const acmeName = domain.endsWith('.')
    ? `_acme-challenge.${domain}`
    : `_acme-challenge.${domain}.`;

  await r53.send(
    new ChangeResourceRecordSetsCommand({
      HostedZoneId: zoneId,
      ChangeBatch: {
        Changes: [
          {
            Action: 'UPSERT',
            ResourceRecordSet: {
              Name: acmeName,
              Type: 'TXT',
              TTL: 60,
              ResourceRecords: [
                {
                  Value: `"${challengeText}"`,
                },
              ],
            },
          },
        ],
      },
    }),
  );

  logger.info(
    `Create verification record '${acmeName}' in domain '${domain}' - challenge: ${challengeText}`,
  );
};
