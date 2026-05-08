import {
  Route53Client,
  ChangeResourceRecordSetsCommand,
} from '@aws-sdk/client-route-53';

import { getLogger } from './logger';

const { REGION: region } = process.env;

const logger = getLogger('route53');

const r53 = new Route53Client({ region });

// UPSERT only — record persists between renewals; next run overwrites it.
// No challengeRemoveFn is wired into client.auto(), so the placeholder
// in infrastructure/route53.tf stays consistent with runtime state.
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
