import { getLogger } from './logger';

const logger = getLogger('config');

export const loadDomains = () => {
  const raw = process.env.DOMAINS_CONFIG;
  if (!raw) throw new Error('DOMAINS_CONFIG env var is missing');

  const domains = JSON.parse(raw);
  if (!Array.isArray(domains) || domains.length === 0) {
    throw new Error('DOMAINS_CONFIG must be a non-empty array');
  }

  const seen = new Set();
  for (const d of domains) {
    if (!d.common_name || typeof d.common_name !== 'string') {
      throw new Error(`Invalid domain entry (missing common_name): ${JSON.stringify(d)}`);
    }
    if (!d.hosted_zone_id || typeof d.hosted_zone_id !== 'string') {
      throw new Error(`Invalid domain entry (missing hosted_zone_id): ${d.common_name}`);
    }
    if (!Array.isArray(d.acm_regions) || d.acm_regions.length === 0) {
      throw new Error(`Invalid domain entry (acm_regions must be a non-empty list): ${d.common_name}`);
    }
    if (seen.has(d.common_name)) {
      throw new Error(`Duplicate common_name: ${d.common_name}`);
    }
    seen.add(d.common_name);
    if (d.pem_storage_regions !== undefined && !Array.isArray(d.pem_storage_regions)) {
      throw new Error(`pem_storage_regions must be a list when present: ${d.common_name}`);
    }
  }

  logger.info(`Loaded ${domains.length} domain(s) from config.`);
  return domains;
};
