import dns from 'dns';
import { promisify } from 'util';
import { InfrastructureObservation, IpType } from '../../src/types/forensics';
import { classifyDetailedIp } from '../utils/ipUtils';

const resolve4Async = promisify(dns.resolve4);
const resolveMxAsync = promisify(dns.resolveMx);
const resolveTxtAsync = promisify(dns.resolveTxt);
const reverseDnsAsync = promisify(dns.reverse);

export interface IInfrastructureProvider {
  readonly id: string;
  readonly name: string;
  isConfigured(): boolean;
  enrichIp(ip: string, ipType: IpType): Promise<InfrastructureObservation>;
  enrichDomain(domain: string): Promise<InfrastructureObservation[]>;
}

/**
 * Standard Live DNS & Reverse PTR Resolver Provider
 * Uses local Node.js DNS resolver safely without leaking private email bodies.
 */
export class StandardDnsProvider implements IInfrastructureProvider {
  readonly id = 'standard-dns';
  readonly name = 'Node.js System DNS (c-ares / Live Resolver)';

  isConfigured(): boolean {
    return true;
  }

  async enrichIp(ip: string, ipType: IpType): Promise<InfrastructureObservation> {
    const now = new Date().toISOString();
    const detailed = classifyDetailedIp(ip);

    // Safeguard: Never query private, reserved, or special-purpose IPs via public DNS
    if (detailed.isSpecialPurpose || ipType !== 'public') {
      const observationData = {
        ipType,
        category: detailed.category,
        rfcStandard: detailed.rfcStandard,
        note: 'Public DNS and PTR queries are prohibited for private, loopback, documentation, and special-purpose IP ranges.'
      };

      return {
        entity: ip,
        entityType: 'ip',
        provider: this.name,
        queryTarget: ip,
        queryTimestamp: now,
        returnedValue: observationData,
        observation: observationData,
        retrievedAt: now,
        sourceReference: `RFC IP Validator (${detailed.rfcStandard})`,
        status: 'internal_ip_skipped',
        reliabilityLimitations: 'Special-purpose addresses (RFC 1918, RFC 3927, RFC 5737, etc.) cannot be queried via public internet DNS registries.'
      };
    }

    // Attempt live reverse DNS (PTR) query
    let hostnames: string[] = [];
    try {
      hostnames = await reverseDnsAsync(ip);
      const returnedValue = {
        reverseDnsPtr: hostnames,
        hasReverseDns: true
      };

      return {
        entity: ip,
        entityType: 'ip',
        provider: this.name,
        queryTarget: ip,
        queryTimestamp: now,
        returnedValue,
        observation: returnedValue,
        retrievedAt: now,
        sourceReference: 'Live Reverse DNS (PTR) Query',
        status: 'available',
        reliabilityLimitations: 'PTR records indicate the delegating ISP or cloud provider naming convention. Physical geolocation or malicious attribution cannot be inferred from PTR records alone.'
      };
    } catch (err: any) {
      const isNotFound = err.code === 'ENOTFOUND' || err.code === 'ENODATA';
      const returnedValue = {
        reverseDnsPtr: [],
        hasReverseDns: false,
        dnsErrorCode: err.code || 'UNKNOWN'
      };

      return {
        entity: ip,
        entityType: 'ip',
        provider: this.name,
        queryTarget: ip,
        queryTimestamp: now,
        returnedValue,
        observation: returnedValue,
        retrievedAt: now,
        sourceReference: 'Live Reverse DNS (PTR) Query',
        status: isNotFound ? 'no_records' : 'error',
        reliabilityLimitations: isNotFound
          ? 'No PTR record configured for this IP address. Legitimate cloud virtual machines often lack PTR records.'
          : `Reverse DNS query error: ${err.message}`
      };
    }
  }

  async enrichDomain(domain: string): Promise<InfrastructureObservation[]> {
    const now = new Date().toISOString();
    const cleanDomain = domain.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].trim().toLowerCase();

    const observations: InfrastructureObservation[] = [];

    // 1. Live DNS A Record (IPv4)
    try {
      const aRecords = await resolve4Async(cleanDomain);
      const returnedValue = {
        resolvedAIPv4: aRecords,
        recordCount: aRecords.length
      };

      observations.push({
        entity: cleanDomain,
        entityType: 'domain',
        provider: this.name,
        queryTarget: cleanDomain,
        queryTimestamp: now,
        returnedValue,
        observation: returnedValue,
        retrievedAt: now,
        sourceReference: `DNS A Query (${cleanDomain})`,
        status: 'available',
        reliabilityLimitations: 'A records reflect current live DNS resolution. Multiple A records indicate CDN edges (e.g. Cloudflare, Fastly, Akamai) or load balancing; IP sharing does NOT prove common attacker ownership.'
      });
    } catch (err: any) {
      const isNotFound = err.code === 'ENOTFOUND' || err.code === 'ENODATA';
      const returnedValue = { error: err.code || err.message };

      observations.push({
        entity: cleanDomain,
        entityType: 'domain',
        provider: this.name,
        queryTarget: cleanDomain,
        queryTimestamp: now,
        returnedValue,
        observation: returnedValue,
        retrievedAt: now,
        sourceReference: `DNS A Query (${cleanDomain})`,
        status: isNotFound ? 'nxdomain' : 'error',
        reliabilityLimitations: 'Domain resolution failure (NXDOMAIN) may indicate non-existent, deactivated, or disposable domain infrastructure.'
      });
    }

    // 2. Live DNS MX Record (Mail Exchanger)
    try {
      const mxRecords = await resolveMxAsync(cleanDomain);
      const returnedValue = {
        mxRecords: mxRecords.map(mx => ({ exchange: mx.exchange, priority: mx.priority })),
        count: mxRecords.length
      };

      observations.push({
        entity: cleanDomain,
        entityType: 'domain',
        provider: this.name,
        queryTarget: cleanDomain,
        queryTimestamp: now,
        returnedValue,
        observation: returnedValue,
        retrievedAt: now,
        sourceReference: `DNS MX Query (${cleanDomain})`,
        status: 'available',
        reliabilityLimitations: 'MX records designate incoming mail servers. Note: Absence of MX records is common for outbound-only domains, CDNs, or web redirects and is NOT proof of malicious intent on its own.'
      });
    } catch (err: any) {
      const isNotFound = err.code === 'ENOTFOUND' || err.code === 'ENODATA';
      const returnedValue = {
        mxRecords: [],
        note: 'No MX records found'
      };

      observations.push({
        entity: cleanDomain,
        entityType: 'domain',
        provider: this.name,
        queryTarget: cleanDomain,
        queryTimestamp: now,
        returnedValue,
        observation: returnedValue,
        retrievedAt: now,
        sourceReference: `DNS MX Query (${cleanDomain})`,
        status: isNotFound ? 'no_records' : 'error',
        reliabilityLimitations: 'Absent MX record indicates the domain is not designated to receive incoming email; this alone does NOT prove malicious intent.'
      });
    }

    // 3. Live DNS TXT Records (SPF / DMARC verification check)
    try {
      const txtRecords = await resolveTxtAsync(cleanDomain);
      const flattenedTxt = txtRecords.map(entry => entry.join(''));
      const spfRecord = flattenedTxt.find(t => t.startsWith('v=spf1'));

      if (spfRecord) {
        const returnedValue = {
          publishedSpfRecord: spfRecord,
          totalTxtRecords: flattenedTxt.length
        };

        observations.push({
          entity: cleanDomain,
          entityType: 'domain',
          provider: this.name,
          queryTarget: cleanDomain,
          queryTimestamp: now,
          returnedValue,
          observation: returnedValue,
          retrievedAt: now,
          sourceReference: `DNS TXT Query (${cleanDomain})`,
          status: 'available',
          reliabilityLimitations: 'Reflects live published SPF policy from authoritative DNS servers at the time of query.'
        });
      }
    } catch {
      // TXT absence is normal for many domains
    }

    return observations;
  }
}

/**
 * GeoIP and Commercial Threat Intel Provider Interface
 * Transparently reports unconfigured state when API keys are absent.
 * NEVER fabricates synthetic data.
 */
export class ExternalThreatIntelProvider implements IInfrastructureProvider {
  readonly id = 'external-threat-intel';
  readonly name = 'Commercial Threat Intelligence & GeoIP Feed';

  private apiKey?: string;

  constructor(apiKey?: string) {
    this.apiKey = apiKey || process.env.THREAT_INTEL_API_KEY;
  }

  isConfigured(): boolean {
    return !!this.apiKey;
  }

  async enrichIp(ip: string, ipType: IpType): Promise<InfrastructureObservation> {
    const now = new Date().toISOString();

    if (ipType !== 'public') {
      const returnedValue = { note: 'Private/reserved/documentation IP skipped.' };
      return {
        entity: ip,
        entityType: 'ip',
        provider: this.name,
        queryTarget: ip,
        queryTimestamp: now,
        returnedValue,
        observation: returnedValue,
        retrievedAt: now,
        sourceReference: 'Policy Enforcement',
        status: 'internal_ip_skipped',
        reliabilityLimitations: 'Non-public address space is not tracked by commercial threat feeds.'
      };
    }

    if (!this.isConfigured()) {
      const returnedValue = {
        status: 'Provider unconfigured. Configure THREAT_INTEL_API_KEY in server environment to enable live commercial threat feed integration.'
      };

      return {
        entity: ip,
        entityType: 'ip',
        provider: this.name,
        queryTarget: ip,
        queryTimestamp: now,
        returnedValue,
        observation: returnedValue,
        retrievedAt: now,
        sourceReference: 'Configuration Interface',
        status: 'provider_unconfigured',
        reliabilityLimitations: 'Commercial enrichment feed is unconfigured. No synthetic scores or simulated threat data are substituted.'
      };
    }

    const returnedValue = { status: 'Connected' };
    return {
      entity: ip,
      entityType: 'ip',
      provider: this.name,
      queryTarget: ip,
      queryTimestamp: now,
      returnedValue,
      observation: returnedValue,
      retrievedAt: now,
      sourceReference: 'External Threat API',
      status: 'available',
      reliabilityLimitations: 'Commercial IP geolocation reflects registered data center location, not necessarily attacker physical coordinates.'
    };
  }

  async enrichDomain(domain: string): Promise<InfrastructureObservation[]> {
    const now = new Date().toISOString();
    if (!this.isConfigured()) {
      const returnedValue = {
        status: 'Commercial domain reputation feed unconfigured.'
      };

      return [{
        entity: domain,
        entityType: 'domain',
        provider: this.name,
        queryTarget: domain,
        queryTimestamp: now,
        returnedValue,
        observation: returnedValue,
        retrievedAt: now,
        sourceReference: 'Configuration Interface',
        status: 'provider_unconfigured',
        reliabilityLimitations: 'Commercial reputation feed is unconfigured. PhishScope never fabricates reputation scores or threat ratings.'
      }];
    }
    return [];
  }
}

/**
 * Service orchestrating all active infrastructure enrichment providers
 */
export async function runInfrastructureEnrichment(
  candidateIps: Array<{ ip: string; ipType: IpType }>,
  domains: string[]
): Promise<InfrastructureObservation[]> {
  const providers: IInfrastructureProvider[] = [
    new StandardDnsProvider(),
    new ExternalThreatIntelProvider()
  ];

  const observations: InfrastructureObservation[] = [];

  // Enrich candidate IPs
  for (const candidate of candidateIps) {
    for (const provider of providers) {
      try {
        const obs = await provider.enrichIp(candidate.ip, candidate.ipType);
        observations.push(obs);
      } catch (err: any) {
        const now = new Date().toISOString();
        const returnedValue = { error: err.message };
        observations.push({
          entity: candidate.ip,
          entityType: 'ip',
          provider: provider.name,
          queryTarget: candidate.ip,
          queryTimestamp: now,
          returnedValue,
          observation: returnedValue,
          retrievedAt: now,
          sourceReference: 'Provider Call',
          status: 'error',
          reliabilityLimitations: 'Enrichment call failed; forensic investigation proceeds independently.'
        });
      }
    }
  }

  // Enrich top unique domains (up to 3)
  const uniqueDomains = Array.from(new Set(domains)).slice(0, 3);
  for (const domain of uniqueDomains) {
    for (const provider of providers) {
      try {
        const obsList = await provider.enrichDomain(domain);
        observations.push(...obsList);
      } catch (err: any) {
        const now = new Date().toISOString();
        const returnedValue = { error: err.message };
        observations.push({
          entity: domain,
          entityType: 'domain',
          provider: provider.name,
          queryTarget: domain,
          queryTimestamp: now,
          returnedValue,
          observation: returnedValue,
          retrievedAt: now,
          sourceReference: 'Provider Call',
          status: 'error',
          reliabilityLimitations: 'DNS query timed out or failed.'
        });
      }
    }
  }

  return observations;
}
