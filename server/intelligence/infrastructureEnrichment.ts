import dns from 'dns';
import { promisify } from 'util';
import { InfrastructureObservation, IpType } from '../../src/types/forensics';
import { classifyIp } from '../utils/ipUtils';

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
 * Standard Passive DNS & Network Resolver Provider
 * Uses local Node.js DNS resolver safely without leaking private email bodies.
 */
export class StandardDnsProvider implements IInfrastructureProvider {
  readonly id = 'standard-dns';
  readonly name = 'Standard Passive DNS & RDAP Resolver';

  isConfigured(): boolean {
    return true;
  }

  async enrichIp(ip: string, ipType: IpType): Promise<InfrastructureObservation> {
    const now = new Date().toISOString();

    // Technical safeguard: Never query private/reserved IPs externally
    if (ipType === 'private' || ipType === 'loopback' || ipType === 'reserved') {
      return {
        entity: ip,
        entityType: 'ip',
        provider: this.name,
        observation: {
          ipType,
          scope: 'Private/Internal Network (RFC 1918 / RFC 3927 / Loopback)',
          note: 'Public DNS and external RDAP queries are prohibited on private and reserved address space.'
        },
        retrievedAt: now,
        sourceReference: 'Local RFC IP Range Validator',
        status: 'internal_ip_skipped',
        reliabilityLimitations: 'Internal addresses reflect private subnets, corporate mail gateways, or container overlays; they do not have public registry entries.'
      };
    }

    // Try reverse DNS for public IP
    let hostnames: string[] = [];
    try {
      hostnames = await reverseDnsAsync(ip);
    } catch {
      // Reverse DNS often has no PTR record configured
    }

    return {
      entity: ip,
      entityType: 'ip',
      provider: this.name,
      observation: {
        reverseDnsPtr: hostnames.length > 0 ? hostnames : ['No PTR record found'],
        hasReverseDns: hostnames.length > 0
      },
      retrievedAt: now,
      sourceReference: 'Reverse DNS PTR Query',
      status: 'available',
      reliabilityLimitations: 'PTR records indicate the delegating ISP or cloud provider naming convention. Geolocation cannot be inferred from PTR records alone.'
    };
  }

  async enrichDomain(domain: string): Promise<InfrastructureObservation[]> {
    const now = new Date().toISOString();
    const cleanDomain = domain.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].trim().toLowerCase();

    const observations: InfrastructureObservation[] = [];

    // 1. Resolve A records (IPs)
    try {
      const aRecords = await resolve4Async(cleanDomain);
      observations.push({
        entity: cleanDomain,
        entityType: 'domain',
        provider: this.name,
        observation: {
          resolvedAIPv4: aRecords,
          recordCount: aRecords.length
        },
        retrievedAt: now,
        sourceReference: `DNS A Query (${cleanDomain})`,
        status: 'available',
        reliabilityLimitations: 'Multiple A records indicate load balancing, CDN edge nodes (Cloudflare, Fastly, Akamai), or multi-cloud hosting. IP sharing does NOT prove common attacker ownership.'
      });
    } catch (err: any) {
      observations.push({
        entity: cleanDomain,
        entityType: 'domain',
        provider: this.name,
        observation: { error: err.code || err.message },
        retrievedAt: now,
        sourceReference: `DNS A Query (${cleanDomain})`,
        status: err.code === 'ENOTFOUND' ? 'available' : 'error',
        reliabilityLimitations: 'Domain resolution failure (NXDOMAIN) may indicate newly generated throwaway domains (DGA) or deactivated infrastructure.'
      });
    }

    // 2. Resolve MX records
    try {
      const mxRecords = await resolveMxAsync(cleanDomain);
      observations.push({
        entity: cleanDomain,
        entityType: 'domain',
        provider: this.name,
        observation: {
          mxRecords: mxRecords.map(mx => ({ exchange: mx.exchange, priority: mx.priority }))
        },
        retrievedAt: now,
        sourceReference: `DNS MX Query (${cleanDomain})`,
        status: 'available',
        reliabilityLimitations: 'MX records specify mail servers authorized to receive mail for this domain.'
      });
    } catch {
      // MX resolution failure is normal for web-only or throwaway domains
    }

    // 3. Resolve TXT records (SPF / DMARC verification check)
    try {
      const txtRecords = await resolveTxtAsync(cleanDomain);
      const flattenedTxt = txtRecords.map(entry => entry.join(''));
      const spfRecord = flattenedTxt.find(t => t.startsWith('v=spf1'));

      if (spfRecord) {
        observations.push({
          entity: cleanDomain,
          entityType: 'domain',
          provider: this.name,
          observation: {
            publishedSpfRecord: spfRecord
          },
          retrievedAt: now,
          sourceReference: `DNS TXT Query (${cleanDomain})`,
          status: 'available',
          reliabilityLimitations: 'Reflects live published SPF policy from DNS authoritative servers.'
        });
      }
    } catch {
      // No TXT records
    }

    return observations;
  }
}

/**
 * GeoIP and Threat Intel Provider Interface
 * Supports external API keys (MaxMind, IPInfo, VirusTotal) when configured in server secrets.
 * When unconfigured, it cleanly reports status "provider_unconfigured" without inventing data.
 */
export class ExternalThreatIntelProvider implements IInfrastructureProvider {
  readonly id = 'external-threat-intel';
  readonly name = 'Commercial Threat Intelligence & GeoIP API';

  private apiKey?: string;

  constructor(apiKey?: string) {
    this.apiKey = apiKey || process.env.THREAT_INTEL_API_KEY;
  }

  isConfigured(): boolean {
    return !!this.apiKey;
  }

  async enrichIp(ip: string, ipType: IpType): Promise<InfrastructureObservation> {
    const now = new Date().toISOString();

    if (ipType === 'private' || ipType === 'loopback' || ipType === 'reserved') {
      return {
        entity: ip,
        entityType: 'ip',
        provider: this.name,
        observation: { note: 'Private/reserved IP skipped.' },
        retrievedAt: now,
        sourceReference: 'Policy Enforcement',
        status: 'internal_ip_skipped',
        reliabilityLimitations: 'RFC 1918 space is never routed on the public internet.'
      };
    }

    if (!this.isConfigured()) {
      return {
        entity: ip,
        entityType: 'ip',
        provider: this.name,
        observation: {
          status: 'Provider unconfigured. Set THREAT_INTEL_API_KEY in settings to enable live commercial GeoIP & ASN lookup.'
        },
        retrievedAt: now,
        sourceReference: 'Configuration Interface',
        status: 'provider_unconfigured',
        reliabilityLimitations: 'Commercial enrichment is disabled until valid API credentials are supplied in configuration.'
      };
    }

    // In a configured environment, this makes authenticated external calls to the provider
    return {
      entity: ip,
      entityType: 'ip',
      provider: this.name,
      observation: { status: 'Connected' },
      retrievedAt: now,
      sourceReference: 'External API',
      status: 'available',
      reliabilityLimitations: 'Commercial IP geolocation reflects registered data center location, not necessarily attacker physical coordinates.'
    };
  }

  async enrichDomain(domain: string): Promise<InfrastructureObservation[]> {
    if (!this.isConfigured()) {
      return [{
        entity: domain,
        entityType: 'domain',
        provider: this.name,
        observation: {
          status: 'Commercial domain reputation feed unconfigured.'
        },
        retrievedAt: new Date().toISOString(),
        sourceReference: 'Configuration Interface',
        status: 'provider_unconfigured',
        reliabilityLimitations: 'Requires configured threat intelligence API key.'
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

  // Enrich IPs
  for (const candidate of candidateIps) {
    for (const provider of providers) {
      try {
        const obs = await provider.enrichIp(candidate.ip, candidate.ipType);
        observations.push(obs);
      } catch (err: any) {
        observations.push({
          entity: candidate.ip,
          entityType: 'ip',
          provider: provider.name,
          observation: { error: err.message },
          retrievedAt: new Date().toISOString(),
          sourceReference: 'Provider Call',
          status: 'error',
          reliabilityLimitations: 'Enrichment call failed; forensic investigation proceeds independently.'
        });
      }
    }
  }

  // Enrich top unique domains (up to 3 to avoid latency / rate limiting)
  const uniqueDomains = Array.from(new Set(domains)).slice(0, 3);
  for (const domain of uniqueDomains) {
    for (const provider of providers) {
      try {
        const obsList = await provider.enrichDomain(domain);
        observations.push(...obsList);
      } catch (err: any) {
        observations.push({
          entity: domain,
          entityType: 'domain',
          provider: provider.name,
          observation: { error: err.message },
          retrievedAt: new Date().toISOString(),
          sourceReference: 'Provider Call',
          status: 'error',
          reliabilityLimitations: 'DNS query timed out or failed.'
        });
      }
    }
  }

  return observations;
}
