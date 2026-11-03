import { IpType } from '../../src/types/forensics';

// Regular expressions for IPv4 and IPv6 extraction
const IPV4_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const IPV6_REGEX = /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}/g;

/**
 * Validates and classifies an IP address according to RFC standards:
 * RFC 1918 (IPv4 Private)
 * RFC 3927 (IPv4 Link-Local)
 * RFC 4193 / RFC 3513 (IPv6 Unique Local / Link-Local)
 * Loopback & Reserved
 */
export function classifyIp(ip: string): IpType {
  const cleanIp = ip.trim().replace(/^\[|\]$/g, '');

  // IPv4 check
  if (cleanIp.includes('.')) {
    const parts = cleanIp.split('.').map(p => parseInt(p, 10));
    if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
      return 'invalid';
    }

    const [a, b] = parts;

    // Loopback (127.0.0.0/8)
    if (a === 127) return 'loopback';

    // RFC 1918 Private ranges:
    // 10.0.0.0/8
    if (a === 10) return 'private';
    // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if (a === 172 && b >= 16 && b <= 31) return 'private';
    // 192.168.0.0/16
    if (a === 192 && b === 168) return 'private';

    // RFC 3927 Link-Local (169.254.0.0/16)
    if (a === 169 && b === 254) return 'reserved';

    // RFC 5737 Carrier-grade NAT (100.64.0.0/10)
    if (a === 100 && b >= 64 && b <= 127) return 'reserved';

    // 0.0.0.0/8, 224.0.0.0/4 (Multicast), 240.0.0.0/4 (Future)
    if (a === 0 || a >= 224) return 'reserved';

    return 'public';
  }

  // IPv6 check
  if (cleanIp.includes(':')) {
    const lower = cleanIp.toLowerCase();
    if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return 'loopback';
    if (lower.startsWith('fe80:')) return 'reserved'; // Link-Local
    if (lower.startsWith('fc') || lower.startsWith('fd')) return 'private'; // Unique Local
    return 'public';
  }

  return 'invalid';
}

/**
 * Extracts candidate IP addresses from a raw string (e.g. Received header)
 */
export function extractIps(text: string): Array<{ ip: string; type: IpType }> {
  const ips = new Set<string>();
  const results: Array<{ ip: string; type: IpType }> = [];

  const v4Matches = text.match(IPV4_REGEX) || [];
  for (const match of v4Matches) {
    if (!ips.has(match)) {
      ips.add(match);
      const type = classifyIp(match);
      if (type !== 'invalid') {
        results.push({ ip: match, type });
      }
    }
  }

  const v6Matches = text.match(IPV6_REGEX) || [];
  for (const match of v6Matches) {
    if (!ips.has(match)) {
      ips.add(match);
      const type = classifyIp(match);
      if (type !== 'invalid') {
        results.push({ ip: match, type });
      }
    }
  }

  return results;
}
