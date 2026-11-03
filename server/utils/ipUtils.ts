import { IpType } from '../../src/types/forensics';

// Regular expressions for IPv4 and IPv6 extraction
const IPV4_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const IPV6_REGEX = /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::(?:ffff:)?(?:\d{1,3}\.){3}\d{1,3}/g;

export interface IpClassificationDetails {
  ip: string;
  ipType: IpType;
  rfcStandard: string;
  isPublicCandidate: boolean;
  category: string;
  isSpecialPurpose: boolean;
  isTransitionMechanism?: boolean;
  transitionType?: '6to4' | 'ipv4_mapped' | 'teredo' | 'nat64';
  decodedIpv4?: string;
  decodedIpv4Type?: IpType;
  details: string;
}

/**
 * Parses IPv4 string into 4 octets [a, b, c, d] or null if invalid
 */
function parseIpv4Octets(ip: string): [number, number, number, number] | null {
  const parts = ip.split('.').map(p => parseInt(p, 10));
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return null;
  }
  return [parts[0], parts[1], parts[2], parts[3]];
}

/**
 * Expands an IPv6 address into 8 16-bit hex integers [0-65535]
 */
function expandIpv6HexParts(ip: string): number[] | null {
  let clean = ip.toLowerCase().trim().replace(/^\[|\]$/g, '');
  
  // Handle IPv4-mapped IPv6 suffix: ::ffff:192.0.2.1
  if (clean.includes('.')) {
    const lastColon = clean.lastIndexOf(':');
    if (lastColon === -1) return null;
    const v4Part = clean.slice(lastColon + 1);
    const v4Octets = parseIpv4Octets(v4Part);
    if (!v4Octets) return null;
    const high = (v4Octets[0] << 8) | v4Octets[1];
    const low = (v4Octets[2] << 8) | v4Octets[3];
    clean = clean.slice(0, lastColon) + `:${high.toString(16)}:${low.toString(16)}`;
  }

  const doubleColonIdx = clean.indexOf('::');
  if (doubleColonIdx !== -1) {
    if (clean.indexOf('::', doubleColonIdx + 2) !== -1) {
      return null; // More than one '::' is invalid
    }
    const leftPart = clean.slice(0, doubleColonIdx);
    const rightPart = clean.slice(doubleColonIdx + 2);

    const leftWords = leftPart ? leftPart.split(':') : [];
    const rightWords = rightPart ? rightPart.split(':') : [];

    const missingWords = 8 - (leftWords.length + rightWords.length);
    if (missingWords < 0) return null;

    const fullWords: string[] = [
      ...leftWords,
      ...Array(missingWords).fill('0'),
      ...rightWords
    ];

    if (fullWords.length !== 8) return null;
    return fullWords.map(w => parseInt(w || '0', 16));
  } else {
    const words = clean.split(':');
    if (words.length !== 8) return null;
    return words.map(w => parseInt(w, 16));
  }
}

/**
 * Standards-compliant IPv4 and IPv6 classification
 * RFC 1918, RFC 3927, RFC 5737, RFC 6598, RFC 2544, RFC 6890, RFC 7526, RFC 1122, RFC 5771, RFC 1112
 * RFC 4291, RFC 4193, RFC 3849, RFC 3056 (6to4), RFC 4380, RFC 6052, RFC 6666
 */
export function classifyDetailedIp(ip: string): IpClassificationDetails {
  const clean = ip.trim().replace(/^\[|\]$/g, '');

  // 1. IPv4 Classification
  if (clean.includes('.') && !clean.includes(':')) {
    const octets = parseIpv4Octets(clean);
    if (!octets) {
      return {
        ip: clean,
        ipType: 'invalid',
        rfcStandard: 'RFC 791',
        isPublicCandidate: false,
        category: 'Invalid IPv4',
        isSpecialPurpose: true,
        details: 'Invalid IPv4 octet format or out of bounds (0-255).'
      };
    }

    const [a, b, c, d] = octets;

    // RFC 1122: 0.0.0.0/8 ("This network")
    if (a === 0) {
      return {
        ip: clean,
        ipType: 'unspecified',
        rfcStandard: 'RFC 1122 Section 3.2.1.3',
        isPublicCandidate: false,
        category: 'Unspecified / Source Only',
        isSpecialPurpose: true,
        details: '0.0.0.0/8 is reserved for this-network source-only addressing; invalid as routable internet origin.'
      };
    }

    // RFC 1122: 127.0.0.0/8 (Loopback)
    if (a === 127) {
      return {
        ip: clean,
        ipType: 'loopback',
        rfcStandard: 'RFC 1122 Section 3.2.1.3',
        isPublicCandidate: false,
        category: 'IPv4 Loopback',
        isSpecialPurpose: true,
        details: '127.0.0.0/8 loopback address; internal host-only communication.'
      };
    }

    // RFC 1918 Private ranges:
    // 10.0.0.0/8
    if (a === 10) {
      return {
        ip: clean,
        ipType: 'private',
        rfcStandard: 'RFC 1918',
        isPublicCandidate: false,
        category: 'IPv4 Private (Class A 10/8)',
        isSpecialPurpose: true,
        details: 'RFC 1918 private address space (10.0.0.0/8); non-routable on the public internet.'
      };
    }

    // 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    if (a === 172 && b >= 16 && b <= 31) {
      return {
        ip: clean,
        ipType: 'private',
        rfcStandard: 'RFC 1918',
        isPublicCandidate: false,
        category: 'IPv4 Private (Class B 172.16/12)',
        isSpecialPurpose: true,
        details: 'RFC 1918 private address space (172.16.0.0/12); non-routable on the public internet.'
      };
    }

    // 192.168.0.0/16
    if (a === 192 && b === 168) {
      return {
        ip: clean,
        ipType: 'private',
        rfcStandard: 'RFC 1918',
        isPublicCandidate: false,
        category: 'IPv4 Private (Class C 192.168/16)',
        isSpecialPurpose: true,
        details: 'RFC 1918 private address space (192.168.0.0/16); non-routable on the public internet.'
      };
    }

    // RFC 6598: Shared Address Space (Carrier-Grade NAT: 100.64.0.0/10)
    if (a === 100 && b >= 64 && b <= 127) {
      return {
        ip: clean,
        ipType: 'reserved',
        rfcStandard: 'RFC 6598',
        isPublicCandidate: false,
        category: 'Carrier-Grade NAT (CGNAT)',
        isSpecialPurpose: true,
        details: '100.64.0.0/10 Shared Carrier-Grade NAT space; ISP internal customer-premises routing.'
      };
    }

    // RFC 3927: Link-Local (169.254.0.0/16)
    if (a === 169 && b === 254) {
      return {
        ip: clean,
        ipType: 'reserved',
        rfcStandard: 'RFC 3927',
        isPublicCandidate: false,
        category: 'IPv4 Link-Local (APIPA)',
        isSpecialPurpose: true,
        details: '169.254.0.0/16 auto-configuration link-local space; non-routable.'
      };
    }

    // RFC 6890 / RFC 5735: IETF Protocol Assignments (192.0.0.0/24)
    if (a === 192 && b === 0 && c === 0) {
      return {
        ip: clean,
        ipType: 'reserved',
        rfcStandard: 'RFC 6890',
        isPublicCandidate: false,
        category: 'IETF Protocol Assignments',
        isSpecialPurpose: true,
        details: '192.0.0.0/24 reserved for IETF protocol assignments.'
      };
    }

    // RFC 5737: Documentation / Test Networks:
    // 192.0.2.0/24 (TEST-NET-1)
    if (a === 192 && b === 0 && c === 2) {
      return {
        ip: clean,
        ipType: 'documentation',
        rfcStandard: 'RFC 5737',
        isPublicCandidate: false,
        category: 'Documentation Network (TEST-NET-1)',
        isSpecialPurpose: true,
        details: '192.0.2.0/24 (TEST-NET-1) is reserved for documentation and testing; cannot be an ordinary public origin.'
      };
    }

    // RFC 7526: 6to4 Relay Anycast (192.88.99.0/24, Deprecated)
    if (a === 192 && b === 88 && c === 99) {
      return {
        ip: clean,
        ipType: 'reserved',
        rfcStandard: 'RFC 7526 (Deprecated RFC 3068)',
        isPublicCandidate: false,
        category: '6to4 Relay Anycast (Deprecated)',
        isSpecialPurpose: true,
        details: '192.88.99.0/24 was formerly 6to4 relay anycast, now formally deprecated by RFC 7526.'
      };
    }

    // RFC 2544 / RFC 6815: Benchmarking (198.18.0.0/15, 198.18.0.0 - 198.19.255.255)
    if (a === 198 && (b === 18 || b === 19)) {
      return {
        ip: clean,
        ipType: 'reserved',
        rfcStandard: 'RFC 2544 / RFC 6815',
        isPublicCandidate: false,
        category: 'Benchmarking Network',
        isSpecialPurpose: true,
        details: '198.18.0.0/15 is reserved for inter-network communications testing/benchmarking.'
      };
    }

    // 198.51.100.0/24 (TEST-NET-2)
    if (a === 198 && b === 51 && c === 100) {
      return {
        ip: clean,
        ipType: 'documentation',
        rfcStandard: 'RFC 5737',
        isPublicCandidate: false,
        category: 'Documentation Network (TEST-NET-2)',
        isSpecialPurpose: true,
        details: '198.51.100.0/24 (TEST-NET-2) is reserved for documentation and testing.'
      };
    }

    // 203.0.113.0/24 (TEST-NET-3)
    if (a === 203 && b === 0 && c === 113) {
      return {
        ip: clean,
        ipType: 'documentation',
        rfcStandard: 'RFC 5737',
        isPublicCandidate: false,
        category: 'Documentation Network (TEST-NET-3)',
        isSpecialPurpose: true,
        details: '203.0.113.0/24 (TEST-NET-3) is reserved for documentation and testing.'
      };
    }

    // RFC 5771: Multicast (224.0.0.0/4: 224.0.0.0 - 239.255.255.255)
    if (a >= 224 && a <= 239) {
      return {
        ip: clean,
        ipType: 'multicast',
        rfcStandard: 'RFC 5771',
        isPublicCandidate: false,
        category: 'IPv4 Multicast',
        isSpecialPurpose: true,
        details: '224.0.0.0/4 multicast block; cannot originate unicast email routing.'
      };
    }

    // RFC 1112: Reserved / Future use (240.0.0.0/4: 240.0.0.0 - 255.255.255.254)
    if (a >= 240 && !(a === 255 && b === 255 && c === 255 && d === 255)) {
      return {
        ip: clean,
        ipType: 'reserved',
        rfcStandard: 'RFC 1112 Section 4',
        isPublicCandidate: false,
        category: 'IPv4 Reserved (Class E / Future Use)',
        isSpecialPurpose: true,
        details: '240.0.0.0/4 reserved for future use.'
      };
    }

    // RFC 919 / RFC 8190: Limited Broadcast (255.255.255.255/32)
    if (a === 255 && b === 255 && c === 255 && d === 255) {
      return {
        ip: clean,
        ipType: 'reserved',
        rfcStandard: 'RFC 919',
        isPublicCandidate: false,
        category: 'IPv4 Limited Broadcast',
        isSpecialPurpose: true,
        details: '255.255.255.255 limited broadcast.'
      };
    }

    // Standard Public IPv4
    return {
      ip: clean,
      ipType: 'public',
      rfcStandard: 'RFC 791',
      isPublicCandidate: true,
      category: 'Public IPv4 Unicast',
      isSpecialPurpose: false,
      details: 'Globally routable public IPv4 address.'
    };
  }

  // 2. IPv6 Classification
  if (clean.includes(':')) {
    const hexWords = expandIpv6HexParts(clean);
    if (!hexWords) {
      return {
        ip: clean,
        ipType: 'invalid',
        rfcStandard: 'RFC 4291',
        isPublicCandidate: false,
        category: 'Invalid IPv6',
        isSpecialPurpose: true,
        details: 'Malformed IPv6 syntax or invalid hextet values.'
      };
    }

    const [w0, w1, w2, w3, w4, w5, w6, w7] = hexWords;

    // RFC 4291: ::/128 (Unspecified)
    if (hexWords.every(w => w === 0)) {
      return {
        ip: clean,
        ipType: 'unspecified',
        rfcStandard: 'RFC 4291 Section 2.5.2',
        isPublicCandidate: false,
        category: 'IPv6 Unspecified Address (::)',
        isSpecialPurpose: true,
        details: 'The unspecified address :: cannot be assigned to any interface or used as public sender origin.'
      };
    }

    // RFC 4291: ::1/128 (Loopback)
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0 && w6 === 0 && w7 === 1) {
      return {
        ip: clean,
        ipType: 'loopback',
        rfcStandard: 'RFC 4291 Section 2.5.3',
        isPublicCandidate: false,
        category: 'IPv6 Loopback (::1)',
        isSpecialPurpose: true,
        details: 'IPv6 loopback address ::1; internal node-only communication.'
      };
    }

    // RFC 4291: IPv4-mapped IPv6 (::ffff:0:0/96)
    if (w0 === 0 && w1 === 0 && w2 === 0 && w3 === 0 && w4 === 0 && w5 === 0xffff) {
      const v4a = (w6 >> 8) & 0xff;
      const v4b = w6 & 0xff;
      const v4c = (w7 >> 8) & 0xff;
      const v4d = w7 & 0xff;
      const decodedV4 = `${v4a}.${v4b}.${v4c}.${v4d}`;
      const v4Class = classifyDetailedIp(decodedV4);

      return {
        ip: clean,
        ipType: v4Class.ipType,
        rfcStandard: 'RFC 4291 Section 2.5.5.2',
        isPublicCandidate: v4Class.isPublicCandidate,
        category: `IPv4-Mapped IPv6 (${v4Class.category})`,
        isSpecialPurpose: true,
        isTransitionMechanism: true,
        transitionType: 'ipv4_mapped',
        decodedIpv4: decodedV4,
        decodedIpv4Type: v4Class.ipType,
        details: `IPv4-mapped IPv6 embedding ${decodedV4} (${v4Class.details})`
      };
    }

    // RFC 3056: 6to4 Transition Mechanism (2002::/16)
    // Bits 16-47 contain the embedded IPv4 address (w1 and w2)
    if (w0 === 0x2002) {
      const v4a = (w1 >> 8) & 0xff;
      const v4b = w1 & 0xff;
      const v4c = (w2 >> 8) & 0xff;
      const v4d = w2 & 0xff;
      const decodedV4 = `${v4a}.${v4b}.${v4c}.${v4d}`;
      const v4Class = classifyDetailedIp(decodedV4);

      // CRITICAL REQUIREMENT: If the embedded IPv4 address is private, reserved, loopback, or documentation,
      // the 6to4 address must be classified accordingly and NEVER treated as an ordinary public candidate!
      const isPublic = v4Class.isPublicCandidate;
      return {
        ip: clean,
        ipType: isPublic ? 'public' : v4Class.ipType,
        rfcStandard: 'RFC 3056',
        isPublicCandidate: isPublic,
        category: `6to4 Tunnel (${v4Class.category})`,
        isSpecialPurpose: true,
        isTransitionMechanism: true,
        transitionType: '6to4',
        decodedIpv4: decodedV4,
        decodedIpv4Type: v4Class.ipType,
        details: `6to4 address embedding IPv4 ${decodedV4} [${v4Class.ipType}]. ${
          isPublic 
            ? 'Embeds public IPv4 address.' 
            : `Special-purpose warning: Embeds non-public IPv4 (${v4Class.details}). Must NOT be classified as valid public origin candidate.`
        }`
      };
    }

    // RFC 4380: Teredo Tunneling (2001:0000::/32)
    if (w0 === 0x2001 && w1 === 0x0000) {
      // Teredo encodes client IPv4 inverted in w6 and w7
      const v4a = (~(w6 >> 8)) & 0xff;
      const v4b = (~w6) & 0xff;
      const v4c = (~(w7 >> 8)) & 0xff;
      const v4d = (~w7) & 0xff;
      const decodedV4 = `${v4a}.${v4b}.${v4c}.${v4d}`;
      const v4Class = classifyDetailedIp(decodedV4);

      return {
        ip: clean,
        ipType: v4Class.isPublicCandidate ? 'public' : v4Class.ipType,
        rfcStandard: 'RFC 4380',
        isPublicCandidate: v4Class.isPublicCandidate,
        category: 'Teredo Tunneling (IPv6 over UDP)',
        isSpecialPurpose: true,
        isTransitionMechanism: true,
        transitionType: 'teredo',
        decodedIpv4: decodedV4,
        decodedIpv4Type: v4Class.ipType,
        details: `Teredo tunneling address embedding client IPv4 ${decodedV4} (${v4Class.category}).`
      };
    }

    // RFC 3849: Documentation IPv6 (2001:db8::/32)
    if (w0 === 0x2001 && w1 === 0x0db8) {
      return {
        ip: clean,
        ipType: 'documentation',
        rfcStandard: 'RFC 3849',
        isPublicCandidate: false,
        category: 'IPv6 Documentation Prefix (2001:db8::/32)',
        isSpecialPurpose: true,
        details: '2001:db8::/32 is reserved exclusively for documentation and code examples; cannot route on public internet.'
      };
    }

    // RFC 6666: Discard-Only Address Block (100::/64)
    if (w0 === 0x0100 && w1 === 0 && w2 === 0 && w3 === 0) {
      return {
        ip: clean,
        ipType: 'reserved',
        rfcStandard: 'RFC 6666',
        isPublicCandidate: false,
        category: 'IPv6 Discard-Only Prefix (100::/64)',
        isSpecialPurpose: true,
        details: '100::/64 is reserved for traffic blackholing / discard.'
      };
    }

    // RFC 4193: Unique Local Address (ULA: fc00::/7 -> fc00::/8 and fd00::/8)
    if ((w0 & 0xfe00) === 0xfc00) {
      return {
        ip: clean,
        ipType: 'private',
        rfcStandard: 'RFC 4193',
        isPublicCandidate: false,
        category: 'IPv6 Unique Local Address (ULA)',
        isSpecialPurpose: true,
        details: 'fc00::/7 (ULA) private IPv6 address; non-routable on the global internet.'
      };
    }

    // RFC 4291: Link-Local Unicast (fe80::/10 -> fe80 to febf)
    if ((w0 & 0xffc0) === 0xfe80) {
      return {
        ip: clean,
        ipType: 'reserved',
        rfcStandard: 'RFC 4291 Section 2.5.6',
        isPublicCandidate: false,
        category: 'IPv6 Link-Local Unicast (fe80::/10)',
        isSpecialPurpose: true,
        details: 'fe80::/10 link-local address; valid only within the local network link.'
      };
    }

    // RFC 3879: Deprecated Site-Local Unicast (fec0::/10)
    if ((w0 & 0xffc0) === 0xfec0) {
      return {
        ip: clean,
        ipType: 'reserved',
        rfcStandard: 'RFC 3879 (Deprecated)',
        isPublicCandidate: false,
        category: 'IPv6 Site-Local (Deprecated fec0::/10)',
        isSpecialPurpose: true,
        details: 'fec0::/10 site-local address deprecated by RFC 3879.'
      };
    }

    // RFC 4291: Multicast (ff00::/8)
    if ((w0 & 0xff00) === 0xff00) {
      return {
        ip: clean,
        ipType: 'multicast',
        rfcStandard: 'RFC 4291 Section 2.7',
        isPublicCandidate: false,
        category: 'IPv6 Multicast (ff00::/8)',
        isSpecialPurpose: true,
        details: 'ff00::/8 multicast address block; cannot originate unicast mail hops.'
      };
    }

    // Standard Public Globally Routable IPv6
    return {
      ip: clean,
      ipType: 'public',
      rfcStandard: 'RFC 4291',
      isPublicCandidate: true,
      category: 'Public IPv6 Global Unicast',
      isSpecialPurpose: false,
      details: 'Globally routable public IPv6 address.'
    };
  }

  return {
    ip: clean,
    ipType: 'invalid',
    rfcStandard: 'Unknown',
    isPublicCandidate: false,
    category: 'Unrecognized IP format',
    isSpecialPurpose: true,
    details: 'String does not conform to valid IPv4 or IPv6 notation.'
  };
}

/**
 * Validates and classifies an IP address according to RFC standards.
 * Backward compatible signature returning IpType.
 */
export function classifyIp(ip: string): IpType {
  const details = classifyDetailedIp(ip);
  return details.ipType;
}

/**
 * Extracts candidate IP addresses from a raw string (e.g. Received header)
 */
export function extractIps(text: string): Array<{ ip: string; type: IpType; details: IpClassificationDetails }> {
  const ips = new Set<string>();
  const results: Array<{ ip: string; type: IpType; details: IpClassificationDetails }> = [];

  const v4Matches = text.match(IPV4_REGEX) || [];
  for (const match of v4Matches) {
    if (!ips.has(match)) {
      ips.add(match);
      const details = classifyDetailedIp(match);
      if (details.ipType !== 'invalid') {
        results.push({ ip: match, type: details.ipType, details });
      }
    }
  }

  const v6Matches = text.match(IPV6_REGEX) || [];
  for (const match of v6Matches) {
    if (!ips.has(match)) {
      ips.add(match);
      const details = classifyDetailedIp(match);
      if (details.ipType !== 'invalid') {
        results.push({ ip: match, type: details.ipType, details });
      }
    }
  }

  return results;
}
