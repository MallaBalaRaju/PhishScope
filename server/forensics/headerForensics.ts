import { 
  ReceivedHop, 
  EvidenceFinding, 
  EmailEnvelope,
  IpType 
} from '../../src/types/forensics';
import { extractIps, classifyIp } from '../utils/ipUtils';

export interface HeaderForensicResults {
  receivedHops: ReceivedHop[];
  candidateSourceIps: Array<{ ip: string; confidence: string; justification: string; ipType: IpType }>;
  routingAnomalies: EvidenceFinding[];
  identityMismatches: EvidenceFinding[];
  messageIdAnomalies: EvidenceFinding[];
  dateAnomalies: EvidenceFinding[];
}

/**
 * Parses individual Received headers into structured hops.
 * Normalizes chronological order (earliest hop to final recipient delivery).
 */
export function parseReceivedChain(receivedHeaders: string[]): ReceivedHop[] {
  // In raw email headers, top header is the last hop.
  // Reversing gives chronological submission order: [0] = earliest hop, [N] = final hop.
  const chronological = [...receivedHeaders].reverse();
  const hops: ReceivedHop[] = [];

  let previousTimestamp: Date | null = null;

  for (let i = 0; i < chronological.length; i++) {
    const raw = chronological[i];
    const suspiciousSignals: string[] = [];

    // Extract reporting server: from <server> (<rdns> [<ip>])
    const fromMatch = raw.match(/from\s+([^\s;]+)(?:\s+\(([^)]+)\))?/i);
    const reportingServer = fromMatch ? fromMatch[1].trim() : undefined;
    const parenthetical = fromMatch ? fromMatch[2] : '';

    // Extract receiving server: by <server>
    const byMatch = raw.match(/\bby\s+([^\s;]+)/i);
    const byServer = byMatch ? byMatch[1].trim() : undefined;

    // Extract protocol: with <protocol>
    const withMatch = raw.match(/\bwith\s+([^\s;]+)/i);
    const protocol = withMatch ? withMatch[1].trim() : undefined;

    // Extract timestamp after semicolon
    let timestamp: string | undefined = undefined;
    let hopDate: Date | null = null;
    let timeDeltaSeconds: number | undefined = undefined;

    const semiIdx = raw.lastIndexOf(';');
    if (semiIdx !== -1) {
      const datePart = raw.slice(semiIdx + 1).trim();
      const parsedDate = new Date(datePart);
      if (!isNaN(parsedDate.getTime())) {
        hopDate = parsedDate;
        timestamp = parsedDate.toISOString();
      } else {
        suspiciousSignals.push(`Unparseable timestamp in hop: "${datePart}"`);
      }
    }

    if (hopDate && previousTimestamp) {
      timeDeltaSeconds = Math.round((hopDate.getTime() - previousTimestamp.getTime()) / 1000);
      if (timeDeltaSeconds < -120) {
        suspiciousSignals.push(`Negative transit time (${timeDeltaSeconds}s): hop timestamp predates previous hop, indicating clock desynchronization or forged header insertion.`);
      } else if (timeDeltaSeconds > 86400 * 2) {
        suspiciousSignals.push(`Abnormally high transit delay (${Math.round(timeDeltaSeconds / 3600)}h) between mail hops.`);
      }
    }
    if (hopDate) {
      previousTimestamp = hopDate;
    }

    // Extract IP address from parenthetical or overall hop text
    const ips = extractIps(parenthetical || raw);
    let ipAddress: string | undefined = undefined;
    let ipType: IpType = 'invalid';

    if (ips.length > 0) {
      // Prioritize IP inside parenthetical after 'from'
      ipAddress = ips[0].ip;
      ipType = ips[0].type;
    }

    // Hostname
    let hostname: string | undefined = reportingServer;
    if (parenthetical) {
      const words = parenthetical.split(/\s+/);
      const possibleHost = words.find(w => w.includes('.') && !w.match(/^\d+\.\d+/));
      if (possibleHost) hostname = possibleHost.replace(/[\[\]]/g, '');
    }

    // Heuristics on hop structure
    if (raw.toLowerCase().includes('localhost') && i > 0) {
      suspiciousSignals.push('Internal localhost loopback referenced in intermediate hop.');
    }

    hops.push({
      hopIndex: i + 1,
      reportingServer,
      receivingServer: byServer,
      byServer,
      ipAddress,
      ipType,
      hostname,
      timestamp,
      timeDeltaSeconds,
      protocol,
      rawHeader: raw,
      parsingConfidence: (reportingServer || byServer) ? (ipAddress ? 0.95 : 0.75) : 0.4,
      suspiciousSignals
    });
  }

  return hops;
}

/**
 * Determines candidate sending IP addresses from parsed hops
 */
export function identifyCandidateSourceIps(hops: ReceivedHop[]): Array<{ ip: string; confidence: string; justification: string; ipType: IpType }> {
  const candidates: Array<{ ip: string; confidence: string; justification: string; ipType: IpType }> = [];
  const seenIps = new Set<string>();

  // Walk from earliest hop (hopIndex 1) forward
  for (const hop of hops) {
    if (hop.ipAddress && !seenIps.has(hop.ipAddress)) {
      seenIps.add(hop.ipAddress);

      if (hop.ipType === 'public') {
        candidates.push({
          ip: hop.ipAddress,
          confidence: hop.hopIndex === 1 ? 'High (Initial connecting public hop)' : 'Medium (Intermediate public relay)',
          justification: hop.hopIndex === 1 
            ? 'First public IP address recorded in the chronological Received chain.' 
            : `Public relay observed at hop #${hop.hopIndex} (by ${hop.byServer || 'unknown server'}).`,
          ipType: 'public'
        });
      } else if (hop.ipType === 'private' || hop.ipType === 'loopback') {
        candidates.push({
          ip: hop.ipAddress,
          confidence: 'Low (Internal LAN/submission address)',
          justification: `Hop #${hop.hopIndex} originated from private/reserved space (${hop.ipType}). This reflects internal network submission rather than public internet routing origin.`,
          ipType: hop.ipType
        });
      }
    }
  }

  return candidates;
}

/**
 * Analyzes identity headers for spoofing, mismatch, and display anomalies
 */
export function analyzeIdentityMismatches(
  envelope: EmailEnvelope, 
  rawHeaders: Record<string, string | string[]>
): EvidenceFinding[] {
  const findings: EvidenceFinding[] = [];
  const now = new Date().toISOString();

  const fromDomain = envelope.from?.domain?.toLowerCase();
  const returnPathDomain = envelope.returnPathDomain?.toLowerCase();
  const replyToDomain = envelope.replyTo?.domain?.toLowerCase();

  // 1. From vs Return-Path domain mismatch
  if (fromDomain && returnPathDomain && fromDomain !== returnPathDomain) {
    // Check if subdomains of each other
    const isSubdomain = fromDomain.endsWith(`.${returnPathDomain}`) || returnPathDomain.endsWith(`.${fromDomain}`);
    if (!isSubdomain) {
      findings.push({
        findingId: 'ID-001',
        findingType: 'From_ReturnPath_Mismatch',
        value: `From: ${fromDomain} vs Return-Path: ${returnPathDomain}`,
        status: 'warning',
        source: 'RFC 5322 Envelope Headers',
        observedAt: now,
        explanation: `The visible 'From' domain (${fromDomain}) differs from the envelope 'Return-Path' domain (${returnPathDomain}). While legitimate mailing services use bounce return paths, attackers frequently abuse this to spoof brand domains.`,
        confidence: 0.85,
        supportingEvidenceReferences: ['From', 'Return-Path']
      });
    }
  }

  // 2. From vs Reply-To domain mismatch
  if (fromDomain && replyToDomain && fromDomain !== replyToDomain) {
    const isSubdomain = fromDomain.endsWith(`.${replyToDomain}`) || replyToDomain.endsWith(`.${fromDomain}`);
    if (!isSubdomain) {
      findings.push({
        findingId: 'ID-002',
        findingType: 'From_ReplyTo_Mismatch',
        value: `From: ${fromDomain} vs Reply-To: ${replyToDomain}`,
        status: 'warning',
        source: 'RFC 5322 Headers',
        observedAt: now,
        explanation: `The 'Reply-To' domain (${replyToDomain}) redirects replies away from the apparent sender domain (${fromDomain}). This is a frequent indicator of email redirection or credential harvesting.`,
        confidence: 0.9,
        supportingEvidenceReferences: ['From', 'Reply-To']
      });
    }
  }

  // 3. Display Name Spoofing
  if (envelope.from?.name) {
    const name = envelope.from.name.toLowerCase();
    // Check if display name contains an email address that doesn't match From address
    const emailInNameMatch = name.match(/[\w.-]+@[\w.-]+\.[a-z]{2,}/i);
    if (emailInNameMatch) {
      const emailInName = emailInNameMatch[0].toLowerCase();
      if (emailInName !== envelope.from.address.toLowerCase()) {
        findings.push({
          findingId: 'ID-003',
          findingType: 'Display_Name_Email_Deception',
          value: `Display Name: "${envelope.from.name}" vs Address: ${envelope.from.address}`,
          status: 'fail',
          source: 'From Header Display Name',
          observedAt: now,
          explanation: `The sender display name embeds an email address (${emailInName}) that contradicts the actual sending mailbox (${envelope.from.address}). This is a classic visual deception tactic.`,
          confidence: 0.95,
          supportingEvidenceReferences: ['From']
        });
      }
    }

    // Check high-profile brand keywords in display name with unrelated domain
    const brandKeywords = ['paypal', 'microsoft', 'google', 'apple', 'amazon', 'bank of america', 'wells fargo', 'chase', 'netflix', 'dhl', 'fedex', 'usps'];
    for (const brand of brandKeywords) {
      if (name.includes(brand) && fromDomain && !fromDomain.includes(brand.replace(/\s+/g, ''))) {
        findings.push({
          findingId: `ID-004-${brand.replace(/\s+/g, '')}`,
          findingType: 'Brand_Display_Impersonation',
          value: `Display Name mentions '${brand}' but From domain is '${fromDomain}'`,
          status: 'fail',
          source: 'From Header',
          observedAt: now,
          explanation: `The sender display name claims identity with brand '${brand}', but the actual sender domain (${fromDomain}) has no demonstrable association with that brand.`,
          confidence: 0.9,
          supportingEvidenceReferences: ['From']
        });
        break;
      }
    }
  }

  return findings;
}

/**
 * Analyzes Message-ID header characteristics
 */
export function analyzeMessageId(
  messageId: string | undefined, 
  envelope: EmailEnvelope
): EvidenceFinding[] {
  const findings: EvidenceFinding[] = [];
  const now = new Date().toISOString();

  if (!messageId) {
    findings.push({
      findingId: 'MID-001',
      findingType: 'Missing_Message_ID',
      value: 'Missing',
      status: 'warning',
      source: 'Message-ID Header',
      observedAt: now,
      explanation: 'Message-ID header is missing. RFC 5322 strongly recommends a globally unique Message-ID; its absence is common in automated spam tools or ad-hoc scripts.',
      confidence: 0.8,
      supportingEvidenceReferences: ['Message-ID']
    });
    return findings;
  }

  // Check syntax: should be <id@domain>
  const match = messageId.match(/<([^@]+)@([^>]+)>/);
  if (!match) {
    findings.push({
      findingId: 'MID-002',
      findingType: 'Malformed_Message_ID',
      value: messageId,
      status: 'warning',
      source: 'Message-ID Header',
      observedAt: now,
      explanation: 'Message-ID does not conform to standard RFC 5322 syntax (<id@domain>).',
      confidence: 0.7,
      supportingEvidenceReferences: ['Message-ID']
    });
  } else {
    const midDomain = match[2].toLowerCase();
    const fromDomain = envelope.from?.domain?.toLowerCase();

    if (fromDomain && midDomain !== fromDomain && !fromDomain.endsWith(`.${midDomain}`) && !midDomain.endsWith(`.${fromDomain}`)) {
      findings.push({
        findingId: 'MID-003',
        findingType: 'Message_ID_Domain_Mismatch',
        value: `Message-ID domain: ${midDomain} vs From domain: ${fromDomain}`,
        status: 'info',
        source: 'Message-ID Header',
        observedAt: now,
        explanation: `Message-ID domain (${midDomain}) differs from the sender domain (${fromDomain}). This can occur naturally when using hosted infrastructure (e.g. Amazon SES, SendGrid) or may signify external mail generation.`,
        confidence: 0.6,
        supportingEvidenceReferences: ['Message-ID', 'From']
      });
    }
  }

  return findings;
}

/**
 * Master header forensics pipeline
 */
export function runHeaderForensics(
  receivedHeaders: string[],
  envelope: EmailEnvelope,
  rawHeaders: Record<string, string | string[]>
): HeaderForensicResults {
  const receivedHops = parseReceivedChain(receivedHeaders);
  const candidateSourceIps = identifyCandidateSourceIps(receivedHops);
  const identityMismatches = analyzeIdentityMismatches(envelope, rawHeaders);
  const messageIdAnomalies = analyzeMessageId(envelope.messageId, envelope);

  const routingAnomalies: EvidenceFinding[] = [];
  const dateAnomalies: EvidenceFinding[] = [];
  const now = new Date().toISOString();

  // Aggregate hop-level suspicious signals
  for (const hop of receivedHops) {
    for (const signal of hop.suspiciousSignals) {
      routingAnomalies.push({
        findingId: `ROUT-${hop.hopIndex}`,
        findingType: 'Routing_Anomaly',
        value: `Hop #${hop.hopIndex}: ${signal}`,
        status: 'warning',
        source: `Received Hop #${hop.hopIndex}`,
        observedAt: now,
        explanation: signal,
        confidence: 0.85,
        supportingEvidenceReferences: [`Received[${hop.hopIndex - 1}]`]
      });
    }
  }

  // Date validity check
  if (envelope.date) {
    const parsedDate = new Date(envelope.date);
    if (isNaN(parsedDate.getTime())) {
      dateAnomalies.push({
        findingId: 'DATE-001',
        findingType: 'Invalid_Date_Header',
        value: envelope.date,
        status: 'warning',
        source: 'Date Header',
        observedAt: now,
        explanation: `Date header could not be parsed into a valid UTC timestamp: "${envelope.date}".`,
        confidence: 0.9,
        supportingEvidenceReferences: ['Date']
      });
    } else {
      const nowMs = Date.now();
      // Future date check (> 2 hours into future)
      if (parsedDate.getTime() > nowMs + 7200000) {
        dateAnomalies.push({
          findingId: 'DATE-002',
          findingType: 'Future_Timestamp',
          value: envelope.date,
          status: 'warning',
          source: 'Date Header',
          observedAt: now,
          explanation: `Date header is set in the future (${Math.round((parsedDate.getTime() - nowMs) / 3600000)}h ahead of current system time). This may indicate time tampering or incorrect mail server clock settings.`,
          confidence: 0.8,
          supportingEvidenceReferences: ['Date']
        });
      }
    }
  }

  return {
    receivedHops,
    candidateSourceIps,
    routingAnomalies,
    identityMismatches,
    messageIdAnomalies,
    dateAnomalies
  };
}
