import { 
  AuthStatus, 
  AlignmentStatus, 
  EmailEnvelope 
} from '../../src/types/forensics';
import { extractDomain } from '../parser/emailParser';

export interface AuthenticationForensicResults {
  authResultsHeaderPresent: boolean;
  rawAuthResultsHeader?: string;
  spf: {
    result: AuthStatus;
    domain?: string;
    helo?: string;
    scope?: string;
    ip?: string;
    mechanism?: string;
    rawSnippet?: string;
    alignmentWithFrom: AlignmentStatus;
    alignmentMode?: 'strict' | 'relaxed';
    note: string;
  };
  dkim: {
    result: AuthStatus;
    domain?: string;
    selector?: string;
    headerSnippet?: string;
    alignmentWithFrom: AlignmentStatus;
    alignmentMode?: 'strict' | 'relaxed';
    note: string;
  };
  dmarc: {
    result: AuthStatus;
    policy?: string;
    fromDomain?: string;
    alignmentWithFrom: AlignmentStatus;
    alignmentMode?: { spf: 'strict' | 'relaxed'; dkim: 'strict' | 'relaxed' };
    spfAlignmentContribution: boolean;
    dkimAlignmentContribution: boolean;
    publishedPolicy?: string;
    reportedProvenance: 'header_reported' | 'independently_verified' | 'unverified' | 'missing';
    note: string;
  };
  provenance: 'reported_in_headers' | 'independently_verified' | 'unverified' | 'missing';
  limitations: string[];
}

/**
 * Normalizes string auth result to standard RFC status
 */
export function normalizeAuthResult(val?: string): AuthStatus {
  if (!val) return 'missing';
  const lower = val.toLowerCase().trim();
  if (lower === 'pass') return 'pass';
  if (lower === 'fail') return 'fail';
  if (lower === 'softfail') return 'softfail';
  if (lower === 'neutral') return 'neutral';
  if (lower === 'none') return 'none';
  if (lower === 'temperror' || lower === 'tempfail') return 'temperror';
  if (lower === 'permerror' || lower === 'perm_error') return 'permerror';
  return 'unknown';
}

/**
 * Extracts clean domain name from an email address or domain string
 * E.g. "<bounces+123=user@sub.domain.com>" -> "sub.domain.com"
 * E.g. "smtp.mailfrom=notifications@github.com" -> "github.com"
 */
export function extractCleanMailDomain(rawStr?: string): string {
  if (!rawStr) return '';
  const cleaned = rawStr.trim().replace(/^<|>$/g, '').replace(/^smtp\.(?:mailfrom|helo)=/i, '').trim();
  const atIdx = cleaned.lastIndexOf('@');
  if (atIdx !== -1) {
    return cleaned.slice(atIdx + 1).toLowerCase().trim();
  }
  return cleaned.toLowerCase().trim();
}

/**
 * Extracts root organizational domain (base 2-part or known public suffix simplified)
 */
export function getOrganizationalDomain(domain?: string): string {
  if (!domain) return '';
  const parts = domain.toLowerCase().trim().split('.').filter(Boolean);
  if (parts.length <= 2) return domain.toLowerCase().trim();
  
  // Common 2-part ccTLDs: .co.uk, .com.au, .co.nz, .org.uk, etc.
  const secondLevelTlds = new Set(['co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'com.br']);
  const lastTwo = parts.slice(-2).join('.');
  if (secondLevelTlds.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

/**
 * Calculates domain alignment between an authenticated domain and the RFC 5322 From header domain
 * RFC 7489 Section 3.1:
 * - Strict alignment: RFC 5322 From domain and authenticated domain must match identically.
 * - Relaxed alignment: RFC 5322 From domain and authenticated domain must share the same organizational domain.
 */
export function checkDomainAlignment(
  authDomain?: string, 
  fromDomain?: string,
  mode: 'strict' | 'relaxed' = 'relaxed'
): AlignmentStatus {
  if (!authDomain || !fromDomain) return 'inapplicable';

  const a = authDomain.toLowerCase().trim();
  const f = fromDomain.toLowerCase().trim();

  if (a === f) {
    return 'strict'; // Exact match satisfies both strict and relaxed
  }

  if (mode === 'strict') {
    return 'misaligned';
  }

  // Relaxed mode check: organizational domain comparison
  const orgA = getOrganizationalDomain(a);
  const orgF = getOrganizationalDomain(f);

  if (orgA && orgF && orgA === orgF) {
    return 'relaxed';
  }

  // Subdomain check fallback
  if (f.endsWith(`.${a}`) || a.endsWith(`.${f}`)) {
    return 'relaxed';
  }

  return 'misaligned';
}

/**
 * Analyzes SPF, DKIM, and DMARC from email headers with strict semantic validation
 */
export function analyzeAuthentication(
  authResultsHeaders: string[],
  receivedSpfHeaders: string[],
  dkimSignatureHeaders: string[],
  envelope: EmailEnvelope
): AuthenticationForensicResults {
  const fromDomain = envelope.from?.domain ? envelope.from.domain.toLowerCase().trim() : undefined;
  const returnPathDomain = envelope.returnPathDomain ? envelope.returnPathDomain.toLowerCase().trim() : undefined;

  let spfResult: AuthStatus = 'missing';
  let spfDomain: string | undefined = undefined;
  let spfHelo: string | undefined = undefined;
  let spfScope: string | undefined = undefined;
  let spfIp: string | undefined = undefined;
  let spfMechanism: string | undefined = undefined;
  let spfRawSnippet: string | undefined = undefined;

  let dkimResult: AuthStatus = 'missing';
  let dkimDomain: string | undefined = undefined;
  let dkimSelector: string | undefined = undefined;
  let dkimHeaderSnippet: string | undefined = undefined;

  let headerDmarcResult: AuthStatus = 'missing';
  let dmarcPolicy: string | undefined = undefined;
  let rawAuthHeader: string | undefined = undefined;

  const limitations: string[] = [
    'Header-reported authentication: Evaluation reflects what the receiving MTA logged in Authentication-Results/Received-SPF.',
    'Independent DNS & cryptographic verification: Live DNS queries for published SPF/DMARC TXT policies and full cryptographic RSA/ed25519 body hash verification were not independently executed in this session.'
  ];

  const hasAuthResults = authResultsHeaders.length > 0;
  const hasReceivedSpf = receivedSpfHeaders.length > 0;
  const hasDkimSignature = dkimSignatureHeaders.length > 0;

  // 1. Parse RFC 8601 Authentication-Results headers (Topmost header from receiving MTA)
  if (hasAuthResults) {
    rawAuthHeader = authResultsHeaders[0];
    for (const authHeader of authResultsHeaders) {
      // SPF parsing:
      // Examples:
      // "spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=bounce.example.com"
      // "spf=pass (google.com: domain of sender@example.com designates 1.2.3.4 as permitted sender)"
      const spfMatch = authHeader.match(/\bspf=([a-zA-Z]+)(?:\s+\(([^)]+)\))?(?:[^\w\n]*smtp\.(?:mailfrom|helo)=([^\s;]+))?/i);
      if (spfMatch && spfResult === 'missing') {
        spfResult = normalizeAuthResult(spfMatch[1]);
        spfRawSnippet = spfMatch[0];
        if (spfMatch[3]) {
          spfDomain = extractCleanMailDomain(spfMatch[3]);
        }
        if (spfMatch[2]) {
          const parenthetical = spfMatch[2];
          const ipM = parenthetical.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
          if (ipM) spfIp = ipM[0];
          const domM = parenthetical.match(/domain of\s+([^\s;)]+)/i);
          if (domM && !spfDomain) {
            spfDomain = extractCleanMailDomain(domM[1]);
          }
        }
      }

      // Check for smtp.helo if present
      const heloMatch = authHeader.match(/smtp\.helo=([^\s;]+)/i);
      if (heloMatch) {
        spfHelo = extractCleanMailDomain(heloMatch[1]);
      }

      // DKIM parsing:
      // Examples:
      // "dkim=pass (signature was verified) header.d=example.com header.s=202301"
      const dkimMatch = authHeader.match(/\bdkim=([a-zA-Z]+)(?:\s+\(([^)]+)\))?(?:[^\n]*header\.(?:d|i)=([^\s;]+))?/i);
      if (dkimMatch && dkimResult === 'missing') {
        dkimResult = normalizeAuthResult(dkimMatch[1]);
        dkimHeaderSnippet = dkimMatch[0];
        if (dkimMatch[3]) {
          dkimDomain = dkimMatch[3].toLowerCase().replace(/^@/, '').trim();
        }
        const selectorM = authHeader.match(/header\.s=([^\s;]+)/i);
        if (selectorM) dkimSelector = selectorM[1].trim();
      }

      // DMARC parsing:
      // Examples:
      // "dmarc=pass (p=reject sp=reject dis=none) header.from=example.com"
      // "dmarc=fail (p=none dis=none) header.from=example.com"
      const dmarcMatch = authHeader.match(/\bdmarc=([a-zA-Z]+)(?:\s+\(([^)]+)\))?/i);
      if (dmarcMatch && headerDmarcResult === 'missing') {
        headerDmarcResult = normalizeAuthResult(dmarcMatch[1]);
        if (dmarcMatch[2]) {
          const polM = dmarcMatch[2].match(/\bp=([a-zA-Z]+)/i);
          if (polM) dmarcPolicy = polM[1].toLowerCase();
        }
      }
    }
  }

  // 2. Received-SPF fallback if SPF was not in Authentication-Results
  if (spfResult === 'missing' && hasReceivedSpf) {
    for (const spfHeader of receivedSpfHeaders) {
      const m = spfHeader.match(/^([a-zA-Z]+)\b/);
      if (m) {
        spfResult = normalizeAuthResult(m[1]);
        spfRawSnippet = spfHeader;
        const domMatch = spfHeader.match(/(?:domain of|identity=)\s*([^\s;]+)/i);
        if (domMatch) {
          spfDomain = extractCleanMailDomain(domMatch[1]);
        }
        const ipMatch = spfHeader.match(/client-ip=([^\s;]+)/i);
        if (ipMatch) {
          spfIp = ipMatch[1].trim();
        }
        break;
      }
    }
  }

  // Fallback SPF domain from envelope Return-Path
  if (!spfDomain && returnPathDomain) {
    spfDomain = returnPathDomain;
  }

  // 3. DKIM-Signature header parsing if not populated
  if (hasDkimSignature) {
    for (const sig of dkimSignatureHeaders) {
      const dMatch = sig.match(/\bd=([a-zA-Z0-9.-]+)/i);
      const sMatch = sig.match(/\bs=([a-zA-Z0-9.-]+)/i);
      if (dMatch && !dkimDomain) dkimDomain = dMatch[1].toLowerCase().trim();
      if (sMatch && !dkimSelector) dkimSelector = sMatch[1].trim();
      if (dkimResult === 'missing') {
        dkimResult = 'not_independently_verified';
        dkimHeaderSnippet = `DKIM-Signature present in headers (d=${dkimDomain || 'unknown'}, s=${dkimSelector || 'unknown'})`;
      }
    }
  }

  // 4. Identifier Alignment Analysis (RFC 7489 Section 3.1)
  const spfAlignment = checkDomainAlignment(spfDomain, fromDomain, 'relaxed');
  const dkimAlignment = checkDomainAlignment(dkimDomain, fromDomain, 'relaxed');

  // Strict alignment checks
  const isSpfAlignedStrict = (spfDomain && fromDomain && spfDomain.toLowerCase() === fromDomain.toLowerCase());
  const isDkimAlignedStrict = (dkimDomain && fromDomain && dkimDomain.toLowerCase() === fromDomain.toLowerCase());

  // DMARC Alignment Contributions:
  // SPF contributes to DMARC pass IF AND ONLY IF SPF result is pass AND SPF domain aligns with From domain
  const spfAlignmentContribution = (spfResult === 'pass') && (spfAlignment === 'strict' || spfAlignment === 'relaxed');
  
  // DKIM contributes to DMARC pass IF AND ONLY IF DKIM result is pass AND DKIM d= aligns with From domain
  const dkimAlignmentContribution = (dkimResult === 'pass') && (dkimAlignment === 'strict' || dkimAlignment === 'relaxed');

  // RFC 7489 Section 4.2 DMARC Verification Verdict:
  // DMARC passes IF AND ONLY IF (SPF passes with alignment) OR (DKIM passes with alignment).
  // CRITICAL REQUIREMENT: Never report DMARC PASS if neither SPF nor DKIM has a passing aligned identifier!
  let validatedDmarcResult: AuthStatus = 'missing';

  if (headerDmarcResult !== 'missing') {
    if (headerDmarcResult === 'pass') {
      // Validate that at least one aligned mechanism actually passed
      if (spfAlignmentContribution || dkimAlignmentContribution) {
        validatedDmarcResult = 'pass';
      } else {
        // Receiving MTA header erroneously claimed pass, or From header domain was altered
        validatedDmarcResult = 'fail';
        limitations.push('DMARC header reported pass, but neither SPF nor DKIM satisfied RFC 7489 identifier alignment with RFC 5322 From header.');
      }
    } else {
      validatedDmarcResult = headerDmarcResult;
    }
  } else if (hasAuthResults || hasReceivedSpf || hasDkimSignature) {
    // Derive DMARC status if auth headers are present
    if (spfAlignmentContribution || dkimAlignmentContribution) {
      validatedDmarcResult = 'pass';
    } else if (spfResult === 'fail' || dkimResult === 'fail' || (spfAlignment === 'misaligned' && dkimAlignment === 'misaligned')) {
      validatedDmarcResult = 'fail';
    } else {
      validatedDmarcResult = 'none';
    }
  }

  // Overall DMARC domain alignment mode
  let dmarcOverallAlignment: AlignmentStatus = 'inapplicable';
  if (spfAlignmentContribution || dkimAlignmentContribution) {
    dmarcOverallAlignment = (isSpfAlignedStrict || isDkimAlignedStrict) ? 'strict' : 'relaxed';
  } else if (spfAlignment === 'misaligned' || dkimAlignment === 'misaligned') {
    dmarcOverallAlignment = 'misaligned';
  }

  // Explanatory notes
  let spfNote = '';
  if (spfResult === 'pass') {
    spfNote = `Sender IP ${spfIp ? `(${spfIp}) ` : ''}was authorized by SPF record for '${spfDomain || 'domain'}'. Alignment with From (${fromDomain || 'none'}): ${spfAlignment}.`;
  } else if (spfResult === 'fail' || spfResult === 'softfail') {
    spfNote = `SPF validation failed or softfailed for '${spfDomain || 'domain'}'. The sending server is unauthorized or not listed in the SPF policy.`;
  } else if (spfResult === 'missing') {
    spfNote = 'No SPF evaluation was recorded in the message headers.';
  } else {
    spfNote = `SPF result reported as '${spfResult}'.`;
  }

  let dkimNote = '';
  if (dkimResult === 'pass') {
    dkimNote = `Cryptographic signature for '${dkimDomain || 'domain'}' (selector '${dkimSelector || 'default'}') verified by MTA. Alignment with From (${fromDomain || 'none'}): ${dkimAlignment}.`;
  } else if (dkimResult === 'fail') {
    dkimNote = `DKIM signature verification failed for '${dkimDomain || 'domain'}'. Message body or headers may have been modified in transit, or public key was invalid.`;
  } else if (dkimResult === 'not_independently_verified') {
    dkimNote = `DKIM-Signature header exists for domain '${dkimDomain || 'unknown'}', but receiving MTA Authentication-Results were absent. Independent cryptographic key verification was not performed.`;
  } else if (dkimResult === 'missing') {
    dkimNote = 'No DKIM signature or evaluation was recorded in the message headers.';
  } else {
    dkimNote = `DKIM result reported as '${dkimResult}'.`;
  }

  let dmarcNote = '';
  if (validatedDmarcResult === 'pass') {
    dmarcNote = `DMARC authentication passed (${dmarcOverallAlignment} alignment). ${
      spfAlignmentContribution ? 'SPF aligned and passed. ' : ''
    }${dkimAlignmentContribution ? 'DKIM aligned and passed. ' : ''}${
      dmarcPolicy ? `(Published policy: p=${dmarcPolicy})` : ''
    }`;
  } else if (validatedDmarcResult === 'fail') {
    dmarcNote = `DMARC evaluation failed. Neither SPF nor DKIM satisfied both authentication pass and identifier alignment with From domain '${fromDomain || 'none'}'. ${
      dmarcPolicy ? `(Published policy: p=${dmarcPolicy})` : ''
    }`;
  } else if (validatedDmarcResult === 'missing') {
    dmarcNote = 'No DMARC evaluation or policy records were available.';
  } else {
    dmarcNote = `DMARC status reported as '${validatedDmarcResult}'.`;
  }

  const provenance = (hasAuthResults || hasReceivedSpf) 
    ? 'reported_in_headers' 
    : (hasDkimSignature ? 'unverified' : 'missing');

  return {
    authResultsHeaderPresent: hasAuthResults,
    rawAuthResultsHeader: rawAuthHeader,
    spf: {
      result: spfResult,
      domain: spfDomain,
      helo: spfHelo,
      scope: spfScope,
      ip: spfIp,
      mechanism: spfMechanism,
      rawSnippet: spfRawSnippet,
      alignmentWithFrom: spfAlignment,
      alignmentMode: isSpfAlignedStrict ? 'strict' : 'relaxed',
      note: spfNote
    },
    dkim: {
      result: dkimResult,
      domain: dkimDomain,
      selector: dkimSelector,
      headerSnippet: dkimHeaderSnippet,
      alignmentWithFrom: dkimAlignment,
      alignmentMode: isDkimAlignedStrict ? 'strict' : 'relaxed',
      note: dkimNote
    },
    dmarc: {
      result: validatedDmarcResult,
      policy: dmarcPolicy,
      fromDomain,
      alignmentWithFrom: dmarcOverallAlignment,
      alignmentMode: {
        spf: isSpfAlignedStrict ? 'strict' : 'relaxed',
        dkim: isDkimAlignedStrict ? 'strict' : 'relaxed'
      },
      spfAlignmentContribution,
      dkimAlignmentContribution,
      publishedPolicy: dmarcPolicy,
      reportedProvenance: 'header_reported',
      note: dmarcNote
    },
    provenance,
    limitations
  };
}
