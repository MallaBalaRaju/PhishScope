import { 
  AuthStatus, 
  AlignmentStatus, 
  EmailEnvelope 
} from '../../src/types/forensics';

export interface AuthenticationForensicResults {
  authResultsHeaderPresent: boolean;
  spf: {
    result: AuthStatus;
    domain?: string;
    scope?: string;
    ip?: string;
    mechanism?: string;
    rawSnippet?: string;
    alignmentWithFrom: AlignmentStatus;
    note: string;
  };
  dkim: {
    result: AuthStatus;
    domain?: string;
    selector?: string;
    headerSnippet?: string;
    alignmentWithFrom: AlignmentStatus;
    note: string;
  };
  dmarc: {
    result: AuthStatus;
    policy?: string;
    alignmentWithFrom: AlignmentStatus;
    note: string;
  };
  provenance: 'reported_in_headers' | 'independently_verified' | 'unverified' | 'missing';
  limitations: string[];
}

/**
 * Normalizes string auth result to standard RFC status
 */
function normalizeAuthResult(val?: string): AuthStatus {
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
 * Calculates domain alignment between an authenticated domain and the From header domain
 */
function checkAlignment(authDomain?: string, fromDomain?: string): AlignmentStatus {
  if (!authDomain || !fromDomain) return 'inapplicable';

  const a = authDomain.toLowerCase();
  const f = fromDomain.toLowerCase();

  if (a === f) return 'strict';
  if (f.endsWith(`.${a}`) || a.endsWith(`.${f}`)) return 'relaxed';

  return 'misaligned';
}

/**
 * Analyzes SPF, DKIM, and DMARC from email headers
 */
export function analyzeAuthentication(
  authResultsHeaders: string[],
  receivedSpfHeaders: string[],
  dkimSignatureHeaders: string[],
  envelope: EmailEnvelope
): AuthenticationForensicResults {
  const fromDomain = envelope.from?.domain?.toLowerCase();
  const returnPathDomain = envelope.returnPathDomain?.toLowerCase();

  let spfResult: AuthStatus = 'missing';
  let spfDomain: string | undefined = undefined;
  let spfScope: string | undefined = undefined;
  let spfIp: string | undefined = undefined;
  let spfMechanism: string | undefined = undefined;
  let spfRawSnippet: string | undefined = undefined;

  let dkimResult: AuthStatus = 'missing';
  let dkimDomain: string | undefined = undefined;
  let dkimSelector: string | undefined = undefined;
  let dkimHeaderSnippet: string | undefined = undefined;

  let dmarcResult: AuthStatus = 'missing';
  let dmarcPolicy: string | undefined = undefined;

  const limitations: string[] = [
    'Header-derived authentication: Results reflect the evaluation reported by the receiving mail transfer agent (MTA) in Authentication-Results/Received-SPF headers.',
    'Independent cryptographic re-verification: DKIM body hashes and live DNS SPF/DMARC policy records have not been re-verified in this offline/in-memory session.'
  ];

  const hasAuthResults = authResultsHeaders.length > 0;
  const hasReceivedSpf = receivedSpfHeaders.length > 0;
  const hasDkimSignature = dkimSignatureHeaders.length > 0;

  // 1. Parse RFC 8601 Authentication-Results headers
  for (const authHeader of authResultsHeaders) {
    // SPF in Authentication-Results: spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=domain.com
    const spfMatch = authHeader.match(/\bspf=([a-zA-Z]+)(?:\s+\(([^)]+)\))?(?:[^\w\n]*smtp\.(?:mailfrom|helo)=([^\s;]+))?/i);
    if (spfMatch && spfResult === 'missing') {
      spfResult = normalizeAuthResult(spfMatch[1]);
      spfRawSnippet = spfMatch[0];
      if (spfMatch[3]) spfDomain = spfMatch[3].toLowerCase();
      if (spfMatch[2]) {
        const ipM = spfMatch[2].match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
        if (ipM) spfIp = ipM[0];
      }
    }

    // DKIM in Authentication-Results: dkim=pass (signature was verified) header.d=domain.com header.s=selector
    const dkimMatch = authHeader.match(/\bdkim=([a-zA-Z]+)(?:\s+\(([^)]+)\))?(?:[^\n]*header\.(?:d|i)=([^\s;]+))?/i);
    if (dkimMatch && dkimResult === 'missing') {
      dkimResult = normalizeAuthResult(dkimMatch[1]);
      dkimHeaderSnippet = dkimMatch[0];
      if (dkimMatch[3]) dkimDomain = dkimMatch[3].toLowerCase().replace(/^@/, '');
      const selectorM = authHeader.match(/header\.s=([^\s;]+)/i);
      if (selectorM) dkimSelector = selectorM[1];
    }

    // DMARC in Authentication-Results: dmarc=pass (p=reject ...) header.from=domain.com
    const dmarcMatch = authHeader.match(/\bdmarc=([a-zA-Z]+)(?:\s+\(([^)]+)\))?/i);
    if (dmarcMatch && dmarcResult === 'missing') {
      dmarcResult = normalizeAuthResult(dmarcMatch[1]);
      if (dmarcMatch[2]) {
        const polM = dmarcMatch[2].match(/p=([a-zA-Z]+)/i);
        if (polM) dmarcPolicy = polM[1];
      }
    }
  }

  // 2. Parse Received-SPF fallback if SPF not populated
  if (spfResult === 'missing' && hasReceivedSpf) {
    for (const spfHeader of receivedSpfHeaders) {
      const m = spfHeader.match(/^([a-zA-Z]+)\b/);
      if (m) {
        spfResult = normalizeAuthResult(m[1]);
        spfRawSnippet = spfHeader;
        const domMatch = spfHeader.match(/(?:domain of|client-ip=|identity=)\s*([^\s;]+)/i);
        if (domMatch) spfDomain = domMatch[1].replace(/[<>]/g, '').trim().toLowerCase();
        break;
      }
    }
  }

  // If SPF domain is still missing, fallback to envelope Return-Path
  if (!spfDomain && returnPathDomain) {
    spfDomain = returnPathDomain;
  }

  // 3. Parse DKIM-Signature headers to extract selector and domain if present
  if (hasDkimSignature) {
    for (const sig of dkimSignatureHeaders) {
      const dMatch = sig.match(/\bd=([a-zA-Z0-9.-]+)/i);
      const sMatch = sig.match(/\bs=([a-zA-Z0-9.-]+)/i);
      if (dMatch && !dkimDomain) dkimDomain = dMatch[1].toLowerCase();
      if (sMatch && !dkimSelector) dkimSelector = sMatch[1];
      if (dkimResult === 'missing') {
        // We know a signature is declared, but receiving MTA result wasn't recorded in Authentication-Results
        dkimResult = 'not_independently_verified';
        dkimHeaderSnippet = `DKIM-Signature present (d=${dkimDomain || 'unknown'}, s=${dkimSelector || 'unknown'})`;
      }
    }
  }

  // Alignment checks
  const spfAlignment = checkAlignment(spfDomain, fromDomain);
  const dkimAlignment = checkAlignment(dkimDomain, fromDomain);

  // DMARC alignment determination:
  // RFC 7489 specifies DMARC pass requires (SPF pass + SPF alignment) OR (DKIM pass + DKIM alignment)
  let dmarcAlignment: AlignmentStatus = 'inapplicable';
  if (dmarcResult !== 'missing') {
    const isSpfDmarcValid = (spfResult === 'pass') && (spfAlignment === 'strict' || spfAlignment === 'relaxed');
    const isDkimDmarcValid = (dkimResult === 'pass') && (dkimAlignment === 'strict' || dkimAlignment === 'relaxed');

    if (isSpfDmarcValid || isDkimDmarcValid) {
      dmarcAlignment = (spfAlignment === 'strict' || dkimAlignment === 'strict') ? 'strict' : 'relaxed';
    } else {
      dmarcAlignment = 'misaligned';
    }
  }

  // Construct explanatory notes
  let spfNote = '';
  if (spfResult === 'pass') {
    spfNote = `Sender IP was authorized by SPF record for '${spfDomain || 'domain'}'. Alignment with From: ${spfAlignment}.`;
  } else if (spfResult === 'fail' || spfResult === 'softfail') {
    spfNote = `SPF validation failed or softfailed for '${spfDomain || 'domain'}'. The sending server is unauthorized or not listed in the SPF policy.`;
  } else if (spfResult === 'missing') {
    spfNote = 'No SPF evaluation was recorded in the message headers.';
  } else {
    spfNote = `SPF result reported as '${spfResult}'.`;
  }

  let dkimNote = '';
  if (dkimResult === 'pass') {
    dkimNote = `Cryptographic signature for '${dkimDomain || 'domain'}' reported valid by receiving MTA. Alignment with From: ${dkimAlignment}.`;
  } else if (dkimResult === 'fail') {
    dkimNote = `DKIM signature verification failed for '${dkimDomain || 'domain'}'. The message body or headers may have been modified in transit, or the key was invalid.`;
  } else if (dkimResult === 'not_independently_verified') {
    dkimNote = `DKIM-Signature header exists for domain '${dkimDomain || 'unknown'}', but receiving MTA Authentication-Results were not provided to confirm verification.`;
  } else if (dkimResult === 'missing') {
    dkimNote = 'No DKIM signature or evaluation was recorded in the message headers.';
  } else {
    dkimNote = `DKIM result reported as '${dkimResult}'.`;
  }

  let dmarcNote = '';
  if (dmarcResult === 'pass') {
    dmarcNote = `DMARC authentication passed with alignment '${dmarcAlignment}'.`;
  } else if (dmarcResult === 'fail') {
    dmarcNote = `DMARC evaluation failed. Neither SPF nor DKIM passed with valid From-domain identifier alignment.`;
  } else if (dmarcResult === 'missing') {
    dmarcNote = 'No DMARC evaluation was recorded in the message headers.';
  } else {
    dmarcNote = `DMARC status reported as '${dmarcResult}'.`;
  }

  const provenance = (hasAuthResults || hasReceivedSpf) 
    ? 'reported_in_headers' 
    : (hasDkimSignature ? 'unverified' : 'missing');

  return {
    authResultsHeaderPresent: hasAuthResults,
    spf: {
      result: spfResult,
      domain: spfDomain,
      scope: spfScope,
      ip: spfIp,
      mechanism: spfMechanism,
      rawSnippet: spfRawSnippet,
      alignmentWithFrom: spfAlignment,
      note: spfNote
    },
    dkim: {
      result: dkimResult,
      domain: dkimDomain,
      selector: dkimSelector,
      headerSnippet: dkimHeaderSnippet,
      alignmentWithFrom: dkimAlignment,
      note: dkimNote
    },
    dmarc: {
      result: dmarcResult,
      policy: dmarcPolicy,
      alignmentWithFrom: dmarcAlignment,
      note: dmarcNote
    },
    provenance,
    limitations
  };
}
