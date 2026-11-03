import { 
  AssessmentLabel, 
  EvidenceFinding, 
  ExtractedUrl, 
  AttachmentMetadata 
} from '../../src/types/forensics';
import { AuthenticationForensicResults } from '../forensics/authForensics';
import { HeaderForensicResults } from '../forensics/headerForensics';

export interface EvidenceFusionInput {
  inputType: string;
  hasHeaders: boolean;
  hasReceivedChain: boolean;
  hasAuthenticationHeaders: boolean;
  headerFindings: HeaderForensicResults;
  authFindings: AuthenticationForensicResults;
  urls: ExtractedUrl[];
  contentFindings: EvidenceFinding[];
  attachments: AttachmentMetadata[];
  mlScore?: number;
  mlConfigured: boolean;
}

export interface FusionAssessmentOutput {
  label: AssessmentLabel;
  confidenceLevel: 'high' | 'medium' | 'low';
  score: number; // 0 - 100 risk score with explicit formula
  summary: string;
  primaryRiskFactors: string[];
  mitigatingFactors: string[];
  reasoningChain: string[];
}

/**
 * Deterministic Evidence Fusion Engine
 * Explicitly breaks down risk evaluation into transparent, traceable components.
 */
export function fuseEvidence(input: EvidenceFusionInput): FusionAssessmentOutput {
  const reasoningChain: string[] = [];
  const primaryRiskFactors: string[] = [];
  const mitigatingFactors: string[] = [];

  // Check for insufficient evidence first
  if (!input.hasHeaders && input.urls.length === 0 && input.attachments.length === 0) {
    return {
      label: 'insufficient_evidence',
      confidenceLevel: 'low',
      score: 10,
      summary: 'Insufficient forensic evidence: The provided input contains neither RFC 5322 headers, verifiable links, nor attachments. Complete email evaluation is impossible.',
      primaryRiskFactors: ['Missing RFC headers', 'Missing routing hops'],
      mitigatingFactors: [],
      reasoningChain: [
        '1. Input contains no headers; Received chain and authentication could not be examined.',
        '2. No verifiable URLs or attachments extracted from body.',
        '3. Evaluated as Insufficient Evidence.'
      ]
    };
  }

  let totalRisk = 0;

  // 1. Authentication Analysis Component (Weight: Up to 35 pts)
  reasoningChain.push('--- Evaluation Stage 1: Authentication Records ---');
  if (!input.hasAuthenticationHeaders) {
    reasoningChain.push('Authentication headers (Authentication-Results, Received-SPF) are absent from the message.');
    primaryRiskFactors.push('Unauthenticated message: No SPF, DKIM, or DMARC evaluation present in headers.');
    totalRisk += 15;
  } else {
    // SPF
    if (input.authFindings.spf.result === 'fail') {
      totalRisk += 25;
      primaryRiskFactors.push(`SPF hard failure: Sending server is unauthorized for ${input.authFindings.spf.domain || 'domain'}.`);
      reasoningChain.push('SPF evaluation resulted in hard FAIL (+25 risk points).');
    } else if (input.authFindings.spf.result === 'softfail') {
      totalRisk += 15;
      primaryRiskFactors.push(`SPF softfail: Sending server is not designated as authorized in ${input.authFindings.spf.domain || 'domain'} policy.`);
      reasoningChain.push('SPF evaluation resulted in SOFTFAIL (+15 risk points).');
    } else if (input.authFindings.spf.result === 'pass') {
      mitigatingFactors.push(`SPF passed for domain '${input.authFindings.spf.domain || 'domain'}'.`);
      reasoningChain.push('SPF evaluation passed (-10 risk offset).');
      totalRisk = Math.max(0, totalRisk - 10);
    }

    // DKIM
    if (input.authFindings.dkim.result === 'fail') {
      totalRisk += 25;
      primaryRiskFactors.push(`DKIM verification failure: Digital signature failed verification for domain '${input.authFindings.dkim.domain || 'domain'}'.`);
      reasoningChain.push('DKIM signature failed validation (+25 risk points).');
    } else if (input.authFindings.dkim.result === 'pass') {
      mitigatingFactors.push(`DKIM signature verified for domain '${input.authFindings.dkim.domain || 'domain'}'.`);
      reasoningChain.push('DKIM signature passed verification (-10 risk offset).');
      totalRisk = Math.max(0, totalRisk - 10);
    }

    // DMARC
    if (input.authFindings.dmarc.result === 'fail') {
      totalRisk += 20;
      primaryRiskFactors.push('DMARC alignment failed: Message violates published domain alignment policy.');
      reasoningChain.push('DMARC alignment failed (+20 risk points).');
    } else if (input.authFindings.dmarc.result === 'pass') {
      mitigatingFactors.push('DMARC policy satisfied with valid domain identifier alignment.');
      reasoningChain.push('DMARC policy satisfied (-15 risk offset).');
      totalRisk = Math.max(0, totalRisk - 15);
    }
  }

  // 2. Identity and Routing Forensics Component (Weight: Up to 35 pts)
  reasoningChain.push('--- Evaluation Stage 2: Header & Identity Consistency ---');
  for (const mismatch of input.headerFindings.identityMismatches) {
    if (mismatch.status === 'fail') {
      totalRisk += 30;
      primaryRiskFactors.push(mismatch.explanation);
      reasoningChain.push(`High-severity identity anomaly: ${mismatch.value} (+30 risk points).`);
    } else if (mismatch.status === 'warning') {
      totalRisk += 15;
      primaryRiskFactors.push(mismatch.explanation);
      reasoningChain.push(`Moderate identity anomaly: ${mismatch.value} (+15 risk points).`);
    }
  }

  for (const anomaly of input.headerFindings.routingAnomalies) {
    totalRisk += 15;
    primaryRiskFactors.push(anomaly.explanation);
    reasoningChain.push(`Routing anomaly: ${anomaly.value} (+15 risk points).`);
  }

  // 3. Content, URL and Attachment Forensics Component (Weight: Up to 40 pts)
  reasoningChain.push('--- Evaluation Stage 3: Content, URLs & Attachments ---');
  let hasAnchorMismatch = false;
  let hasIpUrl = false;
  let hasPunycode = false;

  for (const u of input.urls) {
    if (u.isMismatch) {
      hasAnchorMismatch = true;
      totalRisk += 35;
      primaryRiskFactors.push(`Deceptive anchor link: text claims '${u.displayText}' but navigates to '${u.domain}'.`);
      reasoningChain.push(`Deceptive anchor text divergence observed for ${u.domain} (+35 risk points).`);
    }
    if (u.isIpBased) {
      hasIpUrl = true;
      totalRisk += 25;
      primaryRiskFactors.push(`Direct IP link: '${u.domain}' used as URL host.`);
      reasoningChain.push(`Direct IP link address observed (+25 risk points).`);
    }
    if (u.isPunycode) {
      hasPunycode = true;
      totalRisk += 20;
      primaryRiskFactors.push(`Internationalized Punycode homoglyph domain: '${u.domain}'.`);
      reasoningChain.push(`Punycode homoglyph detected (+20 risk points).`);
    }
  }

  // Suspicious attachments
  for (const att of input.attachments) {
    if (att.isSuspiciousExtension) {
      totalRisk += 35;
      primaryRiskFactors.push(`Dangerous file attachment: '${att.filename}' (.${att.filename.split('.').pop()}) carries high execution risk.`);
      reasoningChain.push(`Executable or script attachment detected: ${att.filename} (+35 risk points).`);
    }
  }

  // Social engineering cues
  for (const finding of input.contentFindings) {
    if (finding.findingType.startsWith('Urgency') || finding.findingType.startsWith('Credential')) {
      totalRisk += 10;
      primaryRiskFactors.push(finding.explanation);
      reasoningChain.push(`Social engineering heuristic signal: ${finding.value} (+10 risk points).`);
    }
  }

  // 4. ML Contribution (if configured)
  if (input.mlConfigured && typeof input.mlScore === 'number') {
    reasoningChain.push(`--- Evaluation Stage 4: Configured ML Model (Score: ${input.mlScore}) ---`);
    if (input.mlScore > 0.7) {
      totalRisk += 15;
      primaryRiskFactors.push(`Configured ML model flagged text patterns as suspicious (${input.mlScore}).`);
    } else if (input.mlScore < 0.2) {
      totalRisk = Math.max(0, totalRisk - 10);
      mitigatingFactors.push(`Configured ML model scored text content as low risk (${input.mlScore}).`);
    }
  } else {
    reasoningChain.push('--- Evaluation Stage 4: ML Model (Unconfigured / Bypassed) ---');
  }

  // Final score clamping
  const normalizedScore = Math.min(100, Math.max(0, totalRisk));
  reasoningChain.push(`Final cumulative risk score: ${normalizedScore}/100.`);

  // Determine Assessment Label
  let label: AssessmentLabel;
  let confidenceLevel: 'high' | 'medium' | 'low';
  let summary: string;

  if (hasAnchorMismatch || totalRisk >= 65) {
    label = 'likely_phishing';
    confidenceLevel = hasAnchorMismatch || primaryRiskFactors.length >= 2 ? 'high' : 'medium';
    summary = `Likely Phishing (Risk Score ${normalizedScore}/100): High-confidence malicious indicators detected, including ${primaryRiskFactors[0] || 'critical authentication and identity failures'}. Immediate mitigation recommended.`;
  } else if (totalRisk >= 35) {
    label = 'potentially_suspicious';
    confidenceLevel = 'medium';
    summary = `Potentially Suspicious (Risk Score ${normalizedScore}/100): Moderate anomalies detected. While definite malicious payload was not conclusively established, ${primaryRiskFactors[0] || 'several indicators'} warrant analyst review.`;
  } else if (totalRisk >= 15 && (!input.hasAuthenticationHeaders || !input.hasReceivedChain)) {
    label = 'inconclusive';
    confidenceLevel = 'low';
    summary = `Inconclusive Analysis (Risk Score ${normalizedScore}/100): Key evidence layers (e.g. Received chain or authentication headers) were omitted in the input. Conclusions cannot be affirmed with high confidence.`;
  } else {
    label = 'likely_legitimate';
    confidenceLevel = (input.authFindings.spf.result === 'pass' && input.authFindings.dkim.result === 'pass') ? 'high' : 'medium';
    summary = `Likely Legitimate (Risk Score ${normalizedScore}/100): No critical deception signatures observed. Authentication and sender alignment conform to standard expectations.`;
  }

  return {
    label,
    confidenceLevel,
    score: normalizedScore,
    summary,
    primaryRiskFactors,
    mitigatingFactors,
    reasoningChain
  };
}
