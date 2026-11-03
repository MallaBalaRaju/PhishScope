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
  hasBodyText: boolean;
  hasBodyHtml: boolean;
  hasAttachments: boolean;
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
  score: number; // Combined/clamped risk score (0 - 100)
  observedRiskScore: number;
  evidenceCoverageScore: number;
  availableEvidenceCategories: string[];
  unavailableEvidenceCategories: string[];
  summary: string;
  primaryRiskFactors: string[];
  mitigatingFactors: string[];
  reasoningChain: string[];
}

/**
 * Deterministic Evidence Fusion Engine
 * Strictly separates:
 * 1. Observed Risk Score (threat indicators detected)
 * 2. Evidence Coverage (completeness of forensic data)
 * 3. Assessment Confidence (certainty derived from coverage & signal consistency)
 * 4. ML Contribution (transparently isolated)
 *
 * Core Integrity Law: Missing evidence is NEVER interpreted as benign evidence!
 */
export function fuseEvidence(input: EvidenceFusionInput): FusionAssessmentOutput {
  const reasoningChain: string[] = [];
  const primaryRiskFactors: string[] = [];
  const mitigatingFactors: string[] = [];
  const availableEvidenceCategories: string[] = [];
  const unavailableEvidenceCategories: string[] = [];

  // --- Step 1: Evidence Coverage Assessment ---
  let coverageWeight = 0;

  if (input.hasHeaders) {
    coverageWeight += 25;
    availableEvidenceCategories.push('RFC 5322 Envelope Headers');
  } else {
    unavailableEvidenceCategories.push('RFC 5322 Envelope Headers (missing)');
  }

  if (input.hasReceivedChain && input.headerFindings.receivedHops.length > 0) {
    coverageWeight += 20;
    availableEvidenceCategories.push(`Received Relay Chain (${input.headerFindings.receivedHops.length} hops)`);
  } else {
    unavailableEvidenceCategories.push('Received Relay Chain (missing)');
  }

  if (input.hasAuthenticationHeaders && input.authFindings.authResultsHeaderPresent) {
    coverageWeight += 25;
    availableEvidenceCategories.push('MTA Authentication Headers (SPF/DKIM/DMARC)');
  } else {
    unavailableEvidenceCategories.push('MTA Authentication Headers (missing)');
  }

  if (input.hasBodyText || input.hasBodyHtml) {
    coverageWeight += 15;
    availableEvidenceCategories.push('Message Body Content (Text/HTML)');
  } else {
    unavailableEvidenceCategories.push('Message Body Content (missing)');
  }

  // URL / Attachment coverage
  coverageWeight += 15;
  if (input.urls.length > 0) {
    availableEvidenceCategories.push(`Extracted Hyperlinks (${input.urls.length} URLs inspected)`);
  }
  if (input.attachments.length > 0) {
    availableEvidenceCategories.push(`File Attachments (${input.attachments.length} items inspected)`);
  }
  if (input.urls.length === 0 && input.attachments.length === 0) {
    availableEvidenceCategories.push('URL/Attachment Verification (None present in message)');
  }

  const evidenceCoverageScore = Math.min(100, coverageWeight);
  reasoningChain.push(`--- Stage 1: Evidence Coverage Audit (${evidenceCoverageScore}% coverage) ---`);
  reasoningChain.push(`Available categories: ${availableEvidenceCategories.join(', ')}`);
  if (unavailableEvidenceCategories.length > 0) {
    reasoningChain.push(`Unavailable categories: ${unavailableEvidenceCategories.join(', ')}`);
  }

  // If evidence is severely deficient (e.g. body-only paste with no headers)
  if (!input.hasHeaders && input.urls.length === 0 && input.attachments.length === 0) {
    return {
      label: 'insufficient_evidence',
      confidenceLevel: 'low',
      score: 15,
      observedRiskScore: 15,
      evidenceCoverageScore,
      availableEvidenceCategories,
      unavailableEvidenceCategories,
      summary: 'Insufficient forensic evidence: The submission lacks RFC 5322 headers, Received routing hops, and actionable URLs/attachments. An authentic verdict cannot be determined.',
      primaryRiskFactors: ['Missing RFC headers', 'Missing Received relay chain', 'No verifiable payload identifiers'],
      mitigatingFactors: [],
      reasoningChain: [
        '1. Envelope headers and Received routing chain are entirely absent.',
        '2. Authentication records (SPF, DKIM, DMARC) could not be verified.',
        '3. Evaluated as Insufficient Evidence with LOW confidence.'
      ]
    };
  }

  let observedThreatPoints = 0;

  // --- Step 2: Authentication Forensics (Max 35 pts) ---
  reasoningChain.push('--- Stage 2: Authentication Evaluation ---');
  if (!input.hasAuthenticationHeaders) {
    observedThreatPoints += 15;
    primaryRiskFactors.push('Unauthenticated message: No SPF, DKIM, or DMARC evaluation records in headers.');
    reasoningChain.push('Authentication headers absent: unauthenticated mail (+15 risk points).');
  } else {
    // SPF
    if (input.authFindings.spf.result === 'fail') {
      observedThreatPoints += 25;
      primaryRiskFactors.push(`SPF hard failure: Sending server unauthorized for ${input.authFindings.spf.domain || 'domain'}.`);
      reasoningChain.push('SPF evaluation resulted in hard FAIL (+25 risk points).');
    } else if (input.authFindings.spf.result === 'softfail') {
      observedThreatPoints += 15;
      primaryRiskFactors.push(`SPF softfail: Sending server is not explicitly designated in ${input.authFindings.spf.domain || 'domain'} SPF record.`);
      reasoningChain.push('SPF evaluation resulted in SOFTFAIL (+15 risk points).');
    } else if (input.authFindings.spf.result === 'pass') {
      mitigatingFactors.push(`SPF passed for '${input.authFindings.spf.domain || 'domain'}'.`);
      reasoningChain.push('SPF evaluation passed (-10 risk offset).');
      observedThreatPoints = Math.max(0, observedThreatPoints - 10);
    }

    // DKIM
    if (input.authFindings.dkim.result === 'fail') {
      observedThreatPoints += 25;
      primaryRiskFactors.push(`DKIM failure: Digital signature failed verification for '${input.authFindings.dkim.domain || 'domain'}'.`);
      reasoningChain.push('DKIM signature failed validation (+25 risk points).');
    } else if (input.authFindings.dkim.result === 'pass') {
      mitigatingFactors.push(`DKIM signature verified for '${input.authFindings.dkim.domain || 'domain'}'.`);
      reasoningChain.push('DKIM signature passed verification (-10 risk offset).');
      observedThreatPoints = Math.max(0, observedThreatPoints - 10);
    }

    // DMARC
    if (input.authFindings.dmarc.result === 'fail') {
      observedThreatPoints += 20;
      primaryRiskFactors.push('DMARC alignment failed: Neither SPF nor DKIM passed with aligned From domain.');
      reasoningChain.push('DMARC alignment failed (+20 risk points).');
    } else if (input.authFindings.dmarc.result === 'pass') {
      mitigatingFactors.push('DMARC policy satisfied with valid domain identifier alignment.');
      reasoningChain.push('DMARC policy satisfied (-15 risk offset).');
      observedThreatPoints = Math.max(0, observedThreatPoints - 15);
    }
  }

  // --- Step 3: Header and Identity Consistency (Max 35 pts) ---
  reasoningChain.push('--- Stage 3: Routing & Identity Forensics ---');
  for (const mismatch of input.headerFindings.identityMismatches) {
    if (mismatch.status === 'fail') {
      observedThreatPoints += 30;
      primaryRiskFactors.push(mismatch.explanation);
      reasoningChain.push(`Severe identity deception: ${mismatch.value} (+30 risk points).`);
    } else if (mismatch.status === 'warning') {
      observedThreatPoints += 15;
      primaryRiskFactors.push(mismatch.explanation);
      reasoningChain.push(`Moderate identity anomaly: ${mismatch.value} (+15 risk points).`);
    }
  }

  for (const anomaly of input.headerFindings.routingAnomalies) {
    observedThreatPoints += 15;
    primaryRiskFactors.push(anomaly.explanation);
    reasoningChain.push(`Routing anomaly: ${anomaly.value} (+15 risk points).`);
  }

  // --- Step 4: Content, URL & Attachment Forensics (Max 40 pts) ---
  reasoningChain.push('--- Stage 4: URL, Content & Attachment Payloads ---');
  let hasAnchorMismatch = false;

  for (const u of input.urls) {
    if (u.isMismatch) {
      hasAnchorMismatch = true;
      observedThreatPoints += 35;
      primaryRiskFactors.push(`Deceptive anchor link: text claims '${u.displayText}' but navigates to '${u.domain}'.`);
      reasoningChain.push(`Deceptive anchor mismatch detected for ${u.domain} (+35 risk points).`);
    }
    if (u.isIpBased) {
      observedThreatPoints += 25;
      primaryRiskFactors.push(`Direct IP link: '${u.domain}' used as URL destination.`);
      reasoningChain.push(`Direct IP link observed (+25 risk points).`);
    }
    if (u.isPunycode) {
      observedThreatPoints += 20;
      primaryRiskFactors.push(`Internationalized Punycode homoglyph: '${u.domain}'.`);
      reasoningChain.push(`Punycode homoglyph observed (+20 risk points).`);
    }
  }

  for (const att of input.attachments) {
    if (att.isSuspiciousExtension) {
      observedThreatPoints += 35;
      primaryRiskFactors.push(`Dangerous file attachment: '${att.filename}' carries high execution risk.`);
      reasoningChain.push(`High-risk executable/script attachment detected: ${att.filename} (+35 risk points).`);
    }
  }

  for (const finding of input.contentFindings) {
    if (finding.findingType.startsWith('Urgency') || finding.findingType.startsWith('Credential')) {
      observedThreatPoints += 10;
      primaryRiskFactors.push(finding.explanation);
      reasoningChain.push(`Social engineering heuristic: ${finding.value} (+10 risk points).`);
    }
  }

  // --- Step 5: ML Contribution (Independent & Calibrated) ---
  if (input.mlConfigured && typeof input.mlScore === 'number') {
    reasoningChain.push(`--- Stage 5: Calibrated ML Input (Score: ${input.mlScore}) ---`);
    if (input.mlScore > 0.7) {
      observedThreatPoints += 15;
      primaryRiskFactors.push(`Configured ML model flagged content patterns (${input.mlScore.toFixed(3)}).`);
    } else if (input.mlScore < 0.2) {
      observedThreatPoints = Math.max(0, observedThreatPoints - 10);
      mitigatingFactors.push(`Configured ML model scored text content as low risk (${input.mlScore.toFixed(3)}).`);
    }
  }

  const normalizedObservedScore = Math.min(100, Math.max(0, observedThreatPoints));
  reasoningChain.push(`Observed risk score: ${normalizedObservedScore}/100.`);

  // --- Step 6: Synthesis & Label Determination ---
  let label: AssessmentLabel;
  let confidenceLevel: 'high' | 'medium' | 'low';
  let summary: string;

  // Rule 1: High malicious signals (anchor deception, extreme risk)
  if (hasAnchorMismatch || normalizedObservedScore >= 65) {
    label = 'likely_phishing';
    confidenceLevel = (hasAnchorMismatch || primaryRiskFactors.length >= 2) ? 'high' : 'medium';
    summary = `Likely Phishing (Risk Score ${normalizedObservedScore}/100, Coverage ${evidenceCoverageScore}%): High-confidence malicious indicators detected (${primaryRiskFactors[0] || 'critical authentication and identity failures'}). Immediate mitigation recommended.`;
  }
  // Rule 2: Moderate malicious signals
  else if (normalizedObservedScore >= 35) {
    label = 'potentially_suspicious';
    confidenceLevel = evidenceCoverageScore >= 60 ? 'medium' : 'low';
    summary = `Potentially Suspicious (Risk Score ${normalizedObservedScore}/100, Coverage ${evidenceCoverageScore}%): Moderate anomalies detected (${primaryRiskFactors[0] || 'several indicators'}). Further analyst inspection advised.`;
  }
  // Rule 3: Low observed score BUT incomplete evidence coverage
  // CRITICAL REQUIREMENT: A low heuristic score in an email with missing headers must NOT produce a high-confidence benign classification!
  else if (evidenceCoverageScore < 65 || !input.hasAuthenticationHeaders || !input.hasReceivedChain) {
    label = 'inconclusive';
    confidenceLevel = 'low';
    summary = `Inconclusive Analysis (Risk Score ${normalizedObservedScore}/100, Coverage ${evidenceCoverageScore}%): Core evidence categories (${unavailableEvidenceCategories.join(', ')}) were omitted. A benign verdict cannot be affirmed without authentication and routing verification.`;
    primaryRiskFactors.push('Incomplete forensic evidence: Missing headers or relay hops prevent origin authentication.');
  }
  // Rule 4: Low observed score WITH full/high evidence coverage and passing authentication
  else {
    const authFullyPassed = (input.authFindings.spf.result === 'pass' && input.authFindings.dkim.result === 'pass');
    label = 'likely_legitimate';
    confidenceLevel = authFullyPassed && evidenceCoverageScore >= 80 ? 'high' : 'medium';
    summary = `Likely Legitimate (Risk Score ${normalizedObservedScore}/100, Coverage ${evidenceCoverageScore}%): Authentication verified (SPF/DKIM/DMARC) with valid identifier alignment and no deceptive indicators.`;
  }

  return {
    label,
    confidenceLevel,
    score: normalizedObservedScore,
    observedRiskScore: normalizedObservedScore,
    evidenceCoverageScore,
    availableEvidenceCategories,
    unavailableEvidenceCategories,
    summary,
    primaryRiskFactors,
    mitigatingFactors,
    reasoningChain
  };
}
