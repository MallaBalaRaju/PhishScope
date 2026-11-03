import { 
  StandardizedModelFeatures, 
  FeatureState, 
  MissingnessState 
} from './contracts';
import { EmailEnvelope, ReceivedHop, ExtractedUrl, AttachmentMetadata } from '../../src/types/forensics';
import { AuthenticationForensicResults } from '../forensics/authForensics';
import { HeaderForensicResults } from '../forensics/headerForensics';

export const FEATURE_SCHEMA_VERSION = '2.0.0';
export const FEATURE_EXTRACTOR_VERSION = '1.1.0';

export interface FeatureExtractionContext {
  envelope: EmailEnvelope;
  rawHeaders: Record<string, string | string[]>;
  bodyText: string;
  bodyHtml: string;
  hasHeaders: boolean;
  hasReceivedChain: boolean;
  hasAuthenticationHeaders: boolean;
  headerFindings: HeaderForensicResults;
  authFindings: AuthenticationForensicResults;
  urls: ExtractedUrl[];
  attachments: AttachmentMetadata[];
}

/**
 * Extracts immutable standardized features from parsed email artifacts.
 * Strictly avoids coercing missing or unverified evidence into boolean false.
 */
export function extractStandardizedModelFeatures(
  ctx: FeatureExtractionContext
): StandardizedModelFeatures {
  const extractedAt = new Date().toISOString();
  const missingness: Record<string, MissingnessState> = {};
  const provenance: Record<string, string> = {};

  // 1. Lexical Features
  const subject = ctx.envelope.subject || null;
  const bodyClean = ctx.bodyText ? ctx.bodyText.trim() : null;
  const hasHtml: FeatureState = ctx.bodyHtml ? 'true' : 'false';
  const textLength = bodyClean ? bodyClean.length : 0;
  const wordCount = bodyClean ? bodyClean.split(/\s+/).filter(Boolean).length : 0;

  missingness['subject'] = subject !== null ? 'present' : 'missing';
  missingness['body'] = bodyClean !== null ? 'present' : 'missing';
  provenance['subject'] = 'RFC 5322 Subject Header';
  provenance['body'] = 'MIME Text/Plain Section';

  // 2. Authentication Four-State Features
  let spfPass: FeatureState = 'unknown';
  let dkimPass: FeatureState = 'unknown';
  let dmarcPass: FeatureState = 'unknown';
  let isDomainAligned: FeatureState = 'unknown';

  if (!ctx.hasAuthenticationHeaders) {
    missingness['authentication'] = 'missing';
    provenance['authentication'] = 'Omitted in input headers';
  } else {
    missingness['authentication'] = 'present';
    provenance['authentication'] = 'Authentication-Results & Received-SPF headers';

    // SPF
    if (ctx.authFindings.spf.result === 'pass') {
      spfPass = 'true';
    } else if (ctx.authFindings.spf.result === 'fail' || ctx.authFindings.spf.result === 'softfail') {
      spfPass = 'false';
    } else if (ctx.authFindings.spf.result === 'missing') {
      spfPass = 'unknown';
    } else {
      spfPass = 'unknown';
    }

    // DKIM
    if (ctx.authFindings.dkim.result === 'pass') {
      dkimPass = 'true';
    } else if (ctx.authFindings.dkim.result === 'fail') {
      dkimPass = 'false';
    } else if (ctx.authFindings.dkim.result === 'missing') {
      dkimPass = 'unknown';
    } else {
      dkimPass = 'unknown';
    }

    // DMARC
    if (ctx.authFindings.dmarc.result === 'pass') {
      dmarcPass = 'true';
    } else if (ctx.authFindings.dmarc.result === 'fail') {
      dmarcPass = 'false';
    } else {
      dmarcPass = 'unknown';
    }

    // Domain Alignment
    const spfAlign = ctx.authFindings.spf.alignmentWithFrom;
    const dkimAlign = ctx.authFindings.dkim.alignmentWithFrom;
    if (spfAlign === 'strict' || spfAlign === 'relaxed' || dkimAlign === 'strict' || dkimAlign === 'relaxed') {
      isDomainAligned = 'true';
    } else if (spfAlign === 'misaligned' && dkimAlign === 'misaligned') {
      isDomainAligned = 'false';
    } else {
      isDomainAligned = 'unknown';
    }
  }

  // 3. Routing Four-State Features
  let hasNegativeTransitTime: FeatureState = 'not_applicable';
  let hasPrivateOriginHop: FeatureState = 'not_applicable';
  let hasIntermediateLoopback: FeatureState = 'not_applicable';
  let totalHops: number | null = null;
  const candidateIpCount = ctx.headerFindings.candidateSourceIps.length;

  if (!ctx.hasReceivedChain) {
    missingness['routing'] = 'missing';
    provenance['routing'] = 'No Received headers in input';
  } else {
    missingness['routing'] = 'present';
    provenance['routing'] = 'Parsed chronological Received hops';
    totalHops = ctx.headerFindings.receivedHops.length;

    const hasNeg = ctx.headerFindings.receivedHops.some(h => 
      h.suspiciousSignals.some(s => s.toLowerCase().includes('negative transit time'))
    );
    hasNegativeTransitTime = hasNeg ? 'true' : 'false';

    const firstHop = ctx.headerFindings.receivedHops[0];
    hasPrivateOriginHop = (firstHop && (firstHop.ipType === 'private' || firstHop.ipType === 'loopback')) 
      ? 'true' 
      : 'false';

    const loopbackIntermediate = ctx.headerFindings.receivedHops.some((h, idx) => 
      idx > 0 && h.ipType === 'loopback'
    );
    hasIntermediateLoopback = loopbackIntermediate ? 'true' : 'false';
  }

  // 4. Content & URL Features
  let hasDirectIpUrls: FeatureState = 'not_applicable';
  let hasAnchorTextDivergence: FeatureState = 'not_applicable';
  let hasPunycodeDomains: FeatureState = 'not_applicable';
  let hasShortenerUrls: FeatureState = 'not_applicable';
  const totalUrlCount = ctx.urls.length;

  if (totalUrlCount === 0) {
    missingness['urls'] = 'inapplicable';
    provenance['urls'] = 'No URLs present in message body';
  } else {
    missingness['urls'] = 'present';
    provenance['urls'] = 'Extracted HTML anchor hrefs and text tokens';

    hasDirectIpUrls = ctx.urls.some(u => u.isIpBased) ? 'true' : 'false';
    hasAnchorTextDivergence = ctx.urls.some(u => u.isMismatch) ? 'true' : 'false';
    hasPunycodeDomains = ctx.urls.some(u => u.isPunycode) ? 'true' : 'false';
    hasShortenerUrls = ctx.urls.some(u => u.isShortener) ? 'true' : 'false';
  }

  // Brand mentions
  const brandKeywords = ['paypal', 'microsoft', 'google', 'apple', 'amazon', 'bank of america', 'wells fargo', 'chase'];
  let brandCount = 0;
  const combined = `${ctx.bodyText} ${ctx.envelope.subject || ''}`.toLowerCase();
  for (const b of brandKeywords) {
    if (combined.includes(b)) brandCount++;
  }

  // 5. Attachment Features
  let hasSuspiciousAttachmentType: FeatureState = 'not_applicable';
  const attachmentCount = ctx.attachments.length;

  if (attachmentCount === 0) {
    missingness['attachments'] = 'inapplicable';
    provenance['attachments'] = 'No attachments declared in MIME sections';
  } else {
    missingness['attachments'] = 'present';
    provenance['attachments'] = 'MIME part Content-Disposition & Content-Type headers';
    hasSuspiciousAttachmentType = ctx.attachments.some(a => a.isSuspiciousExtension) ? 'true' : 'false';
  }

  return {
    schemaVersion: FEATURE_SCHEMA_VERSION,
    extractorVersion: FEATURE_EXTRACTOR_VERSION,
    extractedAt,
    subjectText: subject,
    bodyCleanText: bodyClean,
    hasHtmlMarkup: hasHtml,
    textLengthChars: textLength,
    wordCount,
    spfPass,
    dkimPass,
    dmarcPass,
    isDomainAligned,
    hasNegativeTransitTime,
    hasPrivateOriginHop,
    hasIntermediateLoopback,
    totalHopCount: totalHops,
    candidateIpCount,
    hasDirectIpUrls,
    hasAnchorTextDivergence,
    hasPunycodeDomains,
    hasShortenerUrls,
    totalUrlCount,
    suspiciousBrandMentionCount: brandCount,
    hasSuspiciousAttachmentType,
    attachmentCount,
    missingnessMetadata: missingness,
    featureProvenance: provenance
  };
}
