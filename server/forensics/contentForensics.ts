import { 
  ExtractedUrl, 
  EvidenceFinding 
} from '../../src/types/forensics';

const KNOWN_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 
  'ow.ly', 'cutt.ly', 'rebrand.ly', 'rb.gy', 's.id', 'shorturl.at'
]);

const HIGH_PROFILE_BRANDS = [
  'paypal', 'microsoft', 'google', 'apple', 'amazon', 'netflix', 
  'bankofamerica', 'chase', 'wellsfargo', 'dhl', 'fedex', 'usps',
  'docuSign', 'dropbox', 'facebook', 'instagram', 'linkedin', 'irs'
];

/**
 * Defangs a URL for safe analyst display
 */
export function defangUrl(url: string): string {
  return url
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/\./g, '[.]');
}

/**
 * Defangs a domain or IP for safe analyst display
 */
export function defangEntity(entity: string): string {
  return entity.replace(/\./g, '[.]');
}

/**
 * Extracts links, anchors, and anchor text from HTML
 */
function extractHtmlLinks(html: string): Array<{ href: string; text: string }> {
  const links: Array<{ href: string; text: string }> = [];
  // Safe regex match on <a ... href="..." ...>text</a>
  const anchorRegex = /<a\s+(?:[^>]*?\s+)?href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let match;

  while ((match = anchorRegex.exec(html)) !== null) {
    const href = match[1].trim();
    // Strip tags from anchor text
    const text = match[2].replace(/<[^>]+>/g, '').trim();
    if (href && !href.startsWith('mailto:') && !href.startsWith('javascript:') && !href.startsWith('#')) {
      links.push({ href, text });
    }
  }

  return links;
}

/**
 * Extracts plain-text URLs using standard URI regex
 */
function extractTextUrls(text: string): string[] {
  const urlRegex = /\b(?:https?):\/\/[^\s<>'")]+[^\s<>'").,;:!?]/gi;
  return text.match(urlRegex) || [];
}

/**
 * Analyzes URLs and domains in text and HTML
 */
export function analyzeContentUrls(
  text: string, 
  html: string,
  senderDomain?: string
): { urls: ExtractedUrl[]; domains: string[]; contentFindings: EvidenceFinding[] } {
  const foundUrlsMap = new Map<string, { href: string; text?: string }>();

  // Extract from HTML with display text
  if (html) {
    const htmlLinks = extractHtmlLinks(html);
    for (const l of htmlLinks) {
      foundUrlsMap.set(l.href, l);
    }
  }

  // Extract from plain text
  const textUrls = extractTextUrls(text);
  for (const tu of textUrls) {
    if (!foundUrlsMap.has(tu)) {
      foundUrlsMap.set(tu, { href: tu });
    }
  }

  const urls: ExtractedUrl[] = [];
  const domainSet = new Set<string>();
  const contentFindings: EvidenceFinding[] = [];
  const now = new Date().toISOString();

  let linkIndex = 0;
  for (const [, item] of foundUrlsMap) {
    linkIndex++;
    const rawUrl = item.href;
    const displayText = item.text;

    let parsedUrl: URL | null = null;
    try {
      parsedUrl = new URL(rawUrl);
    } catch {
      // Malformed URL
      continue;
    }

    const domain = parsedUrl.hostname.toLowerCase();
    domainSet.add(domain);

    const protocol = parsedUrl.protocol.replace(':', '');
    const port = parsedUrl.port ? parseInt(parsedUrl.port, 10) : undefined;
    const isIpBased = /^\[?(?:\d{1,3}\.){3}\d{1,3}\]?$/.test(domain) || domain.includes(':');
    const isPunycode = domain.startsWith('xn--') || domain.includes('.xn--');
    const isShortener = KNOWN_SHORTENERS.has(domain);
    const suspiciousFlags: string[] = [];

    // Check IP-based URLs
    if (isIpBased) {
      suspiciousFlags.push('Direct IP address used as URL host instead of domain name.');
      contentFindings.push({
        findingId: `URL-IP-${linkIndex}`,
        findingType: 'IP_Based_URL',
        value: defangUrl(rawUrl),
        status: 'fail',
        source: 'Email Body Link',
        observedAt: now,
        explanation: `Link points directly to an IP address (${defangEntity(domain)}) instead of a registered domain. Attackers use raw IP links to evade domain reputation and blacklist filters.`,
        confidence: 0.95,
        supportingEvidenceReferences: [rawUrl]
      });
    }

    // Check unusual ports
    if (port && port !== 80 && port !== 443 && port !== 8080 && port !== 8443) {
      suspiciousFlags.push(`Non-standard web port :${port} detected.`);
      contentFindings.push({
        findingId: `URL-PORT-${linkIndex}`,
        findingType: 'Unusual_Port_URL',
        value: `${defangEntity(domain)}:${port}`,
        status: 'warning',
        source: 'Email Body Link',
        observedAt: now,
        explanation: `Link routes over non-standard port ${port}. Legitimate consumer and corporate services almost exclusively communicate over 80 and 443.`,
        confidence: 0.85,
        supportingEvidenceReferences: [rawUrl]
      });
    }

    // Check Punycode / IDN
    if (isPunycode) {
      suspiciousFlags.push('Punycode/IDN internationalized domain detected.');
      contentFindings.push({
        findingId: `URL-PUNY-${linkIndex}`,
        findingType: 'Punycode_Domain_Homoglyph',
        value: defangEntity(domain),
        status: 'fail',
        source: 'Email Body Link',
        observedAt: now,
        explanation: `Domain uses Punycode prefix 'xn--' (${defangEntity(domain)}). Attackers frequently register lookalike internationalized domains with homoglyph characters (e.g. Cyrillic 'a' vs Latin 'a') to mimic trusted domains.`,
        confidence: 0.9,
        supportingEvidenceReferences: [rawUrl]
      });
    }

    // Check shortener
    if (isShortener) {
      suspiciousFlags.push('Known URL shortener hiding ultimate landing destination.');
      contentFindings.push({
        findingId: `URL-SHORT-${linkIndex}`,
        findingType: 'URL_Shortener_Obfuscation',
        value: defangUrl(rawUrl),
        status: 'warning',
        source: 'Email Body Link',
        observedAt: now,
        explanation: `Link uses shortener service '${domain}', which obscures the destination target from mail filters and security scanners.`,
        confidence: 0.75,
        supportingEvidenceReferences: [rawUrl]
      });
    }

    // Check Anchor Display Text vs Href Mismatch (classic phishing attack)
    let isMismatch = false;
    if (displayText) {
      const displayDomainMatch = displayText.match(/\b([a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?)\b/);
      if (displayDomainMatch) {
        const displayedDomain = displayDomainMatch[1].toLowerCase();
        if (displayedDomain !== domain && !domain.endsWith(`.${displayedDomain}`)) {
          isMismatch = true;
          suspiciousFlags.push(`Display text shows '${displayedDomain}' but actual link destination is '${domain}'.`);
          contentFindings.push({
            findingId: `URL-MISMATCH-${linkIndex}`,
            findingType: 'Anchor_Text_Divergence',
            value: `Visual: "${displayText}" -> Actual: ${defangUrl(rawUrl)}`,
            status: 'fail',
            source: 'HTML Anchor Element',
            observedAt: now,
            explanation: `The clickable text displays '${displayedDomain}', misleading the recipient into believing they are navigating to that domain, whereas the actual HTML href points to '${domain}'. This is a high-confidence credential harvesting signature.`,
            confidence: 0.98,
            supportingEvidenceReferences: [rawUrl]
          });
        }
      }
    }

    // Check Brand Impersonation in Link Domain
    for (const brand of HIGH_PROFILE_BRANDS) {
      if (domain.includes(brand) && !domain.endsWith(`${brand}.com`) && !domain.endsWith(`${brand}.net`) && !domain.endsWith(`${brand}.org`)) {
        // e.g. paypal-security-update.xyz or login-microsoft365.online
        suspiciousFlags.push(`Domain contains brand keyword '${brand}' with suspicious peripheral structure.`);
        contentFindings.push({
          findingId: `URL-BRAND-${linkIndex}-${brand}`,
          findingType: 'Brand_Keyword_Typosquat',
          value: defangEntity(domain),
          status: 'fail',
          source: 'Link Hostname',
          observedAt: now,
          explanation: `Domain '${defangEntity(domain)}' embeds major brand keyword '${brand}', but does not belong to the authentic brand organization. Attackers routinely craft lookalike subdomains or compound names.`,
          confidence: 0.9,
          supportingEvidenceReferences: [rawUrl]
        });
        break;
      }
    }

    urls.push({
      url: rawUrl,
      defangedUrl: defangUrl(rawUrl),
      domain,
      protocol,
      port,
      isIpBased,
      isPunycode,
      isShortener,
      suspiciousFlags,
      displayText,
      isMismatch
    });
  }

  // Analyze text for social engineering / urgency / coercion cues
  const combinedText = `${text} ${html}`.toLowerCase();
  
  // Urgency cues
  const urgencyMatches = combinedText.match(/(?:immediate(?:ly)?|within 24 hours|within 48 hours|suspended immediately|permanent(?:ly)? closed|account termination|urgent action required|final warning|action required within)/gi);
  if (urgencyMatches && urgencyMatches.length > 0) {
    contentFindings.push({
      findingId: 'SOC-001',
      findingType: 'Urgency_Coercion_Language',
      value: `Detected phrases: ${[...new Set(urgencyMatches)].slice(0, 3).join(', ')}`,
      status: 'warning',
      source: 'Email Body Content',
      observedAt: now,
      explanation: 'Content exerts artificial temporal pressure ("urgent action", "within 24 hours") to force hasty recipient decision-making before verifying authenticity.',
      confidence: 0.75,
      supportingEvidenceReferences: ['BodyText']
    });
  }

  // Credential harvesting cues
  const credMatches = combinedText.match(/(?:verify your password|confirm your identity|update billing information|re-authenticate|login to restore access|security credentials|reset password now)/gi);
  if (credMatches && credMatches.length > 0) {
    contentFindings.push({
      findingId: 'SOC-002',
      findingType: 'Credential_Harvesting_Language',
      value: `Detected prompts: ${[...new Set(credMatches)].slice(0, 3).join(', ')}`,
      status: 'warning',
      source: 'Email Body Content',
      observedAt: now,
      explanation: 'Content solicits login credential re-verification, password reset, or payment details directly through unverified links.',
      confidence: 0.8,
      supportingEvidenceReferences: ['BodyText']
    });
  }

  return {
    urls,
    domains: Array.from(domainSet),
    contentFindings
  };
}
