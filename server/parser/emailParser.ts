import { simpleParser, ParsedMail, HeaderValue } from 'mailparser';
import crypto from 'crypto';
import { 
  InputType, 
  EmailEnvelope, 
  AttachmentMetadata 
} from '../../src/types/forensics';

export interface ParsedEmailResult {
  inputType: InputType;
  envelope: EmailEnvelope;
  rawHeaders: Record<string, string | string[]>;
  receivedHeaders: string[];
  authResultsHeaders: string[];
  receivedSpfHeaders: string[];
  dkimSignatureHeaders: string[];
  bodyText: string;
  bodyHtml: string;
  attachments: AttachmentMetadata[];
  parsingStatus: {
    status: 'success' | 'partial' | 'error';
    errors: string[];
    warnings: string[];
    mimeVersion?: string;
    contentType?: string;
  };
  availableEvidence: {
    hasHeaders: boolean;
    hasReceivedChain: boolean;
    hasAuthenticationHeaders: boolean;
    hasBodyText: boolean;
    hasBodyHtml: boolean;
    hasAttachments: boolean;
  };
}

const SUSPICIOUS_EXTENSIONS = new Set([
  'exe', 'scr', 'iso', 'img', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 
  'hta', 'bat', 'cmd', 'ps1', 'psm1', 'jar', 'pif', 'com', 'xlsm', 'docm', 
  'pptm', 'dotm', 'xltm', 'xlam', 'svg', 'lnk', 'chm'
]);

/**
 * Extracts domain name from an email address
 */
export function extractDomain(emailAddress?: string): string {
  if (!emailAddress) return '';
  const clean = emailAddress.replace(/[<>]/g, '').trim();
  const atIdx = clean.lastIndexOf('@');
  if (atIdx !== -1 && atIdx < clean.length - 1) {
    return clean.slice(atIdx + 1).toLowerCase();
  }
  return '';
}

/**
 * Detects whether pasted content is raw email, headers-only, or body-only
 */
export function detectInputType(content: string, isFileUpload = false): InputType {
  if (isFileUpload) return 'eml_file';

  const trimmed = content.trim();
  const hasReceived = /(?:^|\n)received:\s+/i.test(trimmed);
  const hasFrom = /(?:^|\n)from:\s+/i.test(trimmed);
  const hasSubject = /(?:^|\n)subject:\s+/i.test(trimmed);
  const hasEmptyLineDivider = /\r?\n\r?\n/.test(trimmed);

  if ((hasReceived || hasFrom) && hasSubject && hasEmptyLineDivider) {
    return 'pasted_raw';
  }

  if ((hasReceived || hasFrom || hasSubject) && !hasEmptyLineDivider) {
    return 'pasted_headers';
  }

  if (!hasReceived && !hasFrom && !hasSubject) {
    return 'pasted_body';
  }

  return 'pasted_raw';
}

/**
 * Parses raw or pasted email safely using mailparser
 */
export async function parseEmail(
  rawInput: string | Buffer, 
  isFileUpload = false
): Promise<ParsedEmailResult> {
  const inputStr = typeof rawInput === 'string' ? rawInput : rawInput.toString('utf-8');
  const inputType = detectInputType(inputStr, isFileUpload);

  const errors: string[] = [];
  const warnings: string[] = [];

  let parsed: ParsedMail | null = null;
  try {
    parsed = await simpleParser(rawInput, {
      skipHtmlToText: false,
      skipTextToHtml: true,
      skipImageLinks: true
    });
  } catch (err: any) {
    errors.push(`MIME parsing error: ${err.message || 'Unknown parsing exception'}`);
  }

  // Extract raw headers map
  const rawHeaders: Record<string, string | string[]> = {};
  const receivedHeaders: string[] = [];
  const authResultsHeaders: string[] = [];
  const receivedSpfHeaders: string[] = [];
  const dkimSignatureHeaders: string[] = [];

  if (parsed?.headers) {
    for (const [key, value] of parsed.headers) {
      const headerKey = key.toLowerCase();
      
      // Preserve original header representation
      if (Array.isArray(value)) {
        rawHeaders[headerKey] = value.map(v => typeof v === 'object' && v !== null && 'text' in v ? (v as any).text : String(v));
      } else if (typeof value === 'object' && value !== null && 'text' in value) {
        rawHeaders[headerKey] = (value as any).text;
      } else {
        rawHeaders[headerKey] = String(value);
      }

      if (headerKey === 'received') {
        if (Array.isArray(value)) {
          for (const v of value) {
            receivedHeaders.push(typeof v === 'object' && v !== null && 'text' in v ? (v as any).text : String(v));
          }
        } else {
          receivedHeaders.push(typeof value === 'object' && value !== null && 'text' in value ? (value as any).text : String(value));
        }
      } else if (headerKey === 'authentication-results') {
        if (Array.isArray(value)) {
          authResultsHeaders.push(...value.map(v => String(typeof v === 'object' && v !== null && 'text' in v ? (v as any).text : v)));
        } else {
          authResultsHeaders.push(String(typeof value === 'object' && value !== null && 'text' in value ? (value as any).text : value));
        }
      } else if (headerKey === 'received-spf') {
        if (Array.isArray(value)) {
          receivedSpfHeaders.push(...value.map(v => String(typeof v === 'object' && v !== null && 'text' in v ? (v as any).text : v)));
        } else {
          receivedSpfHeaders.push(String(typeof value === 'object' && value !== null && 'text' in value ? (value as any).text : value));
        }
      } else if (headerKey === 'dkim-signature') {
        if (Array.isArray(value)) {
          dkimSignatureHeaders.push(...value.map(v => String(typeof v === 'object' && v !== null && 'text' in v ? (v as any).text : v)));
        } else {
          dkimSignatureHeaders.push(String(typeof value === 'object' && value !== null && 'text' in value ? (value as any).text : value));
        }
      }
    }
  }

  // Handle manual header extraction fallback if mailparser missed multi-line headers in partial input
  if (receivedHeaders.length === 0) {
    const manualReceived = inputStr.match(/(?:^|\n)Received:[^\n]*(?:\n\s+[^\n]*)*/gi);
    if (manualReceived) {
      for (const rec of manualReceived) {
        const clean = rec.replace(/^Received:\s*/i, '').trim();
        receivedHeaders.push(clean);
      }
    }
  }

  // Build envelope
  const fromObj = parsed?.from?.value?.[0];
  const envelope: EmailEnvelope = {
    from: fromObj ? {
      name: fromObj.name || undefined,
      address: fromObj.address || '',
      domain: extractDomain(fromObj.address)
    } : undefined,
    to: (parsed?.to ? (Array.isArray(parsed.to) ? parsed.to : [parsed.to]) : []).flatMap(addr => 
      addr.value.map(v => ({
        name: v.name || undefined,
        address: v.address || '',
        domain: extractDomain(v.address)
      }))
    ),
    cc: (parsed?.cc ? (Array.isArray(parsed.cc) ? parsed.cc : [parsed.cc]) : []).flatMap(addr => 
      addr.value.map(v => ({
        name: v.name || undefined,
        address: v.address || '',
        domain: extractDomain(v.address)
      }))
    ),
    replyTo: parsed?.replyTo?.value?.[0] ? {
      name: parsed.replyTo.value[0].name || undefined,
      address: parsed.replyTo.value[0].address || '',
      domain: extractDomain(parsed.replyTo.value[0].address)
    } : undefined,
    returnPath: (parsed as any)?.returnPath || (rawHeaders['return-path'] ? String(rawHeaders['return-path']).replace(/[<>]/g, '').trim() : undefined),
    returnPathDomain: undefined,
    messageId: parsed?.messageId || (rawHeaders['message-id'] ? String(rawHeaders['message-id']) : undefined),
    date: parsed?.date ? parsed.date.toISOString() : (rawHeaders['date'] ? String(rawHeaders['date']) : undefined),
    subject: parsed?.subject || (rawHeaders['subject'] ? String(rawHeaders['subject']) : undefined)
  };

  if (envelope.returnPath) {
    envelope.returnPathDomain = extractDomain(envelope.returnPath);
  }

  // Handle attachments safely
  const attachments: AttachmentMetadata[] = [];
  if (parsed?.attachments && Array.isArray(parsed.attachments)) {
    for (const att of parsed.attachments) {
      const filename = att.filename || 'unnamed_attachment';
      const ext = filename.split('.').pop()?.toLowerCase() || '';
      const isSuspicious = SUSPICIOUS_EXTENSIONS.has(ext);

      // Compute sha256 checksum
      const hash = crypto.createHash('sha256');
      if (att.content) {
        hash.update(att.content);
      }
      const checksumSha256 = hash.digest('hex');

      attachments.push({
        filename,
        contentType: att.contentType || 'application/octet-stream',
        size: att.size || 0,
        checksumSha256,
        isSuspiciousExtension: isSuspicious,
        suspicionReason: isSuspicious ? `File extension .${ext} is associated with executable or script payload execution.` : undefined
      });
    }
  }

  const bodyText = parsed?.text || '';
  const bodyHtml = typeof parsed?.html === 'string' ? parsed.html : '';

  const hasHeaders = Object.keys(rawHeaders).length > 0 || !!envelope.from || !!envelope.subject;
  const hasReceivedChain = receivedHeaders.length > 0;
  const hasAuthenticationHeaders = authResultsHeaders.length > 0 || receivedSpfHeaders.length > 0 || dkimSignatureHeaders.length > 0;
  const hasBodyText = bodyText.trim().length > 0;
  const hasBodyHtml = bodyHtml.trim().length > 0;
  const hasAttachments = attachments.length > 0;

  if (!hasHeaders) {
    warnings.push('No RFC 5322 header block detected in the input.');
  }
  if (!hasReceivedChain) {
    warnings.push('Received headers are absent; SMTP routing path cannot be reconstructed.');
  }
  if (!hasAuthenticationHeaders) {
    warnings.push('Authentication-Results and SPF headers are absent; authentication cannot be established from headers.');
  }

  return {
    inputType,
    envelope,
    rawHeaders,
    receivedHeaders,
    authResultsHeaders,
    receivedSpfHeaders,
    dkimSignatureHeaders,
    bodyText,
    bodyHtml,
    attachments,
    parsingStatus: {
      status: errors.length > 0 ? 'error' : (warnings.length > 0 ? 'partial' : 'success'),
      errors,
      warnings,
      mimeVersion: rawHeaders['mime-version'] ? String(rawHeaders['mime-version']) : undefined,
      contentType: rawHeaders['content-type'] ? String(rawHeaders['content-type']) : undefined
    },
    availableEvidence: {
      hasHeaders,
      hasReceivedChain,
      hasAuthenticationHeaders,
      hasBodyText,
      hasBodyHtml,
      hasAttachments
    }
  };
}
