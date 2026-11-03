import { CanonicalExportData, ExportOptions } from './exportTypes';
import { generateExportFilename } from './exportDataBuilder';

/**
 * Computes SHA-256 hex string in both Browser and Node.js environments
 */
export async function computeSha256Hex(data: string): Promise<string> {
  // 1. Browser Web Crypto API
  if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    const encoder = new TextEncoder();
    const buffer = encoder.encode(data);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // 2. Node.js Crypto API fallback
  try {
    const nodeCrypto = await import('crypto');
    return nodeCrypto.createHash('sha256').update(data).digest('hex');
  } catch {
    // Basic fallback if crypto is unavailable
    return 'checksum_unavailable';
  }
}

export interface JsonExportResult {
  filename: string;
  jsonString: string;
  checksumSha256?: string;
  mimeType: string;
}

/**
 * Generates a valid, structured, machine-readable JSON export conforming to Schema 1.0.0.
 * Preserves all original values, nulls, and unknown states without falsifying evidence.
 */
export async function generateJsonExport(
  exportData: CanonicalExportData,
  options: ExportOptions = {}
): Promise<JsonExportResult> {
  const filename = generateExportFilename(exportData.summary.investigationId, 'json');

  // Clone data for checksum calculation
  const exportPayload: CanonicalExportData = JSON.parse(JSON.stringify(exportData));

  // Compute canonical checksum before embedding it in metadata
  if (options.includeSha256Checksum !== false) {
    const canonicalText = JSON.stringify(exportPayload);
    const checksum = await computeSha256Hex(canonicalText);
    exportPayload.metadata.checksumSha256 = checksum;
  }

  const jsonString = JSON.stringify(exportPayload, null, 2);

  return {
    filename,
    jsonString,
    checksumSha256: exportPayload.metadata.checksumSha256,
    mimeType: 'application/json'
  };
}
