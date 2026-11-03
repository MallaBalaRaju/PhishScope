import { EmailAnalysis } from '../types/forensics';
import { ExportFormat, ExportOptions, CanonicalExportData } from './exportTypes';
import { buildCanonicalExportData, generateExportFilename } from './exportDataBuilder';
import { generateJsonExport } from './jsonExporter';
import { generatePdfExport } from './pdfExporter';
import { generateExcelExport } from './excelExporter';

export * from './exportTypes';
export * from './exportDataBuilder';
export * from './jsonExporter';
export * from './pdfExporter';
export * from './excelExporter';

/**
 * Triggers native browser file download safely without opening popups
 */
export function triggerBrowserDownload(
  data: Uint8Array | string,
  filename: string,
  mimeType: string
): void {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    return; // Headless / Node testing environment
  }

  const blob = data instanceof Uint8Array 
    ? new Blob([data.buffer as ArrayBuffer], { type: mimeType })
    : new Blob([data], { type: `${mimeType};charset=utf-8` });

  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  anchor.style.display = 'none';

  document.body.appendChild(anchor);
  anchor.click();

  setTimeout(() => {
    document.body.removeChild(anchor);
    window.URL.revokeObjectURL(url);
  }, 150);
}

export interface ExportExecutionResult {
  format: ExportFormat;
  filename: string;
  mimeType: string;
  checksumSha256?: string;
  bytesCount: number;
}

/**
 * Master Export Orchestrator
 * Captures canonical snapshot and executes the requested export pipeline (JSON, PDF, XLSX).
 */
export async function executeExportInvestigation(
  analysis: EmailAnalysis,
  format: ExportFormat,
  options: ExportOptions = {},
  autoDownload = true
): Promise<ExportExecutionResult> {
  if (!analysis) {
    throw new Error('Export failed: No investigation is currently selected.');
  }

  // 1. Build canonical snapshot
  const exportData: CanonicalExportData = buildCanonicalExportData(analysis, format, options);

  let filename = '';
  let mimeType = '';
  let dataPayload: Uint8Array | string;
  let checksumSha256: string | undefined = undefined;

  switch (format) {
    case 'json': {
      const res = await generateJsonExport(exportData, options);
      filename = res.filename;
      mimeType = res.mimeType;
      dataPayload = res.jsonString;
      checksumSha256 = res.checksumSha256;
      break;
    }
    case 'pdf': {
      const res = generatePdfExport(exportData, options);
      filename = res.filename;
      mimeType = res.mimeType;
      dataPayload = res.binaryBuffer;
      break;
    }
    case 'xlsx': {
      const res = generateExcelExport(exportData, options);
      filename = res.filename;
      mimeType = res.mimeType;
      dataPayload = res.binaryBuffer;
      break;
    }
    default:
      throw new Error(`Unsupported export format: ${format}`);
  }

  // 2. Trigger browser download if requested
  if (autoDownload) {
    triggerBrowserDownload(dataPayload, filename, mimeType);
  }

  const bytesCount = typeof dataPayload === 'string' 
    ? new TextEncoder().encode(dataPayload).length 
    : dataPayload.length;

  return {
    format,
    filename,
    mimeType,
    checksumSha256,
    bytesCount
  };
}
