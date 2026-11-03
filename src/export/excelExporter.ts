import * as XLSX from 'xlsx';
import { CanonicalExportData, ExportOptions } from './exportTypes';
import { generateExportFilename } from './exportDataBuilder';

/**
 * Formula Injection Protection (OWASP / CWE-1236)
 * Prepends a single quote (') if untrusted text begins with =, +, -, @, \t, \r, %, or |
 * This forces spreadsheet applications to interpret the cell strictly as literal text.
 */
export function sanitizeSpreadsheetValue(value: any): string | number {
  if (value === null || value === undefined) return 'N/A';
  if (typeof value === 'boolean') return value ? 'TRUE' : 'FALSE';
  if (typeof value === 'number') {
    if (isNaN(value)) return 'N/A';
    return value;
  }
  const str = String(value).trim();
  if (str === '') return '';

  // Check for formula trigger characters
  if (/^[=+\-@\t\r%|]/.test(str)) {
    return `'${str}`;
  }
  return str;
}

/**
 * Utility to convert 2D array of rows into an XLSX worksheet with auto-width,
 * header freezing, and autofilter enabled.
 */
function createWorksheetWithFormatting(
  rows: (string | number)[][],
  minColWidth = 15
): XLSX.WorkSheet {
  const ws: XLSX.WorkSheet = {};
  const range = { s: { c: 0, r: 0 }, e: { c: 0, r: 0 } };

  if (rows.length === 0) {
    ws['!ref'] = 'A1:A1';
    ws['A1'] = { t: 's', v: 'No records available' };
    return ws;
  }

  const colWidths: number[] = [];

  for (let R = 0; R < rows.length; ++R) {
    for (let C = 0; C < rows[R].length; ++C) {
      if (range.e.r < R) range.e.r = R;
      if (range.e.c < C) range.e.c = C;

      const rawVal = rows[R][C];
      const sanitized = sanitizeSpreadsheetValue(rawVal);
      const cellRef = XLSX.utils.encode_cell({ c: C, r: R });

      const cell: XLSX.CellObject = {
        t: typeof sanitized === 'number' ? 'n' : 's',
        v: sanitized
      };

      ws[cellRef] = cell;

      // Track max length for column widths
      const strLen = String(sanitized).length;
      colWidths[C] = Math.max(colWidths[C] || minColWidth, Math.min(60, strLen + 3));
    }
  }

  ws['!ref'] = XLSX.utils.encode_range(range);
  ws['!cols'] = colWidths.map(w => ({ wch: w }));

  // Freeze top header row
  ws['!freeze'] = { xSplit: 0, ySplit: 1 };

  // Enable autofilter on data range
  ws['!autofilter'] = { ref: ws['!ref'] };

  return ws;
}

export interface ExcelExportResult {
  filename: string;
  workbook: XLSX.WorkBook;
  binaryBuffer: Uint8Array;
  mimeType: string;
}

/**
 * Generates a structured multi-sheet Excel workbook conforming to Section 5 requirements.
 * Contains 12 dedicated worksheets:
 * 1. Investigation Summary
 * 2. SMTP Received Chain
 * 3. Candidate IP Addresses
 * 4. Authentication Results
 * 5. URLs and Domains
 * 6. Attachments
 * 7. Infrastructure Intelligence
 * 8. Graph Nodes
 * 9. Graph Relationships
 * 10. ML and Evidence Fusion
 * 11. Limitations and Missing Evidence
 * 12. Analyst Notes
 */
export function generateExcelExport(
  exportData: CanonicalExportData,
  options: ExportOptions = {}
): ExcelExportResult {
  const wb = XLSX.utils.book_new();

  // --- Sheet 1: Investigation Summary ---
  const summaryRows: (string | number)[][] = [
    ['Metric / Property', 'Value', 'Forensic Provenance / Details'],
    ['Investigation ID', exportData.summary.investigationId, 'Canonical System UUID'],
    ['Analysis Timestamp (UTC)', exportData.summary.analysisTimestamp, 'Session Execution Record'],
    ['Export Timestamp (UTC)', exportData.metadata.exportTimestamp, 'Export Module Snapshot'],
    ['Input Type', exportData.summary.inputType, 'MIME Ingestion Classifier'],
    ['Email Subject', exportData.summary.subject, 'RFC 5322 Subject Header'],
    ['Sender Address', exportData.summary.senderAddress, 'RFC 5322 From Mailbox'],
    ['Sender Domain', exportData.summary.senderDomain, 'Parsed From Authority'],
    ['Reply-To Address', exportData.summary.replyToAddress || 'None', 'RFC 5322 Reply-To'],
    ['Envelope Return-Path', exportData.headersAndRouting.returnPath, 'RFC 5321 Mail From Envelope'],
    ['Assessment Classification', exportData.summary.overallLabel.replace(/_/g, ' ').toUpperCase(), 'Deterministic Evidence Fusion'],
    ['Observed Risk Score', exportData.summary.observedRiskScore, 'Cumulative malicious indicators (0-100)'],
    ['Evidence Coverage Score', exportData.summary.evidenceCoverageScore, 'Percentage of verifiable evidence layers present (0-100)'],
    ['Assessment Confidence', exportData.summary.assessmentConfidence.toUpperCase(), 'Confidence level derived from coverage & signal consistency'],
    ['Executive Summary', exportData.summary.executiveSummary, 'Analyst Synthesis'],
    ['Schema Version', exportData.metadata.exportSchemaVersion, 'Export Specification Standard'],
    ['Data Classification', exportData.metadata.dataClassification, 'Privacy & Confidentiality Standard']
  ];
  XLSX.utils.book_append_sheet(wb, createWorksheetWithFormatting(summaryRows), 'Investigation Summary');

  // --- Sheet 2: SMTP Received Chain ---
  const hopsRows: (string | number)[][] = [
    ['Hop # (Chrono)', 'Position From Top', 'Reporting Server (From)', 'Receiving Server (By)', 'Observed IP', 'IP Type', 'Trust Zone', 'Border MTA?', 'Potentially Forged?', 'Transit Delta (sec)', 'Hop Timestamp (UTC)', 'Protocol', 'Suspicious Signals']
  ];
  for (const h of exportData.headersAndRouting.chronologicalHops) {
    hopsRows.push([
      h.hopIndex,
      h.rawPositionFromTop,
      h.reportingServer,
      h.receivingServer,
      h.ipAddress,
      h.ipType,
      h.trustZone,
      h.isBorderHop ? 'YES' : 'NO',
      h.isPotentiallyForged ? 'YES' : 'NO',
      h.timeDeltaSeconds !== null ? h.timeDeltaSeconds : 'N/A',
      h.timestamp,
      h.protocol,
      h.suspiciousSignals.join('; ') || 'None'
    ]);
  }
  XLSX.utils.book_append_sheet(wb, createWorksheetWithFormatting(hopsRows), 'SMTP Received Chain');

  // --- Sheet 3: Candidate IP Addresses ---
  const ipRows: (string | number)[][] = [
    ['Candidate IP', 'IP Classification', 'Attribution Category', 'Trust Boundary', 'Confidence Rating', 'Forensic Justification', 'Special-Purpose Range?']
  ];
  for (const c of exportData.headersAndRouting.candidateSourceIps) {
    ipRows.push([
      c.ip,
      c.ipType,
      c.attributionCategory,
      c.trustBoundary,
      c.confidence,
      c.justification,
      c.isSpecialPurpose ? 'YES' : 'NO'
    ]);
  }
  XLSX.utils.book_append_sheet(wb, createWorksheetWithFormatting(ipRows), 'Candidate IP Addresses');

  // --- Sheet 4: Authentication Results ---
  const auth = exportData.authentication;
  const authRows: (string | number)[][] = [
    ['Protocol', 'Result Verdict', 'Evaluated Domain / Identity', 'Selector / Mode', 'Alignment Status', 'Alignment Mode', 'Provenance', 'Forensic Note / Details'],
    ['SPF', auth.spf.result.toUpperCase(), auth.spf.domain, auth.spf.helo ? `HELO: ${auth.spf.helo}` : 'N/A', auth.spf.alignmentWithFrom, auth.spf.alignmentMode, auth.provenance, auth.spf.note],
    ['DKIM', auth.dkim.result.toUpperCase(), auth.dkim.domain, auth.dkim.selector ? `s=${auth.dkim.selector}` : 'N/A', auth.dkim.alignmentWithFrom, auth.dkim.alignmentMode, auth.provenance, auth.dkim.note],
    ['DMARC', auth.dmarc.result.toUpperCase(), auth.dmarc.fromDomain, `p=${auth.dmarc.policy}`, auth.dmarc.alignmentWithFrom, `SPF: ${auth.dmarc.alignmentMode.spf}, DKIM: ${auth.dmarc.alignmentMode.dkim}`, auth.dmarc.reportedProvenance, auth.dmarc.note]
  ];
  XLSX.utils.book_append_sheet(wb, createWorksheetWithFormatting(authRows), 'Authentication Results');

  // --- Sheet 5: URLs and Domains ---
  const urlRows: (string | number)[][] = [
    ['URL (Defanged)', 'Domain / Host', 'Protocol', 'Anchor Text', 'Anchor Mismatch?', 'IP-Based Host?', 'Punycode Homoglyph?', 'Shortener URL?', 'Suspicious Risk Flags']
  ];
  for (const u of exportData.urlsAndContent.urls) {
    urlRows.push([
      u.defangedUrl,
      u.domain,
      u.protocol,
      u.displayText || 'N/A',
      u.isMismatch ? 'YES' : 'NO',
      u.isIpBased ? 'YES' : 'NO',
      u.isPunycode ? 'YES' : 'NO',
      u.isShortener ? 'YES' : 'NO',
      u.suspiciousFlags.join('; ') || 'None'
    ]);
  }
  if (exportData.urlsAndContent.urls.length === 0) {
    urlRows.push(['No URLs extracted from message body', 'N/A', 'N/A', 'N/A', 'NO', 'NO', 'NO', 'NO', 'None']);
  }
  XLSX.utils.book_append_sheet(wb, createWorksheetWithFormatting(urlRows), 'URLs and Domains');

  // --- Sheet 6: Attachments ---
  const attRows: (string | number)[][] = [
    ['Filename', 'Content-Type', 'Size (Formatted)', 'Size (Bytes)', 'SHA-256 Checksum', 'Suspicious Extension?', 'Risk Observations']
  ];
  for (const a of exportData.attachments.items) {
    attRows.push([
      a.filename,
      a.contentType,
      a.sizeFormatted,
      a.sizeBytes,
      a.checksumSha256,
      a.isSuspiciousExtension ? 'YES' : 'NO',
      a.suspicionReason || 'Normal'
    ]);
  }
  if (exportData.attachments.items.length === 0) {
    attRows.push(['No attachments in message', 'N/A', '0 B', 0, 'N/A', 'NO', 'None']);
  }
  XLSX.utils.book_append_sheet(wb, createWorksheetWithFormatting(attRows), 'Attachments');

  // --- Sheet 7: Infrastructure Intelligence ---
  const infraRows: (string | number)[][] = [
    ['Entity Target', 'Entity Type', 'Provider Source', 'Query Target', 'Query Timestamp (UTC)', 'Status', 'Observation Summary', 'Reliability & Caveats']
  ];
  for (const inf of exportData.infrastructureIntelligence.items) {
    infraRows.push([
      inf.entity,
      inf.entityType,
      inf.provider,
      inf.queryTarget,
      inf.queryTimestamp,
      inf.status,
      JSON.stringify(inf.observationData),
      inf.reliabilityLimitations
    ]);
  }
  if (exportData.infrastructureIntelligence.items.length === 0) {
    infraRows.push(['No infrastructure queries performed', 'N/A', 'N/A', 'N/A', 'N/A', 'no_records', 'N/A', 'None']);
  }
  XLSX.utils.book_append_sheet(wb, createWorksheetWithFormatting(infraRows), 'Infrastructure Intelligence');

  // --- Sheet 8: Graph Nodes ---
  const nodeRows: (string | number)[][] = [
    ['Node ID', 'Entity Type', 'Display Label', 'Evidence References', 'Node Attributes']
  ];
  for (const n of exportData.relationshipGraph.nodes) {
    nodeRows.push([
      n.id,
      n.type,
      n.label,
      n.evidenceReferences.join(', ') || 'N/A',
      n.attributes ? JSON.stringify(n.attributes) : 'N/A'
    ]);
  }
  XLSX.utils.book_append_sheet(wb, createWorksheetWithFormatting(nodeRows), 'Graph Nodes');

  // --- Sheet 9: Graph Relationships ---
  const edgeRows: (string | number)[][] = [
    ['Edge ID', 'Source Node', 'Target Node', 'Relationship Type', 'Nature (Observed vs Inferred)', 'Confidence Rating', 'Directly Observed?', 'Supporting Observation / Caveat', 'Evidence References']
  ];
  for (const e of exportData.relationshipGraph.edges) {
    edgeRows.push([
      e.id,
      e.sourceNode,
      e.targetNode,
      e.relationshipType,
      e.relationshipNature,
      e.confidence,
      e.isDirectlyObserved ? 'YES' : 'NO',
      e.supportingObservation || 'N/A',
      e.evidenceReferences.join(', ') || 'N/A'
    ]);
  }
  XLSX.utils.book_append_sheet(wb, createWorksheetWithFormatting(edgeRows), 'Graph Relationships');

  // --- Sheet 10: ML and Evidence Fusion ---
  const ml = exportData.machineLearning;
  const fusion = exportData.evidenceFusionAndLimitations;
  const mlFusionRows: (string | number)[][] = [
    ['Category', 'Property / Factor', 'Value / Assessment', 'Technical Metadata'],
    ['Machine Learning', 'Active Model ID', ml.modelId, `Model Name: ${ml.modelName}`],
    ['Machine Learning', 'Model Version', ml.modelVersion, `Preprocessing Ver: ${ml.preprocessingVersion}`],
    ['Machine Learning', 'Feature Schema Version', ml.featureSchemaVersion, 'Standardized Input Contract'],
    ['Machine Learning', 'Configuration Snapshot', ml.configurationSnapshotId || 'N/A', 'Immutable Version Lock'],
    ['Machine Learning', 'Predicted Class', ml.predictedClass, `Is Available: ${ml.isAvailable ? 'YES' : 'NO'}`],
    ['Machine Learning', 'Raw Decision Score', ml.decisionScore !== undefined && ml.decisionScore !== null ? ml.decisionScore : 'N/A', 'Hyperplane Margin / Linear Distance'],
    ['Machine Learning', 'Estimated Probability', ml.probability !== undefined && ml.probability !== null ? ml.probability : 'N/A', 'Native Sigmoid Probability (if supported)'],
    ['Machine Learning', 'Calibrated Probability', ml.calibratedProbability !== undefined && ml.calibratedProbability !== null ? ml.calibratedProbability : 'N/A', `Is Calibrated: ${ml.isCalibrated ? 'YES' : 'NO'}`],
    ['Machine Learning', 'Validation Status', ml.isExperimentallyValidated ? 'Validated' : 'Unvalidated Research Baseline', 'Benchmark certification flag'],
    ['Machine Learning', 'Rationale', ml.rationale || 'N/A', 'Model explanation'],
    ['Evidence Fusion', 'Observed Risk Score', fusion.observedRiskScore, 'Cumulative malicious signals (0-100)'],
    ['Evidence Fusion', 'Evidence Coverage Score', `${fusion.evidenceCoverageScore}%`, 'Percentage of verifiable forensic layers present'],
    ['Evidence Fusion', 'Assessment Confidence', fusion.assessmentConfidence.toUpperCase(), 'High / Medium / Low certainty rating'],
    ['Evidence Fusion', 'Primary Risk Factors', fusion.primaryRiskFactors.join(' | ') || 'None detected', 'Key threats contributing to risk score'],
    ['Evidence Fusion', 'Mitigating Factors', fusion.mitigatingFactors.join(' | ') || 'None observed', 'Authenticity signals offsetting risk']
  ];
  XLSX.utils.book_append_sheet(wb, createWorksheetWithFormatting(mlFusionRows), 'ML and Evidence Fusion');

  // --- Sheet 11: Limitations and Missing Evidence ---
  const limRows: (string | number)[][] = [
    ['Category', 'Limitation / Unavailable Evidence Layer', 'Forensic Implication']
  ];
  for (const un of fusion.unavailableEvidenceCategories) {
    limRows.push(['Missing Evidence Layer', un, 'Cannot verify authenticity or routing across missing headers/data']);
  }
  for (const lim of fusion.investigationLimitations) {
    limRows.push(['Investigation Limitation', lim, 'In-memory ephemeral session constraints']);
  }
  for (const lim of auth.verificationLimitations) {
    limRows.push(['Authentication Limitation', lim, 'Header-reported versus independent DNS/cryptographic checks']);
  }
  for (const lim of ml.limitations) {
    limRows.push(['Machine Learning Limitation', lim, 'Model domain boundaries and baseline status']);
  }
  XLSX.utils.book_append_sheet(wb, createWorksheetWithFormatting(limRows), 'Limitations & Missing Evidence');

  // --- Sheet 12: Analyst Notes ---
  const notesRows: (string | number)[][] = [
    ['Record Field', 'Content'],
    ['Analyst Name', options.analystName || 'Unassigned Analyst'],
    ['Record Date', exportData.metadata.exportTimestamp],
    ['Investigation ID', exportData.summary.investigationId],
    ['Analyst Notes', fusion.analystNotes || 'No analyst notes recorded for this investigation.']
  ];
  XLSX.utils.book_append_sheet(wb, createWorksheetWithFormatting(notesRows), 'Analyst Notes');

  // Generate binary output buffer
  const binaryBuffer = XLSX.write(wb, { bookType: 'xlsx', type: 'array' });
  const filename = generateExportFilename(exportData.summary.investigationId, 'xlsx');

  return {
    filename,
    workbook: wb,
    binaryBuffer: new Uint8Array(binaryBuffer),
    mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
  };
}
