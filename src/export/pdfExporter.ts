import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { CanonicalExportData, ExportOptions } from './exportTypes';
import { generateExportFilename } from './exportDataBuilder';

export interface PdfExportResult {
  filename: string;
  doc: jsPDF;
  binaryBuffer: Uint8Array;
  mimeType: string;
}

/**
 * Generates a professionally formatted, 14-section cybersecurity forensic investigation PDF report.
 * Includes page numbers, repeating headers, clean typography, tables, and provenance markers.
 */
export function generatePdfExport(
  exportData: CanonicalExportData,
  options: ExportOptions = {}
): PdfExportResult {
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4'
  });

  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const margin = 14;
  const contentWidth = pageWidth - (margin * 2);

  let currentY = 18;

  // Color Palette Constants
  const brandDark: [number, number, number] = [15, 23, 42]; // Slate-900
  const brandCyan: [number, number, number] = [6, 182, 212]; // Cyan-500
  const brandRose: [number, number, number] = [225, 29, 72]; // Rose-600
  const brandAmber: [number, number, number] = [217, 119, 6]; // Amber-600
  const brandEmerald: [number, number, number] = [16, 185, 129]; // Emerald-500
  const brandMuted: [number, number, number] = [100, 116, 139]; // Slate-500

  const riskScore = exportData.summary.observedRiskScore;
  const riskColor = riskScore >= 65 ? brandRose : riskScore >= 35 ? brandAmber : brandEmerald;

  // Helper for section headings
  function renderSectionHeading(title: string, sectionNumber: number) {
    if (currentY > pageHeight - 35) {
      doc.addPage();
      currentY = 20;
    }
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(...brandDark);
    doc.text(`${sectionNumber}. ${title}`, margin, currentY);
    doc.setDrawColor(203, 213, 225); // Slate-300
    doc.setLineWidth(0.4);
    doc.line(margin, currentY + 1.5, pageWidth - margin, currentY + 1.5);
    currentY += 7;
  }

  // --- 1. Report Title & Header ---
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(18);
  doc.setTextColor(...brandDark);
  doc.text('PhishScope Forensic Threat Report', margin, currentY);

  doc.setFontSize(8);
  doc.setFont('helvetica', 'normal');
  doc.setTextColor(...brandMuted);
  doc.text('Automated Email Threat Forensics & Evidence Correlation', margin, currentY + 4.5);

  // Classification Badge
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(7.5);
  doc.setTextColor(255, 255, 255);
  doc.setFillColor(...brandDark);
  doc.roundedRect(pageWidth - margin - 48, currentY - 5, 48, 8, 1, 1, 'F');
  doc.text(exportData.metadata.dataClassification.replace(/_/g, ' '), pageWidth - margin - 46, currentY);

  currentY += 12;

  // Metadata Card
  autoTable(doc, {
    startY: currentY,
    theme: 'grid',
    head: [['Investigation Metadata Field', 'Recorded Value']],
    body: [
      ['Investigation ID', exportData.summary.investigationId],
      ['Analysis Timestamp (UTC)', exportData.summary.analysisTimestamp],
      ['Report Generation Date (UTC)', exportData.metadata.exportTimestamp],
      ['Input Format / Ingestion Method', exportData.summary.inputType],
      ['Forensic Export Schema Version', exportData.metadata.exportSchemaVersion],
      ['Lead Analyst / Examiner', options.analystName || 'Unassigned Analyst']
    ],
    headStyles: { fillColor: brandDark, textColor: 255, fontSize: 8, fontStyle: 'bold' },
    styles: { fontSize: 7.5, cellPadding: 2, textColor: [30, 41, 59] },
    columnStyles: { 0: { cellWidth: 55, fontStyle: 'bold' }, 1: { cellWidth: contentWidth - 55 } },
    margin: { left: margin, right: margin }
  });
  currentY = (doc as any).lastAutoTable.finalY + 7;

  // --- 2. Executive Summary ---
  renderSectionHeading('Executive Summary', 2);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(30, 41, 59);
  const summaryLines = doc.splitTextToSize(exportData.summary.executiveSummary, contentWidth);
  doc.text(summaryLines, margin, currentY);
  currentY += (summaryLines.length * 4) + 4;

  // --- 3. Overall Risk & Evidence Coverage ---
  renderSectionHeading('Overall Risk & Evidence Coverage', 3);
  autoTable(doc, {
    startY: currentY,
    theme: 'plain',
    body: [
      [
        `Assessment Verdict: ${exportData.summary.overallLabel.replace(/_/g, ' ').toUpperCase()}`,
        `Observed Risk Score: ${exportData.summary.observedRiskScore} / 100`,
        `Coverage: ${exportData.summary.evidenceCoverageScore}%`,
        `Confidence: ${exportData.summary.assessmentConfidence.toUpperCase()}`
      ]
    ],
    styles: { fontSize: 8.5, fontStyle: 'bold', fillColor: [241, 245, 249], cellPadding: 3, textColor: [15, 23, 42] },
    columnStyles: { 0: { cellWidth: 52 }, 1: { cellWidth: 46 }, 2: { cellWidth: 38 }, 3: { cellWidth: 46 } },
    margin: { left: margin, right: margin }
  });
  currentY = (doc as any).lastAutoTable.finalY + 4;

  // Primary Risk & Mitigating Factors
  const factorsBody: string[][] = [];
  if (exportData.evidenceFusionAndLimitations.primaryRiskFactors.length > 0) {
    factorsBody.push(['Primary Threats', exportData.evidenceFusionAndLimitations.primaryRiskFactors.join('\n• ')]);
  } else {
    factorsBody.push(['Primary Threats', 'None detected']);
  }
  if (exportData.evidenceFusionAndLimitations.mitigatingFactors.length > 0) {
    factorsBody.push(['Mitigating Factors', exportData.evidenceFusionAndLimitations.mitigatingFactors.join('\n• ')]);
  }
  autoTable(doc, {
    startY: currentY,
    theme: 'grid',
    body: factorsBody,
    styles: { fontSize: 7.5, cellPadding: 2.5 },
    columnStyles: { 0: { cellWidth: 40, fontStyle: 'bold', textColor: brandDark }, 1: { cellWidth: contentWidth - 40 } },
    margin: { left: margin, right: margin }
  });
  currentY = (doc as any).lastAutoTable.finalY + 7;

  // --- 4. Header & SMTP Forensics ---
  renderSectionHeading('Header and SMTP Forensics', 4);
  autoTable(doc, {
    startY: currentY,
    theme: 'grid',
    head: [['Hop', 'Top Pos', 'Reporting MTA (From)', 'Receiving MTA (By)', 'Observed IP', 'Type', 'Zone', 'Delay']],
    body: exportData.headersAndRouting.chronologicalHops.map(h => [
      h.hopIndex,
      h.rawPositionFromTop,
      h.reportingServer,
      h.receivingServer,
      h.ipAddress,
      h.ipType,
      h.trustZone,
      h.timeDeltaSeconds !== null ? `${h.timeDeltaSeconds}s` : 'N/A'
    ]),
    showHead: 'everyPage',
    headStyles: { fillColor: brandDark, fontSize: 7, fontStyle: 'bold' },
    styles: { fontSize: 6.5, cellPadding: 1.8 },
    columnStyles: {
      0: { cellWidth: 10 },
      1: { cellWidth: 14 },
      2: { cellWidth: 35 },
      3: { cellWidth: 35 },
      4: { cellWidth: 28 },
      5: { cellWidth: 16 },
      6: { cellWidth: 26 },
      7: { cellWidth: 18 }
    },
    margin: { left: margin, right: margin }
  });
  currentY = (doc as any).lastAutoTable.finalY + 7;

  // --- 5. Candidate Origin IP Assessment ---
  renderSectionHeading('Candidate Origin IP Assessment', 5);
  autoTable(doc, {
    startY: currentY,
    theme: 'grid',
    head: [['Candidate IP', 'IP Type', 'Attribution Category', 'Trust Boundary', 'Confidence', 'Forensic Justification']],
    body: exportData.headersAndRouting.candidateSourceIps.map(c => [
      c.ip,
      c.ipType,
      c.attributionCategory,
      c.trustBoundary,
      c.confidence,
      c.justification
    ]),
    showHead: 'everyPage',
    headStyles: { fillColor: brandDark, fontSize: 7, fontStyle: 'bold' },
    styles: { fontSize: 6.5, cellPadding: 2 },
    columnStyles: {
      0: { cellWidth: 26, fontStyle: 'bold' },
      1: { cellWidth: 18 },
      2: { cellWidth: 26 },
      3: { cellWidth: 24 },
      4: { cellWidth: 26 },
      5: { cellWidth: contentWidth - 120 }
    },
    margin: { left: margin, right: margin }
  });
  currentY = (doc as any).lastAutoTable.finalY + 7;

  // --- 6. SPF, DKIM & DMARC Authentication Analysis ---
  renderSectionHeading('Authentication Analysis (SPF, DKIM, DMARC)', 6);
  const auth = exportData.authentication;
  autoTable(doc, {
    startY: currentY,
    theme: 'grid',
    head: [['Protocol', 'Result', 'Domain / Selector', 'Alignment', 'Alignment Mode', 'Provenance', 'Forensic Note']],
    body: [
      ['SPF', auth.spf.result.toUpperCase(), auth.spf.domain, auth.spf.alignmentWithFrom, auth.spf.alignmentMode, auth.provenance, auth.spf.note],
      ['DKIM', auth.dkim.result.toUpperCase(), `${auth.dkim.domain} (${auth.dkim.selector})`, auth.dkim.alignmentWithFrom, auth.dkim.alignmentMode, auth.provenance, auth.dkim.note],
      ['DMARC', auth.dmarc.result.toUpperCase(), `${auth.dmarc.fromDomain} (p=${auth.dmarc.policy})`, auth.dmarc.alignmentWithFrom, `SPF: ${auth.dmarc.alignmentMode.spf}, DKIM: ${auth.dmarc.alignmentMode.dkim}`, auth.dmarc.reportedProvenance, auth.dmarc.note]
    ],
    headStyles: { fillColor: brandDark, fontSize: 7, fontStyle: 'bold' },
    styles: { fontSize: 6.5, cellPadding: 2 },
    columnStyles: {
      0: { cellWidth: 16, fontStyle: 'bold' },
      1: { cellWidth: 16, fontStyle: 'bold' },
      2: { cellWidth: 32 },
      3: { cellWidth: 18 },
      4: { cellWidth: 24 },
      5: { cellWidth: 24 },
      6: { cellWidth: contentWidth - 130 }
    },
    margin: { left: margin, right: margin }
  });
  currentY = (doc as any).lastAutoTable.finalY + 7;

  // --- 7. URL & Content Analysis ---
  renderSectionHeading('URL and Content Analysis', 7);
  const urlRows = exportData.urlsAndContent.urls.map(u => [
    u.defangedUrl,
    u.domain,
    u.displayText || 'N/A',
    u.isMismatch ? 'YES' : 'NO',
    u.isIpBased ? 'YES' : 'NO',
    u.suspiciousFlags.join(', ') || 'None'
  ]);
  if (urlRows.length === 0) {
    urlRows.push(['No URLs extracted from message body', 'N/A', 'N/A', 'NO', 'NO', 'None']);
  }
  autoTable(doc, {
    startY: currentY,
    theme: 'grid',
    head: [['Defanged URL', 'Domain', 'Anchor Text', 'Mismatch?', 'IP Host?', 'Risk Signals']],
    body: urlRows,
    showHead: 'everyPage',
    headStyles: { fillColor: brandDark, fontSize: 7, fontStyle: 'bold' },
    styles: { fontSize: 6.5, cellPadding: 2 },
    columnStyles: {
      0: { cellWidth: 50 },
      1: { cellWidth: 30 },
      2: { cellWidth: 30 },
      3: { cellWidth: 16 },
      4: { cellWidth: 16 },
      5: { cellWidth: contentWidth - 142 }
    },
    margin: { left: margin, right: margin }
  });
  currentY = (doc as any).lastAutoTable.finalY + 7;

  // --- 8. Attachment Analysis ---
  renderSectionHeading('Attachment Analysis', 8);
  const attRows = exportData.attachments.items.map(a => [
    a.filename,
    a.contentType,
    a.sizeFormatted,
    a.checksumSha256,
    a.isSuspiciousExtension ? 'YES' : 'NO',
    a.suspicionReason || 'Normal'
  ]);
  if (attRows.length === 0) {
    attRows.push(['No attachments in message', 'N/A', '0 B', 'N/A', 'NO', 'None']);
  }
  autoTable(doc, {
    startY: currentY,
    theme: 'grid',
    head: [['Filename', 'MIME Type', 'Size', 'SHA-256 Checksum', 'Suspicious?', 'Risk Notes']],
    body: attRows,
    showHead: 'everyPage',
    headStyles: { fillColor: brandDark, fontSize: 7, fontStyle: 'bold' },
    styles: { fontSize: 6.5, cellPadding: 2 },
    columnStyles: {
      0: { cellWidth: 35 },
      1: { cellWidth: 25 },
      2: { cellWidth: 16 },
      3: { cellWidth: 46 },
      4: { cellWidth: 18 },
      5: { cellWidth: contentWidth - 140 }
    },
    margin: { left: margin, right: margin }
  });
  currentY = (doc as any).lastAutoTable.finalY + 7;

  // --- 9. Infrastructure Intelligence ---
  renderSectionHeading('Infrastructure Intelligence & Resolver Data', 9);
  const infraRows = exportData.infrastructureIntelligence.items.map(inf => [
    inf.entity,
    inf.entityType,
    inf.provider,
    inf.status,
    inf.reliabilityLimitations
  ]);
  if (infraRows.length === 0) {
    infraRows.push(['No external enrichment records logged', 'N/A', 'N/A', 'no_records', 'None']);
  }
  autoTable(doc, {
    startY: currentY,
    theme: 'grid',
    head: [['Entity', 'Type', 'Provider', 'Status', 'Reliability Limitations & Source Notes']],
    body: infraRows,
    showHead: 'everyPage',
    headStyles: { fillColor: brandDark, fontSize: 7, fontStyle: 'bold' },
    styles: { fontSize: 6.5, cellPadding: 2 },
    columnStyles: {
      0: { cellWidth: 35 },
      1: { cellWidth: 18 },
      2: { cellWidth: 35 },
      3: { cellWidth: 20 },
      4: { cellWidth: contentWidth - 108 }
    },
    margin: { left: margin, right: margin }
  });
  currentY = (doc as any).lastAutoTable.finalY + 7;

  // --- 10. Relationship Graph Summary ---
  renderSectionHeading('Relationship Graph & Infrastructure Correlation', 10);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(51, 65, 85);
  doc.text(`Identified Entities (Nodes): ${exportData.relationshipGraph.nodeCount} | Relationships (Edges): ${exportData.relationshipGraph.edgeCount}`, margin, currentY);
  currentY += 4;

  const edgeRows = exportData.relationshipGraph.edges.slice(0, 10).map(e => [
    e.sourceNode,
    e.relationshipType,
    e.targetNode,
    e.relationshipNature,
    e.confidence,
    e.supportingObservation || 'N/A'
  ]);
  if (edgeRows.length > 0) {
    autoTable(doc, {
      startY: currentY,
      theme: 'grid',
      head: [['Source Entity', 'Relationship', 'Target Entity', 'Nature', 'Confidence', 'Observation']],
      body: edgeRows,
      showHead: 'everyPage',
      headStyles: { fillColor: brandDark, fontSize: 7, fontStyle: 'bold' },
      styles: { fontSize: 6.5, cellPadding: 2 },
      columnStyles: {
        0: { cellWidth: 32 },
        1: { cellWidth: 26 },
        2: { cellWidth: 32 },
        3: { cellWidth: 22 },
        4: { cellWidth: 22 },
        5: { cellWidth: 48 }
      },
      margin: { left: margin, right: margin }
    });
    currentY = (doc as any).lastAutoTable.finalY + 7;
  }

  // --- 11. ML Classification & Model Provenance ---
  renderSectionHeading('Machine Learning Classification & Model Provenance', 11);
  const ml = exportData.machineLearning;
  autoTable(doc, {
    startY: currentY,
    theme: 'grid',
    head: [['ML Model Parameter', 'Specification / Value']],
    body: [
      ['Model Adapter ID', ml.modelId],
      ['Model Name', ml.modelName],
      ['Model Version', ml.modelVersion],
      ['Preprocessing Version', ml.preprocessingVersion],
      ['Feature Schema Version', ml.featureSchemaVersion],
      ['Configuration Snapshot ID', ml.configurationSnapshotId || 'N/A'],
      ['Predicted Class Output', ml.predictedClass],
      ['Decision Score', ml.decisionScore !== undefined && ml.decisionScore !== null ? String(ml.decisionScore) : 'N/A'],
      ['Native Probability', ml.probability !== undefined && ml.probability !== null ? String(ml.probability) : 'N/A'],
      ['Calibrated Probability', ml.calibratedProbability !== undefined && ml.calibratedProbability !== null ? String(ml.calibratedProbability) : 'N/A'],
      ['Model Health & Availability', ml.isAvailable ? 'Available & Configured' : 'Unconfigured Baseline'],
      ['Experimental Validation Status', ml.isExperimentallyValidated ? 'Validated Production Model' : 'Active Research Baseline (Unvalidated)']
    ],
    showHead: 'everyPage',
    headStyles: { fillColor: brandDark, fontSize: 7, fontStyle: 'bold' },
    styles: { fontSize: 7, cellPadding: 2 },
    columnStyles: { 0: { cellWidth: 55, fontStyle: 'bold' }, 1: { cellWidth: contentWidth - 55 } },
    margin: { left: margin, right: margin }
  });
  currentY = (doc as any).lastAutoTable.finalY + 7;

  // --- 12. Evidence Fusion Reasoning ---
  renderSectionHeading('Evidence Fusion Reasoning Chain', 12);
  const chainText = exportData.evidenceFusionAndLimitations.reasoningChain.join('\n');
  const chainLines = doc.splitTextToSize(chainText, contentWidth);
  doc.setFont('courier', 'normal');
  doc.setFontSize(6.5);
  doc.setTextColor(30, 41, 59);
  doc.text(chainLines, margin, currentY);
  currentY += (chainLines.length * 3.5) + 6;

  // --- 13. Analyst Notes ---
  renderSectionHeading('Analyst Notes & Case Observations', 13);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(30, 41, 59);
  const notesStr = exportData.evidenceFusionAndLimitations.analystNotes || 'No custom case notes recorded for this investigation.';
  const notesLines = doc.splitTextToSize(notesStr, contentWidth);
  doc.text(notesLines, margin, currentY);
  currentY += (notesLines.length * 4) + 6;

  // --- 14. Limitations, Unverified Evidence & Conclusion ---
  renderSectionHeading('Limitations, Unverified Evidence & Conclusion', 14);
  const allLimitations = [
    ...exportData.evidenceFusionAndLimitations.investigationLimitations,
    ...exportData.evidenceFusionAndLimitations.unavailableEvidenceCategories.map(u => `Unavailable evidence: ${u}`),
    ...exportData.authentication.verificationLimitations
  ];
  autoTable(doc, {
    startY: currentY,
    theme: 'grid',
    body: allLimitations.map(l => ['•', l]),
    styles: { fontSize: 6.5, cellPadding: 1.8, textColor: [71, 85, 105] },
    columnStyles: { 0: { cellWidth: 6, fontStyle: 'bold' }, 1: { cellWidth: contentWidth - 6 } },
    margin: { left: margin, right: margin }
  });
  currentY = (doc as any).lastAutoTable.finalY + 6;

  // Legal Disclaimer
  doc.setFont('helvetica', 'italic');
  doc.setFontSize(6.5);
  doc.setTextColor(...brandMuted);
  const disclaimer = 'Notice: This report reflects evidence, enrichment records, and deterministic heuristics captured at the recorded analysis timestamp. Findings are probabilistic and designed for forensic decision-support.';
  doc.text(doc.splitTextToSize(disclaimer, contentWidth), margin, currentY);

  // --- Add Header / Footer to Every Page ---
  const totalPages = doc.getNumberOfPages();
  for (let i = 1; i <= totalPages; i++) {
    doc.setPage(i);

    // Running Header (Pages > 1)
    if (i > 1) {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(...brandMuted);
      doc.text(`PhishScope Threat Report — ID: ${exportData.summary.investigationId.slice(0, 16)}`, margin, 10);
      doc.text(exportData.metadata.exportTimestamp.slice(0, 10), pageWidth - margin - 20, 10);
      doc.setDrawColor(226, 232, 240);
      doc.line(margin, 12, pageWidth - margin, 12);
    }

    // Running Footer (All Pages)
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.5);
    doc.setTextColor(...brandMuted);
    doc.setDrawColor(226, 232, 240);
    doc.line(margin, pageHeight - 11, pageWidth - margin, pageHeight - 11);
    doc.text(`Page ${i} of ${totalPages}`, margin, pageHeight - 6);
    doc.text('Strict Confidentiality — For Authorized Forensic Investigation Use Only', pageWidth / 2, pageHeight - 6, { align: 'center' });
    doc.text('PhishScope Engine v1.2', pageWidth - margin - 26, pageHeight - 6);
  }

  const filename = generateExportFilename(exportData.summary.investigationId, 'pdf');
  const binaryBuffer = new Uint8Array(doc.output('arraybuffer'));

  return {
    filename,
    doc,
    binaryBuffer,
    mimeType: 'application/pdf'
  };
}
