import { EmailAnalysis, SessionMetrics } from '../../src/types/forensics';

/**
 * In-Memory Session Investigation Store
 * Enforces Critical Architectural Decision 3.2:
 * - Temporary in-memory retention only
 * - Zero permanent disk persistence of raw email bodies or attachments
 * - Configurable TTL expiration
 * - Complete session wipe capability
 */
export class SessionStore {
  private static instance: SessionStore;
  private analyses: Map<string, { analysis: EmailAnalysis; expiresAt: number }> = new Map();
  private readonly defaultTtlMs = 1000 * 60 * 60 * 2; // 2 hours in-memory TTL

  private constructor() {
    // Periodic sweep every 15 minutes to purge expired session records
    setInterval(() => this.purgeExpired(), 1000 * 60 * 15);
  }

  public static getInstance(): SessionStore {
    if (!SessionStore.instance) {
      SessionStore.instance = new SessionStore();
    }
    return SessionStore.instance;
  }

  public saveAnalysis(analysis: EmailAnalysis, ttlMs = this.defaultTtlMs): void {
    const expiresAt = Date.now() + ttlMs;
    this.analyses.set(analysis.analysisId, { analysis, expiresAt });
  }

  public getAnalysis(id: string): EmailAnalysis | null {
    const item = this.analyses.get(id);
    if (!item) return null;
    if (Date.now() > item.expiresAt) {
      this.analyses.delete(id);
      return null;
    }
    return item.analysis;
  }

  public getAllAnalyses(): EmailAnalysis[] {
    const now = Date.now();
    const result: EmailAnalysis[] = [];
    for (const [id, item] of this.analyses.entries()) {
      if (now > item.expiresAt) {
        this.analyses.delete(id);
      } else {
        result.push(item.analysis);
      }
    }
    // Sort descending by createdAt
    return result.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  public updateAnalystNotes(id: string, notes: string): boolean {
    const item = this.analyses.get(id);
    if (!item) return false;
    item.analysis.analystNotes = notes;
    return true;
  }

  public clearAll(): void {
    this.analyses.clear();
  }

  public getMetrics(): SessionMetrics {
    const list = this.getAllAnalyses();
    let phishingCount = 0;
    let suspiciousCount = 0;
    let legitimateCount = 0;
    let inconclusiveCount = 0;
    let authenticationWarningsCount = 0;
    let suspiciousRoutingCount = 0;

    for (const a of list) {
      if (a.overallAssessment.label === 'likely_phishing') phishingCount++;
      else if (a.overallAssessment.label === 'potentially_suspicious') suspiciousCount++;
      else if (a.overallAssessment.label === 'likely_legitimate') legitimateCount++;
      else inconclusiveCount++;

      if (a.authenticationFindings.spf.result === 'fail' || a.authenticationFindings.dkim.result === 'fail' || a.authenticationFindings.dmarc.result === 'fail') {
        authenticationWarningsCount++;
      }

      if (a.forensicFindings.routingAnomalies.length > 0) {
        suspiciousRoutingCount++;
      }
    }

    return {
      totalAnalyzed: list.length,
      phishingCount,
      suspiciousCount,
      legitimateCount,
      inconclusiveCount,
      authenticationWarningsCount,
      suspiciousRoutingCount
    };
  }

  private purgeExpired(): void {
    const now = Date.now();
    for (const [id, item] of this.analyses.entries()) {
      if (now > item.expiresAt) {
        this.analyses.delete(id);
      }
    }
  }
}
