export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface HeaderCheck {
  present: Record<string, string>;
  missing: string[];
  statusCode: number | null;
  finalUrl: string | null;
  challengeSuspected: boolean;
  challengeNotes: string[];
}

export interface CspCheck {
  present: boolean;
  raw: string | null;
  findings: { severity: Severity; issue: string }[];
}

export interface CookieFinding {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
  issues: string[];
}

export interface PathResult {
  path: string;
  status: number | null;
  size: number;
  severity?: Severity;
  note?: string;
  error?: string;
}

export interface HttpDowngradeCheck {
  firstHopStatus: number | null;
  finalStatus: number | null;
  servedOverPlaintext: boolean;
}

export interface CorsCheck {
  acao: string | null;
  acac: string | null;
  finding: string | null;
}

export interface ScanResult {
  target: string;
  scannedAt: string;
  headers: HeaderCheck;
  csp: CspCheck;
  cookies: CookieFinding[];
  httpDowngrade: HttpDowngradeCheck;
  cors: CorsCheck;
  paths: PathResult[];
  cleanAreas: string[];
  issues: { severity: Severity; title: string }[];
  error?: string;
}

export interface AnalyzeResponse {
  ok: boolean;
  report?: string;
  scanSummary?: {
    target: string;
    issueCount: number;
    cleanCount: number;
    challengeSuspected: boolean;
  };
  error?: string;
  retryAfterSeconds?: number;
}
