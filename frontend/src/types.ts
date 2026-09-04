export type ScanState = "queued" | "running" | "complete" | "failed";

export interface Me {
  org_id: string;
  org_name: string;
  tier: string;
}

export interface ScanSummary {
  id: string;
  filename: string;
  status: ScanState;
  tier1: number;
  tier2: number;
  target_sha256: string | null;
  created_at: string;
}

export interface ScanStatus {
  id: string;
  filename: string;
  status: ScanState;
  stage: string | null;
  error: string | null;
  runtime: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

export interface UsageResponse {
  org_id: string;
  tier: string;
  scans_completed: number;
  monthly_limit: number | null;
  monthly_used: number;
}

export interface ApiKeyInfo {
  id: string;
  name: string;
  key_prefix: string | null;
  expires_at: string | null;
  revoked_at: string | null;
  last_used_at: string | null;
  created_at: string;
}

export interface VerifiedFact {
  id?: string;
  primitive?: string;
  cwe?: string | null;
  function?: string;
  call_addr?: string;
  summary?: string;
  provenance?: string[];
  analyst_note?: string;
}

export interface Indicator {
  primitive?: string;
  pattern?: string;
  function?: string;
  operand?: string;
  addresses?: string[];
  analyst_question?: string;
}

export interface AnalysisReport {
  target?: string;
  target_arch?: string;
  target_sha256?: string;
  posture?: {
    sound?: boolean;
    complete?: boolean;
    exploitability_claim?: boolean;
    scope?: string;
    platform?: string;
    limits?: string[];
  };
  verified_facts: VerifiedFact[];
  indicators: Indicator[];
  diagnostics?: Array<Record<string, unknown>>;
}
