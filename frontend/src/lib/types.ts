export type EngineName = "nuclei" | "openvas";
export type ScanType = "internal" | "external";
export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";

export type IdentityConfidence = "mac" | "hostname" | "ip";

export interface Asset {
  id: number;
  hostname: string | null;
  ip_address: string | null;
  mac_address: string | null;
  identity_confidence: IdentityConfidence | null;
  environment: string | null;
  criticality: string | null;
  created_at: string;
}

export interface AssetCreate {
  hostname?: string;
  ip_address?: string;
  environment?: string;
  criticality?: string;
}

export interface ScanEngine {
  engine: string;
  status: string;
  progress: string | null;
  progress_pct: number;
  error_message: string | null;
  started_at: string | null;
  finished_at: string | null;
}

export interface Scan {
  id: number;
  type: ScanType;
  status: string;
  start_time: string | null;
  end_time: string | null;
  created_at: string;
  engines: ScanEngine[];
}

export type CredentialType = "ssh" | "winrm" | "snmp";

export interface CredentialCreate {
  type: CredentialType;
  username: string;
  secret: string;
  port?: number;
}

export interface ScanCreate {
  type: ScanType;
  asset_ids: number[];
  agent_id?: number;
  credentials?: CredentialCreate[];
}

export interface ScanEngineStatus {
  status: string;
  progress: string;
  progress_pct: number;
  error_message: string | null;
  findings_count: number;
  started_at: string | null;
  finished_at: string | null;
}

export interface ScanStatus {
  scan_id: number;
  overall_status: string;
  engines: Record<string, ScanEngineStatus>;
}

export interface Finding {
  id: number;
  scan_id: number;
  asset_id: number;
  engine: EngineName;
  severity: string;
  cve: string | null;
  description: string | null;
  recommendation: string | null;
  created_at: string;
}

export interface ScanFindings {
  scan_id: number;
  nuclei: Finding[];
  openvas: Finding[];
}

export interface Agent {
  id: number;
  name: string;
  type: string;
  status: string;
  last_seen: string;
}
