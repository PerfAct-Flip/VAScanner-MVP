export type EngineName = "nuclei" | "openvas";
export type ScanEngineChoice = "discover" | "nuclei" | "openvas";
export type ScanType = "internal" | "external";
export type Severity = "Critical" | "High" | "Medium" | "Low" | "Informational";

export type IdentityConfidence = "mac" | "hostname" | "ip";

export interface Asset {
  id: number;
  hostname: string | null;
  ip_address: string | null;
  mac_address: string | null;
  identity_confidence: IdentityConfidence | null;
  open_ports: string | null;
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
  requested_engines: string | null;
  engines: ScanEngine[];
  warnings: string[];
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
  engines?: ScanEngineChoice[];
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

export type ReportFormat = "csv" | "pdf" | "pci";

export interface Report {
  id: number;
  scan_id: number | null;
  format: ReportFormat;
  finding_count: number;
  generated_at: string;
}

export interface PciCompanyInfo {
  company: string;
  contact_name: string;
  job_title: string;
  telephone: string;
  email: string;
  address: string;
  city?: string;
  state?: string;
  postal_code?: string;
  country?: string;
  url?: string;
}

export interface PciReportInfo {
  customer: PciCompanyInfo;
  asv: PciCompanyInfo;
  asv_certificate_number: string;
  scan_report_type?: "Full scan" | "Partial scan";
}

export interface ReportCreate {
  scan_id?: number;
  format: ReportFormat;
  pci_info?: PciReportInfo;
}

export interface Agent {
  id: number;
  name: string;
  type: string;
  status: string;
  last_seen: string;
}
