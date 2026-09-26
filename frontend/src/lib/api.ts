import type {
  Agent,
  Asset,
  AssetCreate,
  Finding,
  Report,
  ReportCreate,
  Scan,
  ScanCreate,
  ScanFindings,
  ScanStatus,
} from "@/lib/types";

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "";

class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// FastAPI's validation-error shape is a list of {loc, msg, type} objects —
// never show that raw (or a JSON dump of it) in a toast. A pydantic
// model_validator's plain `raise ValueError("...")` shows up here as
// `msg: "Value error, <message>"`, so that prefix is stripped too.
function humanizeErrorDetail(detail: unknown, fallback: string): string {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (!item || typeof item !== "object" || !("msg" in item)) return null;
        const msg = String((item as { msg: unknown }).msg).replace(/^Value error,\s*/, "");
        const loc = (item as { loc?: unknown }).loc;
        const path = Array.isArray(loc) ? loc.filter((p) => p !== "body").join(".") : "";
        return path ? `${path}: ${msg}` : msg;
      })
      .filter((m): m is string => Boolean(m));
    if (messages.length > 0) return messages.join("; ");
  }
  return fallback;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      if (body?.detail !== undefined) detail = humanizeErrorDetail(body.detail, detail);
    } catch {
      // ignore body parse failure
    }
    throw new ApiError(res.status, detail);
  }

  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  // Assets
  listAssets: () => request<Asset[]>("/api/v1/assets"),
  getAsset: (id: number) => request<Asset>(`/api/v1/assets/${id}`),
  createAsset: (payload: AssetCreate) =>
    request<Asset>("/api/v1/assets", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deleteAsset: (id: number) =>
    request<void>(`/api/v1/assets/${id}`, { method: "DELETE" }),

  // Scans
  listScans: () => request<Scan[]>("/api/v1/scans"),
  getScan: (id: number) => request<Scan>(`/api/v1/scans/${id}`),
  createScan: (payload: ScanCreate) =>
    request<Scan>("/api/v1/scans", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getScanStatus: (id: number) => request<ScanStatus>(`/api/v1/scans/${id}/status`),
  getScanFindings: (id: number) => request<ScanFindings>(`/api/v1/scans/${id}/findings`),
  cancelScan: (id: number) =>
    request<Scan>(`/api/v1/scans/${id}/cancel`, { method: "POST" }),
  retryScan: (id: number) =>
    request<Scan>(`/api/v1/scans/${id}/retry`, { method: "POST" }),

  // Findings
  listFindings: (params: {
    scan_id?: number;
    asset_id?: number;
    engine?: string;
    severity?: string;
  }) => {
    const search = new URLSearchParams();
    if (params.scan_id !== undefined) search.set("scan_id", String(params.scan_id));
    if (params.asset_id !== undefined) search.set("asset_id", String(params.asset_id));
    if (params.engine) search.set("engine", params.engine);
    if (params.severity) search.set("severity", params.severity);
    const qs = search.toString();
    return request<Finding[]>(`/api/v1/findings${qs ? `?${qs}` : ""}`);
  },

  // Reports
  reportCsvUrl: (scanId?: number) =>
    `${BASE_URL}/api/v1/reports/csv${scanId ? `?scan_id=${scanId}` : ""}`,
  reportPdfUrl: (scanId?: number) =>
    `${BASE_URL}/api/v1/reports/pdf${scanId ? `?scan_id=${scanId}` : ""}`,
  listReports: (scanId?: number) =>
    request<Report[]>(`/api/v1/reports${scanId ? `?scan_id=${scanId}` : ""}`),
  generateReport: (payload: ReportCreate) =>
    request<Report>("/api/v1/reports", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  deleteReport: (id: number) =>
    request<void>(`/api/v1/reports/${id}`, { method: "DELETE" }),
  reportDownloadUrl: (id: number) => `${BASE_URL}/api/v1/reports/${id}/download`,

  // Agents
  listAgents: () => request<Agent[]>("/api/v1/agents"),
};

export { ApiError };
