import type { AnalysisReport, ApiKeyInfo, Me, ScanStatus, ScanSummary, UsageResponse } from "./types";

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "https://cipherfault.onrender.com";
const KEY = "cipherfault_api_key";

export function getApiKey() {
  return localStorage.getItem(KEY) || "";
}

export function setApiKey(value: string) {
  localStorage.setItem(KEY, value.trim());
}

export function clearApiKey() {
  localStorage.removeItem(KEY);
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...opts,
    headers: { "X-API-Key": getApiKey(), ...opts.headers },
  });
  if (!res.ok) throw new ApiError(res.status, await res.text());
  return res.status === 204 ? (undefined as T) : res.json();
}

export const api = {
  health: () => fetch(`${BASE_URL}/healthz`),
  ready: () => fetch(`${BASE_URL}/readyz`),
  me: () => apiFetch<Me>("/v1/me"),
  uploadScan: (file: File) => {
    const body = new FormData();
    body.append("file", file);
    return apiFetch<{ scan_id: string; job_id: string; status: string }>("/v1/scans/upload", {
      method: "POST",
      body,
    });
  },
  getScan: (id: string) => apiFetch<ScanStatus>(`/v1/scans/${id}`),
  getFindings: (id: string) => apiFetch<AnalysisReport>(`/v1/scans/${id}/findings`),
  getCbom: (id: string) => apiFetch<object>(`/v1/scans/${id}/cbom`),
  listScans: (orgId: string) => apiFetch<ScanSummary[]>(`/v1/orgs/${orgId}/scans`),
  getUsage: (orgId: string) => apiFetch<UsageResponse>(`/v1/orgs/${orgId}/usage`),
  listApiKeys: (orgId: string) => apiFetch<ApiKeyInfo[]>(`/v1/orgs/${orgId}/api-keys`),
  createApiKey: (orgId: string, name: string) =>
    apiFetch<{ id: string; name: string; key_prefix: string; api_key: string }>(`/v1/orgs/${orgId}/api-keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name }),
    }),
  revokeApiKey: (orgId: string, keyId: string) =>
    apiFetch<void>(`/v1/orgs/${orgId}/api-keys/${keyId}`, { method: "DELETE" }),
};
