const TOKEN_KEY = "soc2.token";

export function setToken(token: string) {
  localStorage.setItem(TOKEN_KEY, token);
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function clearToken() {
  localStorage.removeItem(TOKEN_KEY);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const res = await fetch(`/api${path}`, { ...init, headers });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error((body as { error?: string }).error || `HTTP ${res.status}`);
  }
  return res.json();
}

export const api = {
  login: (email: string, password: string) =>
    request<import("./types").UserSession>("/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }),
  register: (body: {
    email: string;
    password: string;
    display_name: string;
    org_name: string;
  }) =>
    request<import("./types").UserSession>("/v1/auth/register", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  me: () => request<import("./types").UserSession>("/v1/auth/me"),
  controls: (edition = "soc2_2017", category = "") =>
    request<import("./types").Control[]>(
      `/v1/registry/controls?edition=${edition}&category=${category}`
    ),
  mappings: (provider = "") =>
    request<import("./types").Mapping[]>(`/v1/registry/mappings?provider=${provider}`),
  providers: () => request<import("./types").Provider[]>("/v1/catalog/providers"),
  generate: (orgID: string, req: import("./types").GenerateRequest) =>
    request<import("./types").GenerateResult>(`/v1/orgs/${orgID}/generations/generate`, {
      method: "POST",
      body: JSON.stringify(req),
    }),
  generations: (orgID: string) =>
    request<import("./types").GenerationRecord[]>(`/v1/orgs/${orgID}/generations`),
  connections: (orgID: string) =>
    request<{ connections: import("./types").Connection[] }>(
      `/v1/orgs/${orgID}/connections`
    ).then((r) => r.connections),
  createConnection: (
    orgID: string,
    body: import("./types").CreateConnectionInput
  ) =>
    request<import("./types").Connection>(`/v1/orgs/${orgID}/connections`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateScanInterval: (orgID: string, connectionID: string, hours: number) =>
    request<import("./types").Connection>(
      `/v1/orgs/${orgID}/connections/${connectionID}`,
      { method: "PATCH", body: JSON.stringify({ scan_interval_hours: hours }) }
    ),
  deleteConnection: (orgID: string, connectionID: string) =>
    request<{ status: string }>(`/v1/orgs/${orgID}/connections/${connectionID}`, {
      method: "DELETE",
    }),
  runScan: (orgID: string, connectionID: string) =>
    request<import("./types").Scan>(
      `/v1/orgs/${orgID}/connections/${connectionID}/scan`,
      { method: "POST" }
    ),
  scans: (orgID: string, connectionID: string) =>
    request<{ scans: import("./types").Scan[] }>(
      `/v1/orgs/${orgID}/connections/${connectionID}/scans`
    ).then((r) => r.scans),
  findings: (orgID: string, connectionID: string, scanID: string, severity = "") =>
    request<{ findings: import("./types").Finding[] }>(
      `/v1/orgs/${orgID}/connections/${connectionID}/scans/${scanID}/findings${
        severity ? `?severity=${severity}` : ""
      }`
    ).then((r) => r.findings),
  evidenceMatrix: (orgID: string) =>
    request<import("./types").EvidenceMatrix>(`/v1/orgs/${orgID}/evidence/matrix`),
  ciRuns: (orgID: string) =>
    request<{ runs: import("./types").CIRun[] }>(`/v1/orgs/${orgID}/ci-runs`).then(
      (r) => r.runs
    ),
};

// fetchZip downloads the bundle as a zip Blob.
export async function fetchZip(
  orgID: string,
  req: import("./types").GenerateRequest
): Promise<Blob> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const res = await fetch(`/api/v1/orgs/${orgID}/generations/generate?format=zip`, {
    method: "POST",
    headers,
    body: JSON.stringify(req),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error((body as { error?: string }).error || `HTTP ${res.status}`);
  }
  return res.blob();
}