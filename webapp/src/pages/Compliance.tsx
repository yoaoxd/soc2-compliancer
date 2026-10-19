import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { useOrg } from "../org";
import type { Connection, CreateConnectionInput, Finding, Scan } from "../types";

const providers: { value: string; label: string; hint: string }[] = [
  { value: "gcp", label: "GCP", hint: "Read-only service-account key" },
  { value: "aws", label: "AWS", hint: "Region + access keys" },
  { value: "azure", label: "Azure", hint: "Service principal (Reader + Key Vault Reader)" },
];

const sevColor: Record<string, string> = {
  critical: "var(--danger)",
  high: "#ffb36b",
  medium: "#ffd97a",
  low: "#8fd0ff",
  info: "var(--muted)",
};

type Tab = "connections" | "scans";

function copyText(t: string) {
  navigator.clipboard?.writeText(t).catch(() => {});
}

export function Compliance() {
  const org = useOrg();
  const [tab, setTab] = useState<Tab>("connections");
  const [connections, setConnections] = useState<Connection[]>([]);
  const [selected, setSelected] = useState<Connection | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [severity, setSeverity] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const loadConnections = useCallback(() => {
    api
      .connections(org.id)
      .then(setConnections)
      .catch((e) => setError(e.message));
  }, [org.id]);

  useEffect(() => {
    loadConnections();
  }, [loadConnections]);

  const loadFindings = useCallback(
    (c: Connection, s: Scan, sev: string) => {
      api
        .findings(org.id, c.id, s.id, sev)
        .then(setFindings)
        .catch((e) => setError(e.message));
    },
    [org.id]
  );

  const selectConnection = useCallback(
    (c: Connection) => {
      setSelected(c);
      setScan(null);
      setFindings([]);
      setSeverity("");
      setTab("scans");
      api
        .scans(org.id, c.id)
        .then((s) => {
          setScans(s);
          if (s.length > 0) selectScan(c, s[0]);
        })
        .catch((e) => setError(e.message));
    },
    [org.id]
  );

  const selectScan = useCallback(
    (c: Connection, s: Scan) => {
      setScan(s);
      loadFindings(c, s, severity);
    },
    [severity, loadFindings]
  );

  useEffect(() => {
    if (selected && scan) loadFindings(selected, scan, severity);
  }, [severity, selected, scan, loadFindings]);

  const runScan = async (c: Connection) => {
    setBusy(true);
    setError("");
    try {
      await api.runScan(org.id, c.id);
      selectConnection(c);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const removeConnection = async (c: Connection) => {
    if (!confirm(`Delete connection "${c.name}" and all its scans?`)) return;
    try {
      await api.deleteConnection(org.id, c.id);
      if (selected?.id === c.id) {
        setSelected(null);
        setScans([]);
        setScan(null);
        setFindings([]);
        setTab("connections");
      }
      loadConnections();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <div>
      <h1>Compliance scans</h1>
      <p style={{ color: "var(--muted)" }}>
        Connect a GCP, AWS, or Azure account with read-only credentials, run a
        scan, and review what's missing against SOC2 with fix-it Terraform.
      </p>
      {error && <p style={{ color: "var(--danger)" }}>{error}</p>}

      <div style={{ display: "flex", gap: 12, margin: "12px 0" }}>
        {(["connections", "scans"] as Tab[]).map((t) => (
          <button
            key={t}
            className={`btn ${tab === t ? "" : "secondary"}`}
            onClick={() => setTab(t)}
          >
            {t === "connections" ? "Connections" : "Scans"}
          </button>
        ))}
      </div>

      {tab === "connections" && (
        <div style={{ display: "grid", gap: 20 }}>
          <div className="card">
            <h3>Connect a cloud account</h3>
            <CreateConnectionForm onCreated={loadConnections} />
          </div>

          <div className="grid">
            {connections.map((c) => (
              <div className="card" key={c.id} style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <h3 style={{ margin: 0, flex: 1 }}>{c.name}</h3>
                  <span className="badge">{c.provider}</span>
                </div>
                <div style={{ color: "var(--muted)", fontSize: 13, overflow: "hidden", textOverflow: "ellipsis" }}>
                  {identityMeta(c).scope}: {c.project_id}
                </div>
                <div style={{ color: "var(--muted)", fontSize: 12 }}>
                  {identityMeta(c).actor}: {c.client_email}
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center", marginTop: 6 }}>
                  <label style={{ color: "var(--muted)", fontSize: 12 }}>
                    Re-scan every
                    <input
                      type="number"
                      min={0}
                      value={c.scan_interval_hours}
                      onChange={(e) =>
                        api
                          .updateScanInterval(org.id, c.id, Number(e.target.value))
                          .then(loadConnections)
                          .catch((err) => setError(err.message))
                      }
                      style={{ width: 72, margin: "0 4px", padding: "4px 6px" }}
                    />
                    hrs (0 = off)
                  </label>
                </div>
                <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                  <button className="btn" disabled={busy} onClick={() => runScan(c)}>
                    Run scan
                  </button>
                  <button className="btn secondary" onClick={() => selectConnection(c)}>
                    View scans
                  </button>
                  <button className="btn secondary" onClick={() => removeConnection(c)}>
                    Delete
                  </button>
                </div>
              </div>
            ))}
            {connections.length === 0 && (
              <p style={{ color: "var(--muted)" }}>
                No connections yet — pick a provider above.
              </p>
            )}
          </div>
        </div>
      )}

      {tab === "scans" && (
        <div style={{ display: "grid", gap: 20 }}>
          {selected ? (
            <>
              <div className="card">
                <h3>
                  {selected.name}{" "}
                  <span className="badge">{selected.project_id}</span>
                </h3>
                <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                  <button className="btn" disabled={busy} onClick={() => runScan(selected)}>
                    Run new scan
                  </button>
                  <button className="btn secondary" onClick={() => setTab("connections")}>
                    All connections
                  </button>
                </div>
              </div>

              {scans.length === 0 && (
                <p style={{ color: "var(--muted)" }}>No scans yet.</p>
              )}

              {scans.map((s) => (
                <div className="card" key={s.id}>
                  <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
                    <h3 style={{ margin: 0 }}>
                      Scan {new Date(s.created_at).toLocaleString()}
                    </h3>
                    <span className="badge">{s.status}</span>
                    <span className="badge">{s.findings_count} findings</span>
                    {scan?.id === s.id && <span className="badge">viewing</span>}
                    <div style={{ flex: 1 }} />
                    <button className="btn secondary" onClick={() => selectScan(selected, s)}>
                      View findings
                    </button>
                  </div>
                  {s.status === "failed" && s.error && (
                    <p style={{ color: "var(--danger)", margin: "8px 0 0" }}>
                      {s.error}
                    </p>
                  )}
                </div>
              ))}

              {scan && scan.status === "completed" && (
                <FindingsPanel
                  findings={findings}
                  severity={severity}
                  onSeverity={setSeverity}
                  counts={counts}
                />
              )}
            </>
          ) : (
            <p style={{ color: "var(--muted)" }}>
              Pick a connection to view its scans.
            </p>
          )}
        </div>
      )}
    </div>
  );
}

function identityMeta(c: Connection): { scope: string; actor: string } {
  switch (c.provider) {
    case "aws":
      return { scope: "Region", actor: "Access key" };
    case "azure":
      return { scope: "Subscription", actor: "Client ID" };
    default:
      return { scope: "Project", actor: "Service account" };
  }
}

function CreateConnectionForm({ onCreated }: { onCreated: () => void }) {
  const org = useOrg();
  const [name, setName] = useState("");
  const [provider, setProvider] = useState("gcp");
  const [sa, setSa] = useState("");

  const [region, setRegion] = useState("");
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secretAccessKey, setSecretAccessKey] = useState("");
  const [sessionToken, setSessionToken] = useState("");

  const [subscriptionId, setSubscriptionId] = useState("");
  const [tenantId, setTenantId] = useState("");
  const [clientId, setClientId] = useState("");
  const [clientSecret, setClientSecret] = useState("");

  const [intervalHours, setIntervalHours] = useState(0);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setError("Name is required");
      return;
    }
    if (provider === "gcp" && !sa.trim()) {
      setError("Service account JSON is required");
      return;
    }
    if (provider === "aws" && (!region.trim() || !accessKeyId.trim() || !secretAccessKey.trim())) {
      setError("Region, access key ID, and secret access key are required");
      return;
    }
    if (
      provider === "azure" &&
      (!subscriptionId.trim() || !tenantId.trim() || !clientId.trim() || !clientSecret.trim())
    ) {
      setError("Subscription, tenant, client ID, and client secret are required");
      return;
    }

    const input = buildConnectionInput(provider, name, {
      sa,
      region,
      accessKeyId,
      secretAccessKey,
      sessionToken,
      subscriptionId,
      tenantId,
      clientId,
      clientSecret,
      intervalHours,
    });

    setBusy(true);
    setError("");
    try {
      await api.createConnection(org.id, input);
      setName("");
      setSa("");
      setRegion("");
      setAccessKeyId("");
      setSecretAccessKey("");
      setSessionToken("");
      setSubscriptionId("");
      setTenantId("");
      setClientId("");
      setClientSecret("");
      setIntervalHours(0);
      onCreated();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const activeHint = providers.find((p) => p.value === provider)?.hint;

  return (
    <form onSubmit={submit}>
      <div className="grid">
        <div className="field">
          <label>Name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="prod" />
        </div>
        <div className="field">
          <label>Provider</label>
          <select value={provider} onChange={(e) => setProvider(e.target.value)}>
            {providers.map((p) => (
              <option key={p.value} value={p.value}>
                {p.label}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label>Re-scan interval (hours, 0 = off)</label>
          <input
            type="number"
            min={0}
            value={intervalHours}
            onChange={(e) => setIntervalHours(Number(e.target.value))}
          />
        </div>
      </div>

      <p style={{ color: "var(--muted)", fontSize: 13, margin: "8px 0 12px" }}>
        {activeHint}
      </p>

      {provider === "gcp" && (
        <div className="field">
          <label>Service account JSON (read-only scopes)</label>
          <textarea
            value={sa}
            onChange={(e) => setSa(e.target.value)}
            rows={5}
            placeholder='{"type": "service_account", "project_id": "...", "private_key": "...", "client_email": "..."}'
            style={{
              width: "100%",
              background: "var(--panel-2)",
              color: "var(--text)",
              border: "1px solid #2c3354",
              borderRadius: 8,
              padding: 10,
              fontFamily: "monospace",
              fontSize: 12,
            }}
          />
        </div>
      )}

      {provider === "aws" && (
        <div className="grid">
          <div className="field">
            <label>Region</label>
            <input value={region} onChange={(e) => setRegion(e.target.value)} placeholder="us-east-1" />
          </div>
          <div className="field">
            <label>Access key ID</label>
            <input value={accessKeyId} onChange={(e) => setAccessKeyId(e.target.value)} placeholder="AKIA..." />
          </div>
          <div className="field">
            <label>Secret access key</label>
            <input
              type="password"
              value={secretAccessKey}
              onChange={(e) => setSecretAccessKey(e.target.value)}
              placeholder="••••••••"
            />
          </div>
          <div className="field">
            <label>Session token (optional)</label>
            <input value={sessionToken} onChange={(e) => setSessionToken(e.target.value)} />
          </div>
        </div>
      )}

      {provider === "azure" && (
        <div className="grid">
          <div className="field">
            <label>Subscription ID</label>
            <input value={subscriptionId} onChange={(e) => setSubscriptionId(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" />
          </div>
          <div className="field">
            <label>Tenant ID</label>
            <input value={tenantId} onChange={(e) => setTenantId(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" />
          </div>
          <div className="field">
            <label>Client ID</label>
            <input value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder="00000000-0000-0000-0000-000000000000" />
          </div>
          <div className="field">
            <label>Client secret</label>
            <input
              type="password"
              value={clientSecret}
              onChange={(e) => setClientSecret(e.target.value)}
              placeholder="••••••••"
            />
          </div>
        </div>
      )}

      {error && <p style={{ color: "var(--danger)" }}>{error}</p>}
      <button className="btn" type="submit" disabled={busy} style={{ marginTop: 8 }}>
        {busy ? "Connecting…" : "Connect account"}
      </button>
    </form>
  );
}

function buildConnectionInput(
  provider: string,
  name: string,
  v: {
    sa: string;
    region: string;
    accessKeyId: string;
    secretAccessKey: string;
    sessionToken: string;
    subscriptionId: string;
    tenantId: string;
    clientId: string;
    clientSecret: string;
    intervalHours: number;
  }
): CreateConnectionInput {
  const base = { provider, name, scan_interval_hours: v.intervalHours };
  if (provider === "aws") {
    return {
      ...base,
      aws_credentials: {
        region: v.region.trim(),
        access_key_id: v.accessKeyId.trim(),
        secret_access_key: v.secretAccessKey.trim(),
        ...(v.sessionToken.trim() ? { session_token: v.sessionToken.trim() } : {}),
      },
    };
  }
  if (provider === "azure") {
    return {
      ...base,
      azure_credentials: {
        subscription_id: v.subscriptionId.trim(),
        tenant_id: v.tenantId.trim(),
        client_id: v.clientId.trim(),
        client_secret: v.clientSecret.trim(),
      },
    };
  }
  return { ...base, service_account_json: v.sa };
}

function FindingsPanel({
  findings,
  severity,
  onSeverity,
  counts,
}: {
  findings: Finding[];
  severity: string;
  onSeverity: (s: string) => void;
  counts: Record<string, number>;
}) {
  const [open, setOpen] = useState<string | null>(null);
  const sevs = ["critical", "high", "medium", "low"];

  return (
    <div>
      <div style={{ display: "flex", gap: 8, alignItems: "center", margin: "12px 0", flexWrap: "wrap" }}>
        {["", ...sevs].map((s) => (
          <button
            key={s || "all"}
            className={`btn ${severity === s ? "" : "secondary"}`}
            onClick={() => onSeverity(s)}
          >
            {s || "all"}
            {s && counts[s] ? ` (${counts[s]})` : ""}
          </button>
        ))}
      </div>

      {findings.length === 0 && (
        <p style={{ color: "var(--muted)" }}>
          No findings{severity ? ` at severity "${severity}"` : ""}.
        </p>
      )}

      <div style={{ display: "grid", gap: 12 }}>
        {findings.map((f) => (
          <div className="card" key={f.id}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
              <span className="badge" style={{ color: sevColor[f.severity], borderColor: sevColor[f.severity] }}>
                {f.severity}
              </span>
              <strong style={{ flex: 1 }}>{f.title}</strong>
              <span className="badge">{f.resource_type}</span>
              <span className="badge">{f.resource_name}</span>
              <button className="btn secondary" onClick={() => setOpen(open === f.id ? null : f.id)}>
                {open === f.id ? "Hide" : "Fix"}
              </button>
            </div>
            <div style={{ color: "var(--muted)", fontSize: 13, marginTop: 6 }}>
              {f.check_name} · controls: {f.controls.join(", ") || "—"}
            </div>
            {open === f.id && (
              <div style={{ marginTop: 12 }}>
                <div style={{ color: "var(--muted)", fontSize: 13, marginBottom: 4 }}>{f.remediation.notes}</div>
                <pre
                  style={{
                    background: "#0c0f1c",
                    border: "1px solid #262d4a",
                    borderRadius: 8,
                    padding: 12,
                    overflowX: "auto",
                    fontSize: 12,
                    lineHeight: 1.5,
                  }}
                >
                  <code>{f.remediation.import_command}</code>
                </pre>
                <button className="btn secondary" onClick={() => copyText(f.remediation.import_command)}>
                  Copy import command
                </button>
                <pre
                  style={{
                    background: "#0c0f1c",
                    border: "1px solid #262d4a",
                    borderRadius: 8,
                    padding: 12,
                    overflowX: "auto",
                    fontSize: 12,
                    lineHeight: 1.5,
                    whiteSpace: "pre",
                  }}
                >
                  <code>{f.remediation.terraform_config}</code>
                </pre>
                <button className="btn" onClick={() => copyText(f.remediation.terraform_config)}>
                  Copy Terraform
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
