import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import type { Provider } from "../types";

export function Dashboard() {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api.providers().then(setProviders).catch((e) => setError(e.message));
  }, []);

  const totalComponents = providers.reduce((n, p) => n + p.components.length, 0);

  return (
    <div>
      <h1>Build SOC2-ready infrastructure</h1>
      <p style={{ color: "var(--muted)" }}>
        Pick components from any cloud provider and generate one Terraform bundle
        wired to SOC2 controls — or connect a cloud account to scan it for gaps.
      </p>
      {error && <p style={{ color: "var(--danger)" }}>{error}</p>}

      <div style={{ display: "flex", gap: 16, margin: "20px 0" }}>
        <Metric label="Providers" value={providers.length} />
        <Metric label="Components" value={totalComponents} />
        <Metric label="SOC2 controls mapped" value={36} />
      </div>

      <div className="grid">
        {providers.map((p) => (
          <Link to="/catalog" key={p.name} style={{ color: "inherit" }}>
            <div className="card selectable" style={{ height: "100%" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                <span className={`provider-dot ${p.name}`} />
                <h3 style={{ margin: 0 }}>{p.name.toUpperCase()}</h3>
              </div>
              <div style={{ color: "var(--muted)", fontSize: 14, marginTop: 4 }}>
                {p.display_name}
              </div>
              <div style={{ marginTop: 12, display: "flex", gap: 8 }}>
                <span className="badge accent">
                  {p.components.length} component{p.components.length === 1 ? "" : "s"}
                </span>
              </div>
              <div style={{ marginTop: 12 }}>
                <span className="muted" style={{ fontSize: 13 }}>
                  {p.components.map((c) => c.name).join(", ") || "—"}
                </span>
              </div>
            </div>
          </Link>
        ))}
      </div>
      {providers.length === 0 && !error && (
        <div className="empty">Loading providers…</div>
      )}
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div
      style={{
        flex: 1,
        background: "var(--panel)",
        border: "1px solid #273056",
        borderRadius: 14,
        padding: "16px 20px",
        textAlign: "center",
      }}
    >
      <div style={{ fontSize: 28, fontWeight: 800, color: "var(--accent)" }}>
        {value}
      </div>
      <div className="muted" style={{ fontSize: 12, textTransform: "uppercase", letterSpacing: "0.05em" }}>
        {label}
      </div>
    </div>
  );
}