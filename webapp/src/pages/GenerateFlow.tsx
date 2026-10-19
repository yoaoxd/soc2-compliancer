import { useMemo, useState } from "react";
import { api, fetchZip } from "../api";
import type { Component, GenerateResult } from "../types";
import { useOrg } from "../org";

type Selected = { provider: string; component: Component };

export function GenerateFlow({
  selection,
  onReset,
}: {
  selection: Selected[];
  onReset: () => void;
}) {
  const org = useOrg();
  const providers = useMemo(
    () => [...new Set(selection.map((s) => s.provider))],
    [selection]
  );
  const multi = providers.length > 1;

  const [values, setValues] = useState<Record<string, string>>({});
  const [results, setResults] = useState<GenerateResult[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [downloading, setDownloading] = useState(false);

  const key = (provider: string, comp: string, varName: string) =>
    `${provider}/${comp}/${varName}`;

  function requestBody() {
    return {
      providers,
      components: selection.map((s) => ({
        provider: s.provider,
        name: s.component.name,
        variables: Object.fromEntries(
          (s.component.variables || [])
            .map((v) => [v.name, values[key(s.provider, s.component.name, v.name)]])
            .filter(([, v]) => v !== undefined && (v as string).trim() !== "")
        ),
      })),
    };
  }

  async function generate() {
    setError("");
    setBusy(true);
    try {
      const res = await api.generate(org.id, requestBody());
      setResults((r) => [res, ...r]);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function downloadZip() {
    setDownloading(true);
    try {
      const blob = await fetchZip(org.id, requestBody());
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `soc2-bundle.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setDownloading(false);
    }
  }

  const compName = (provider: string, comp: string) =>
    multi ? `${provider}/${comp}` : comp;

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <h2 style={{ margin: 0 }}>Generate bundle</h2>
        <span className="badge">
          {selection.length} component{selection.length === 1 ? "" : "s"} ·{" "}
          {providers.length} provider{providers.length === 1 ? "" : "s"}
        </span>
        <span style={{ flex: 1 }} />
        <button className="btn secondary" onClick={onReset}>
          Back to catalog
        </button>
      </div>
      <p style={{ color: "var(--muted)" }}>
        Selected components are packed into{" "}
        <strong style={{ color: "var(--text)" }}>one</strong> Terraform bundle.
        Fill in the inputs below, then generate.
      </p>

      {error && <p style={{ color: "var(--danger)" }}>{error}</p>}

      {providers.map((provider) => {
        const comps = selection.filter((s) => s.provider === provider);
        return (
          <div className="card" key={provider} style={{ marginTop: 16 }}>
            <h3 style={{ margin: "0 0 8px" }}>
              <span className={`provider-dot ${provider}`} />{" "}
              {provider.toUpperCase()}
            </h3>
            {comps.map((s) => (
              <div key={s.component.name} style={{ margin: "10px 0" }}>
                <strong>{compName(provider, s.component.name)}</strong>
                {(s.component.variables || []).map((v) => (
                  <div key={v.name} className="field">
                    <label>
                      {v.name}
                      {v.required ? " *" : ""} ({v.type})
                    </label>
                    <input
                      placeholder={v.default || (v.required ? "required" : "optional")}
                      value={values[key(provider, s.component.name, v.name)] || ""}
                      onChange={(e) =>
                        setValues((prev) => ({
                          ...prev,
                          [key(provider, s.component.name, v.name)]: e.target.value,
                        }))
                      }
                    />
                  </div>
                ))}
              </div>
            ))}
          </div>
        );
      })}

      <div
        style={{
          position: "sticky",
          bottom: 12,
          marginTop: 16,
          display: "flex",
          gap: 12,
          alignItems: "center",
          background: "var(--panel)",
          border: "1px solid #262d4a",
          borderRadius: 12,
          padding: "12px 16px",
        }}
      >
        <span style={{ flex: 1 }} />
        <button className="btn secondary" disabled={downloading} onClick={downloadZip}>
          {downloading ? "Preparing…" : "Download ZIP"}
        </button>
        <button className="btn" disabled={busy} onClick={generate}>
          {busy ? "Generating…" : `Generate bundle (${selection.length})`}
        </button>
      </div>

      {results.map((r, i) => (
        <div
          key={i}
          className="card"
          style={{ marginTop: 14, background: "var(--panel-2)" }}
        >
          <strong>Generated:</strong> {r.provider}
          {" — "}
          {r.components.join(", ")}
          {r.warnings && r.warnings.length > 0 && (
            <ul style={{ color: "var(--muted)", fontSize: 13 }}>
              {r.warnings.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>
          )}
          <div style={{ margin: "8px 0" }}>
            {r.controls.map((c) => (
              <span className="badge" key={c} style={{ marginRight: 6 }}>
                {c}
              </span>
            ))}
          </div>
          <details>
            <summary style={{ cursor: "pointer", color: "var(--accent)" }}>
              View generated files ({r.files.length})
            </summary>
            <pre
              style={{
                background: "#0b0e1d",
                padding: 12,
                borderRadius: 8,
                overflow: "auto",
                fontSize: 12,
                maxHeight: 320,
              }}
            >
              {r.files.map((f) => `${f.path}\n`).join("")}
            </pre>
          </details>
        </div>
      ))}
    </div>
  );
}