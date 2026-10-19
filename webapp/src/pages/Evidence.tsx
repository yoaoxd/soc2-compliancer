import { useCallback, useEffect, useState } from "react";
import { api } from "../api";
import { useOrg } from "../org";
import type { CIRun, EvidenceMatrix } from "../types";

const sevColor: Record<string, string> = {
  critical: "var(--danger)",
  high: "#ffb36b",
  medium: "#ffd97a",
  low: "#8fd0ff",
};

type Tab = "matrix" | "ci";

export function Evidence() {
  const org = useOrg();
  const [tab, setTab] = useState<Tab>("matrix");
  const [matrix, setMatrix] = useState<EvidenceMatrix | null>(null);
  const [runs, setRuns] = useState<CIRun[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(() => {
    api
      .evidenceMatrix(org.id)
      .then(setMatrix)
      .catch((e) => setError(e.message));
  }, [org.id]);

  useEffect(() => {
    load();
  }, [load]);

  const loadRuns = useCallback(() => {
    api
      .ciRuns(org.id)
      .then(setRuns)
      .catch((e) => setError(e.message));
  }, [org.id]);

  useEffect(() => {
    if (tab === "ci") loadRuns();
  }, [tab, loadRuns]);

  const catLabel: Record<string, string> = {
    security: "Security",
    availability: "Availability",
    confidentiality: "Confidentiality",
    integrity: "Integrity",
    privacy: "Privacy",
  };

  return (
    <div>
      <h1>Evidence</h1>
      <p style={{ color: "var(--muted)" }}>
        Control coverage across the org's scans, plus CI policy results reported
        against generated bundles.
      </p>
      {error && <p style={{ color: "var(--danger)" }}>{error}</p>}

      <div style={{ display: "flex", gap: 12, margin: "12px 0" }}>
        {(["matrix", "ci"] as Tab[]).map((t) => (
          <button
            key={t}
            className={`btn ${tab === t ? "" : "secondary"}`}
            onClick={() => setTab(t)}
          >
            {t === "matrix" ? "Control matrix" : "CI runs"}
          </button>
        ))}
      </div>

      {tab === "matrix" && (
        <div className="card" style={{ padding: 0, overflowX: "auto" }}>
          <table className="evidence">
            <thead>
              <tr>
                <th>Control</th>
                <th>Category</th>
                <th>Guardrails</th>
                <th>Evidence types</th>
                <th>Open findings</th>
                <th>Severity</th>
                <th>Coverage</th>
              </tr>
            </thead>
            <tbody>
              {matrix?.controls.map((c) => (
                <tr key={c.code}>
                  <td>
                    <strong>{c.code}</strong>
                    <div style={{ color: "var(--muted)", fontSize: 12 }}>{c.title}</div>
                  </td>
                  <td>{catLabel[c.category] || c.category}</td>
                  <td>{c.guardrails}</td>
                  <td>
                    {c.evidence_types.length
                      ? c.evidence_types.map((t) => (
                          <span className="badge" key={t} style={{ marginRight: 4 }}>
                            {t}
                          </span>
                        ))
                      : "—"}
                  </td>
                  <td>{c.open_findings}</td>
                  <td>
                    {Object.entries(c.findings)
                      .map(
                        ([s, n]) =>
                          n > 0 && (
                            <span
                              key={s}
                              className="badge"
                              style={{ color: sevColor[s], borderColor: sevColor[s], marginRight: 4 }}
                            >
                              {s} {n}
                            </span>
                          )
                      )}
                  </td>
                  <td>
                    <CoverageBadge coverage={c.coverage} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {matrix && matrix.controls.length === 0 && (
            <p style={{ color: "var(--muted)", padding: 12 }}>No controls in this edition.</p>
          )}
        </div>
      )}

      {tab === "ci" && (
        <div style={{ display: "grid", gap: 12 }}>
          {runs.length === 0 && (
            <p style={{ color: "var(--muted)" }}>
              No CI runs reported yet. POST /api/v1/orgs/{"{orgID}"}/ci-runs from CI.
            </p>
          )}
          {runs.map((r) => (
            <div className="card" key={r.id}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
                <span
                  className="badge"
                  style={{
                    color: r.status === "passed" ? "var(--accent-2)" : "var(--danger)",
                    borderColor: r.status === "passed" ? "var(--accent-2)" : "var(--danger)",
                  }}
                >
                  {r.status}
                </span>
                <strong>{r.tool || "policy"}</strong>
                <span className="badge">{r.provider}</span>
                <span className="badge">{new Date(r.created_at).toLocaleString()}</span>
                <span style={{ color: "var(--muted)", fontSize: 13 }}>
                  {r.findings.length} findings
                </span>
              </div>
              {r.findings.length > 0 && (
                <ul style={{ color: "var(--muted)", fontSize: 13, margin: "8px 0 0" }}>
                  {r.findings.slice(0, 5).map((f, i) => (
                    <li key={i}>
                      {String((f as Record<string, unknown>).title ?? (f as Record<string, unknown>).policy ?? JSON.stringify(f))}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function CoverageBadge({ coverage }: { coverage: EvidenceMatrix["controls"][number]["coverage"] }) {
  const color =
    coverage === "gaps" ? "var(--danger)" : coverage === "covered" ? "var(--accent-2)" : "var(--muted)";
  return (
    <span className="badge" style={{ color, borderColor: color }}>
      {coverage === "not_assessed" ? "not assessed" : coverage}
    </span>
  );
}