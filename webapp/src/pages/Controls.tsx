import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { Control } from "../types";

export function Controls() {
  const [controls, setControls] = useState<Control[]>([]);
  const [edition, setEdition] = useState("soc2_2017");
  const [category, setCategory] = useState("security");
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .controls(edition, category)
      .then(setControls)
      .catch((e) => setError(e.message));
  }, [edition, category]);

  const counts = useMemo(() => {
    const map: Record<string, number> = {};
    for (const c of controls) map[c.category] = (map[c.category] || 0) + 1;
    return map;
  }, [controls]);

  return (
    <div>
      <h1>SOC2 controls</h1>
      <p style={{ color: "var(--muted)" }}>
        Trust Services Criteria. Original summaries of the criteria, mapped to
        cloud guardrails. The AICPA did not renumber controls across editions —
        the 2025 guidance revises points of focus only.
      </p>

      <div style={{ display: "flex", gap: 12, flexWrap: "wrap", alignItems: "center", margin: "12px 0" }}>
        <select value={edition} onChange={(e) => setEdition(e.target.value)}>
          <option value="soc2_2017">soc2_2017</option>
          <option value="soc2_2025">soc2_2025</option>
        </select>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {["security", "availability", "confidentiality", "integrity", "privacy"].map(
            (c) => (
              <button
                key={c}
                className={category === c ? "btn" : "btn secondary"}
                onClick={() => setCategory(c)}
              >
                {c} {counts[c] ? `(${counts[c]})` : ""}
              </button>
            )
          )}
        </div>
      </div>

      {error && <p style={{ color: "var(--danger)" }}>{error}</p>}
      <div className="grid">
        {controls.map((c) => (
          <div className="card" key={c.id}>
            <div style={{ display: "flex", justifyContent: "space-between" }}>
              <strong>{c.code}</strong>
              <span className="badge">{c.edition}</span>
            </div>
            <div style={{ margin: "6px 0", fontWeight: 600 }}>{c.title}</div>
            <div style={{ color: "var(--muted)", fontSize: 13 }}>{c.description}</div>
          </div>
        ))}
      </div>
    </div>
  );
}