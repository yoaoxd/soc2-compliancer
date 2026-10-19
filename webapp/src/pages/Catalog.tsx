import { useEffect, useMemo, useState } from "react";
import { api } from "../api";
import type { Component, Provider } from "../types";
import { GenerateFlow } from "./GenerateFlow";

const categories: Record<string, string> = {
  storage: "Storage",
  compute: "Compute",
  data: "Data & Databases",
  networking: "Networking",
  security: "Security & Identity",
  secrets: "Secrets & Keys",
  observability: "Logging & Monitoring",
};

type Selection = { provider: string; component: Component };

export function Catalog() {
  const [providers, setProviders] = useState<Provider[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [category, setCategory] = useState("");
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    api.providers().then(setProviders).catch((e) => setError(e.message));
  }, []);

  const categoriesPresent = useMemo(() => {
    const set = new Set<string>();
    for (const p of providers) for (const c of p.components) set.add(c.category);
    return [...set];
  }, [providers]);

  const selection: Selection[] = useMemo(() => {
    const out: Selection[] = [];
    for (const p of providers) {
      for (const c of p.components) {
        if (selected.has(`${p.name}/${c.name}`)) out.push({ provider: p.name, component: c });
      }
    }
    return out;
  }, [providers, selected]);

  const toggle = (name: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  if (generating) {
    return (
      <GenerateFlow
        selection={selection}
        onReset={() => setGenerating(false)}
      />
    );
  }

  return (
    <div>
      <h1>Component catalog</h1>
      <p style={{ color: "var(--muted)" }}>
        Select any components — across providers — then generate a{" "}
        <strong style={{ color: "var(--text)" }}>single</strong> SOC2-mapped
        Terraform bundle with dependency wiring and policy tests.
      </p>
      {error && <p style={{ color: "var(--danger)" }}>{error}</p>}

      <div className="pill-row">
        <button
          className={`pill ${category === "" ? "active" : ""}`}
          onClick={() => setCategory("")}
        >
          All
        </button>
        {categoriesPresent.map((c) => (
          <button
            key={c}
            className={`pill ${category === c ? "active" : ""}`}
            onClick={() => setCategory(c)}
          >
            {categories[c] || c}
          </button>
        ))}
      </div>

      {providers.flatMap((p) =>
        p.components.filter((c) => category === "" || c.category === category)
      ).length === 0 ? (
        <div className="empty">
          {error ? "Could not load components." : "Loading components…"}
        </div>
      ) : (
        <div className="grid">
          {providers.flatMap((p) =>
            p.components
              .filter((c) => category === "" || c.category === category)
              .map((c) => (
                <ComponentCard
                  key={`${p.name}/${c.name}`}
                  provider={p.name}
                  component={c}
                  selected={selected.has(`${p.name}/${c.name}`)}
                  onToggle={toggle}
                />
              ))
          )}
        </div>
      )}

      {selected.size > 0 && (
        <div
          style={{
            position: "sticky",
            bottom: 12,
            marginTop: 24,
            display: "flex",
            gap: 12,
            alignItems: "center",
            background: "var(--panel)",
            border: "1px solid #273056",
            borderRadius: 14,
            padding: "12px 16px",
            boxShadow: "0 10px 30px rgba(0,0,0,0.4)",
          }}
        >
          <span className="badge accent">{selected.size} selected</span>
          <span className="muted" style={{ fontSize: 13 }}>
            {new Set(selection.map((s) => s.provider)).size} provider
            {new Set(selection.map((s) => s.provider)).size === 1 ? "" : "s"} · one
            bundle on generate
          </span>
          <span style={{ flex: 1 }} />
          <button className="btn secondary" onClick={() => setSelected(new Set())}>
            Clear
          </button>
          <button className="btn" onClick={() => setGenerating(true)}>
            Generate bundle →
          </button>
        </div>
      )}
    </div>
  );
}

function ComponentCard({
  provider,
  component,
  selected,
  onToggle,
}: {
  provider: string;
  component: Component;
  selected: boolean;
  onToggle: (key: string) => void;
}) {
  return (
    <div
      className={`card selectable ${selected ? "selected" : ""}`}
      onClick={() => onToggle(`${provider}/${component.name}`)}
    >
      <div className="checkmark">{selected ? "✓" : ""}</div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
        <strong>{component.name}</strong>
        <span className={`badge badge-provider ${provider}`}>{provider.toUpperCase()}</span>
      </div>
      <p style={{ color: "var(--muted)", fontSize: 13, minHeight: 40 }}>
        {component.description}
      </p>
      <div style={{ fontSize: 12, color: "var(--muted)" }}>
        {component.resource_types.join(", ")}
      </div>
      {component.dependencies && component.dependencies.length > 0 && (
        <div style={{ fontSize: 12, color: "var(--muted)", marginTop: 4 }}>
          deps: {component.dependencies.join(", ")}
        </div>
      )}
      <div style={{ marginTop: 10 }}>
        {component.controls.map((c) => (
          <span className="control-chip" key={c}>
            {c}
          </span>
        ))}
      </div>
    </div>
  );
}