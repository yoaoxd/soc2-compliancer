import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { clearToken, getToken } from "./api";
import { api } from "./api";
import { OrgContext } from "./org";
import type { Org, UserSession } from "./types";
import { Dashboard } from "./pages/Dashboard";
import { Catalog } from "./pages/Catalog";
import { Controls } from "./pages/Controls";
import { Compliance } from "./pages/Compliance";
import { Evidence } from "./pages/Evidence";
import { Login } from "./pages/Login";

export default function App() {
  const [session, setSession] = useState<UserSession | null>(null);
  const [activeOrg, setActiveOrg] = useState<Org | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    if (!getToken()) {
      setLoading(false);
      return;
    }
    api
      .me()
      .then((s) => {
        setSession({ ...s, token: getToken()! });
        if (s.orgs.length > 0) setActiveOrg(s.orgs[0]);
      })
      .catch(() => clearToken())
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <div className="nav">Loading…</div>;

  if (!session) {
    return (
      <Routes>
        <Route
          path="/login"
          element={
            <Login
              onLogin={(s) => {
                setSession(s);
                if (s.orgs.length > 0) setActiveOrg(s.orgs[0]);
              }}
            />
          }
        />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  return (
    <OrgContext.Provider value={activeOrg}>
      <nav className="nav">
        <span className="brand">SOC2 Compliancer</span>
        <NavLink to="/">Dashboard</NavLink>
        <NavLink to="/catalog">Templates</NavLink>
        <NavLink to="/controls">SOC2 Controls</NavLink>
        <NavLink to="/compliance">Compliance</NavLink>
        <NavLink to="/evidence">Evidence</NavLink>
        <span style={{ flex: 1 }} />
        {session.orgs.length > 1 && (
          <select
            style={{
              background: "var(--panel-2)",
              color: "var(--text)",
              border: "1px solid #2c3354",
              borderRadius: 8,
              padding: "6px 8px",
            }}
            value={activeOrg?.id}
            onChange={(e) => {
              const org = session.orgs.find((o) => o.id === e.target.value)!;
              setActiveOrg(org);
            }}
          >
            {session.orgs.map((o) => (
              <option key={o.id} value={o.id}>
                {o.name}
              </option>
            ))}
          </select>
        )}
        <span style={{ color: "var(--muted)", fontSize: 13 }}>
          {session.user.email}
        </span>
        <button
          className="btn secondary"
          onClick={() => {
            clearToken();
            setSession(null);
            navigate("/login");
          }}
        >
          Sign out
        </button>
      </nav>
      <div style={{ padding: 24 }}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/catalog" element={<Catalog />} />
          <Route path="/controls" element={<Controls />} />
          <Route path="/compliance" element={<Compliance />} />
          <Route path="/evidence" element={<Evidence />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </div>
    </OrgContext.Provider>
  );
}