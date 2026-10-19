import { useEffect, useState } from "react";
import { api, setToken } from "../api";
import type { UserSession } from "../types";

export function Login({ onLogin }: { onLogin: (s: UserSession) => void }) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [orgName, setOrgName] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // Handle redirect back from Google OAuth with a token/error query param.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("token");
    const oauthErr = params.get("error");
    if (token) {
      setToken(token);
      params.delete("token");
      params.delete("error");
      const qs = params.toString();
      window.history.replaceState({}, "", qs ? `?${qs}` : window.location.pathname);
      api
        .me()
        .then((s) => onLogin({ ...s, token }))
        .catch((e) => setError(e.message));
    } else if (oauthErr) {
      setError(oauthErr);
    }
  }, [onLogin]);

  function startGoogle() {
    window.location.href = "/api/v1/auth/google/start";
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const session =
        mode === "login"
          ? await api.login(email, password)
          : await api.register({
              email,
              password,
              display_name: displayName || email,
              org_name: orgName,
            });
      setToken(session.token);
      onLogin(session);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div
      style={{
        maxWidth: 380,
        margin: "80px auto",
        padding: 24,
      }}
      className="card"
    >
      <h2>SOC2 Compliancer</h2>
      <p style={{ color: "var(--muted)", fontSize: 14 }}>
        Terraform templates that make your cloud infrastructure SOC2-ready.
      </p>

      <button
        className="btn"
        style={{ width: "100%", marginBottom: 16 }}
        onClick={startGoogle}
      >
        Continue with Google
      </button>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          color: "var(--muted)",
          fontSize: 12,
          marginBottom: 16,
        }}
      >
        <span style={{ flex: 1, height: 1, background: "#2c3354" }} />
        or use email
        <span style={{ flex: 1, height: 1, background: "#2c3354" }} />
      </div>

      <div style={{ display: "flex", gap: 8, margin: "16px 0" }}>
        <button
          className={mode === "login" ? "btn" : "btn secondary"}
          onClick={() => setMode("login")}
        >
          Sign in
        </button>
        <button
          className={mode === "register" ? "btn" : "btn secondary"}
          onClick={() => setMode("register")}
        >
          Create account
        </button>
      </div>

      <form onSubmit={submit}>
        {mode === "register" && (
          <>
            <div className="field">
              <label>Display name</label>
              <input
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
              />
            </div>
            <div className="field">
              <label>Organization</label>
              <input
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="Acme Inc."
              />
            </div>
          </>
        )}
        <div className="field">
          <label>Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
          />
        </div>
        <div className="field">
          <label>Password (min 8 chars)</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
        </div>
        {error && <p style={{ color: "var(--danger)", fontSize: 13 }}>{error}</p>}
        <button className="btn" disabled={busy} style={{ width: "100%", marginTop: 12 }}>
          {busy ? "Working…" : mode === "login" ? "Sign in" : "Create account"}
        </button>
      </form>
    </div>
  );
}