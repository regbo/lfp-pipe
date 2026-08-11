import { StrictMode, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { ArrowRight, Check, Copy, KeyRound, LogOut, ShieldCheck } from "lucide-react";
import brandLogo from "./lfp-connect-reversed.svg";
import "./styles.css";

type Identity = {
  subject: string;
  name: string;
  email: string;
  entitlements: string[];
  required_entitlement: string;
  route_pattern: string;
};

type TunnelToken = {
  token: string;
  expires_at: string;
  hostname: string;
  client_id: string;
  request_subject: string;
  nats_urls: string[];
};

function Brand() {
  return <img className="brand" src={brandLogo} alt="LFP Connect" />;
}

function normalizeEntitlement(value: string) {
  return value.startsWith("route:") ? value.slice(6) : value;
}

function App() {
  const [identity, setIdentity] = useState<Identity>();
  const [hostname, setHostname] = useState("");
  const [clientName, setClientName] = useState("");
  const [issued, setIssued] = useState<TunnelToken | null>(null);
  const [error, setError] = useState("");
  const [working, setWorking] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    fetch("/api/me", { credentials: "same-origin" })
      .then(async (response) => {
        if (response.status === 401) {
          window.location.replace("/api/auth/login");
          return undefined;
        }
        if (!response.ok) throw new Error("Identity lookup failed.");
        return response.json() as Promise<Identity>;
      })
      .then((value) => value && setIdentity(value))
      .catch(() => window.location.replace("/api/auth/login"));
  }, []);

  const requestedHostname = identity && hostname ? `${hostname}.${identity.required_entitlement}` : "";
  const matchedEntitlement = useMemo(() => {
    if (!identity || !requestedHostname) return "";
    return identity.entitlements
      .map(normalizeEntitlement)
      .filter((value) => requestedHostname === value || requestedHostname.endsWith(`.${value}`))
      .sort((left, right) => right.length - left.length)[0] ?? "";
  }, [identity, requestedHostname]);

  async function issue(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setIssued(null);
    setWorking(true);
    try {
      const response = await fetch("/api/tunnel-tokens", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostname: requestedHostname, client_name: clientName }),
      });
      const body = await response.json() as TunnelToken | { error: string };
      if (!response.ok || "error" in body) throw new Error("error" in body ? body.error : "Token issuance failed.");
      setIssued(body);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Token issuance failed.");
    } finally {
      setWorking(false);
    }
  }

  async function copyToken() {
    if (!issued) return;
    await navigator.clipboard.writeText(issued.token);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1800);
  }

  async function logout() {
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
    window.location.assign("/");
  }

  if (!identity) return <div className="loading"><span className="spinner" /></div>;

  return (
    <div className="shell">
      <header className="topbar">
        <Brand />
        <button className="button secondary compact" onClick={logout}><LogOut size={16} /><span>Sign out</span></button>
      </header>
      <main className="main">
        <section className="dashboard">
          <div className="dashboard-header">
            <div><span className="eyebrow">Pipe</span><h1>Route console</h1></div>
            <div className="identity"><span className="avatar">{(identity.name || identity.email || "A")[0]?.toUpperCase()}</span><span className="identity-copy"><strong>{identity.name || "Authentik user"}</strong><span>{identity.email || identity.subject}</span></span></div>
          </div>
          <div className="dashboard-grid">
            <form className="section-card" onSubmit={issue}>
              <div className="section-title"><span className="icon-box"><KeyRound size={20} /></span><div><h2>Issue credential</h2><p>One client and one exact route.</p></div></div>
              <div className="fields">
                <div className="field">
                  <label htmlFor="client-name">Tunnel client</label>
                  <input id="client-name" value={clientName} onChange={(event) => setClientName(event.target.value)} placeholder="regbodesktop" autoComplete="off" required />
                </div>
                <div className="field">
                  <label htmlFor="hostname">Subdomain</label>
                  <div className="input-suffix"><input id="hostname" value={hostname} onChange={(event) => setHostname(event.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))} placeholder="regbodesktop" autoComplete="off" required /><span>.{identity.required_entitlement}</span></div>
                </div>
              </div>
              <div className="submit-row"><span className="helper">Short-lived credential</span><button className="button" disabled={!matchedEntitlement || working}>{working ? "Issuing…" : "Issue credential"}<ArrowRight size={17} /></button></div>
              {error && <p className="error" role="alert">{error}</p>}
              {issued && (
                <div className="token-result" aria-live="polite">
                  <div className="token-result-head"><div><strong>{issued.hostname}</strong><br /><span>Expires {new Date(issued.expires_at).toLocaleString()}</span></div><button type="button" className="button secondary compact" onClick={copyToken}>{copied ? <Check size={15} /> : <Copy size={15} />}{copied ? "Copied" : "Copy"}</button></div>
                  <pre className="token-value">{issued.token}</pre>
                </div>
              )}
            </form>
            <aside className="section-card">
              <div className="section-title"><span className="icon-box"><ShieldCheck size={20} /></span><div><h2>Entitlement</h2><p>From Authentik.</p></div></div>
              {matchedEntitlement ? (
                <div className="entitlement"><Check size={19} /><div><strong>{matchedEntitlement}</strong><span>{requestedHostname}</span></div></div>
              ) : (
                <p className="empty-entitlement">No entitlement covers this route.</p>
              )}
            </aside>
          </div>
        </section>
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
