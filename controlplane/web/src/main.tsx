import { StrictMode, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { ArrowRight, Check, Copy, KeyRound, LogOut, Network, ShieldCheck } from "lucide-react";
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
  return (
    <a className="brand" href="/" aria-label="LFP Connect home">
      <span className="brand-mark" aria-hidden="true" />
      <span className="brand-copy"><strong>LFP CONNECT</strong><span>Private routes · public reach</span></span>
    </a>
  );
}

function App() {
  const [identity, setIdentity] = useState<Identity | null | undefined>();
  const [hostname, setHostname] = useState("");
  const [clientName, setClientName] = useState("");
  const [issued, setIssued] = useState<TunnelToken | null>(null);
  const [error, setError] = useState("");
  const [working, setWorking] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    fetch("/api/me", { credentials: "same-origin" })
      .then(async (response) => response.ok ? response.json() as Promise<Identity> : null)
      .then(setIdentity)
      .catch(() => setIdentity(null));
  }, []);

  const requestedHostname = identity && hostname ? `${hostname}.${identity.required_entitlement}` : "";
  const hasEntitlement = useMemo(() => Boolean(identity && requestedHostname && identity.entitlements.some((raw) => {
    const entitlement = raw.startsWith("route:") ? raw.slice(6) : raw;
    return requestedHostname === entitlement || requestedHostname.endsWith(`.${entitlement}`);
  })), [identity, requestedHostname]);

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

  if (identity === undefined) {
    return <div className="loading"><span><span className="spinner" />Opening the control plane…</span></div>;
  }

  return (
    <div className="shell">
      <header className="topbar">
        <Brand />
        {identity ? (
          <button className="button secondary compact" onClick={logout}><LogOut size={16} /><span>Sign out</span></button>
        ) : <span className="signal">Authentik secured</span>}
      </header>
      <main className="main">
        {!identity ? (
          <section className="hero">
            <div>
              <span className="eyebrow">Route authority</span>
              <h1>Own the name.<br />Move the traffic.</h1>
              <p className="hero-copy">Issue short-lived tunnel credentials for the subdomains your team owns. Authentik establishes the entitlement; NATS enforces the route.</p>
              <div className="signal-row">
                <span className="signal">OIDC identity</span><span className="signal">NATS subject isolation</span><span className="signal">Expiring access</span>
              </div>
            </div>
            <aside className="panel auth-card">
              <div className="panel-head"><span>Control plane / access</span><i className="status-dot" /></div>
              <div className="panel-body">
                <h2>Connect your identity</h2>
                <p>Continue through Authentik to load the route entitlements assigned directly to you or inherited through your team.</p>
                <a className="button" href="/api/auth/login">Continue with Authentik <ArrowRight size={18} /></a>
                <ul className="trust-list">
                  <li><ShieldCheck size={17} /> No domain permissions stored in this browser</li>
                  <li><KeyRound size={17} /> Credentials expire automatically</li>
                  <li><Network size={17} /> Exact route mapped to one NATS subject</li>
                </ul>
              </div>
            </aside>
          </section>
        ) : (
          <section className="dashboard">
            <div className="dashboard-header">
              <div><span className="eyebrow">Tunnel issuance</span><h1>Route console</h1></div>
              <div className="identity"><span className="avatar">{(identity.name || identity.email || "A")[0]?.toUpperCase()}</span><span className="identity-copy"><strong>{identity.name || "Authentik user"}</strong><span>{identity.email || identity.subject}</span></span></div>
            </div>
            <div className="dashboard-grid">
              <form className="section-card" onSubmit={issue}>
                <div className="section-title"><span className="icon-box"><KeyRound size={20} /></span><div><h2>Issue a tunnel credential</h2><p>Credentials authorize one client against one exact route.</p></div></div>
                <div className="fields">
                  <div className="field">
                    <label htmlFor="client-name">Tunnel client</label>
                    <input id="client-name" value={clientName} onChange={(event) => setClientName(event.target.value)} placeholder="unraid-east" autoComplete="off" required />
                  </div>
                  <div className="field">
                    <label htmlFor="hostname">Subdomain</label>
                    <div className="input-suffix"><input id="hostname" value={hostname} onChange={(event) => setHostname(event.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))} placeholder="cool" autoComplete="off" required /><span>.{identity.required_entitlement}</span></div>
                  </div>
                </div>
                <div className="submit-row"><span className="helper">The token is shown once and expires automatically.</span><button className="button" disabled={!hasEntitlement || working}>{working ? "Issuing…" : "Issue credential"}<ArrowRight size={17} /></button></div>
                {error && <p className="error" role="alert">{error}</p>}
                {issued && (
                  <div className="token-result" aria-live="polite">
                    <div className="token-result-head"><div><strong>{issued.hostname}</strong><br /><span>Expires {new Date(issued.expires_at).toLocaleString()}</span></div><button type="button" className="button secondary compact" onClick={copyToken}>{copied ? <Check size={15} /> : <Copy size={15} />}{copied ? "Copied" : "Copy"}</button></div>
                    <pre className="token-value">{issued.token}</pre>
                  </div>
                )}
              </form>
              <aside className="section-card">
                <div className="section-title"><span className="icon-box"><ShieldCheck size={20} /></span><div><h2>Effective entitlement</h2><p>Resolved from your Authentik user and groups.</p></div></div>
                {hasEntitlement ? (
                  <div className="entitlement"><Check size={19} /><div><strong>{identity.required_entitlement}</strong><span>May issue routes matching {identity.route_pattern}</span></div></div>
                ) : (
                  <p className="empty-entitlement">Your Authentik identity does not currently include <strong>{identity.required_entitlement}</strong>. Ask a team owner to bind that entitlement to your user or group.</p>
                )}
              </aside>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
