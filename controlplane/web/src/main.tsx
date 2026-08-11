import { StrictMode, useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { strToU8, zipSync } from "fflate";
import { ArrowRight, Check, Copy, Download, KeyRound, LogOut, Server, ShieldCheck, Trash2 } from "lucide-react";
import brandLogo from "./lfp-connect-reversed.svg";
import "./styles.css";

type Identity = {
  subject: string; name: string; email: string; entitlements: string[];
  required_entitlement: string; route_pattern: string;
};

type TunnelToken = {
  token: string; expires_at: string; hostname: string; client_id: string;
  request_subject: string; nats_urls: string[];
};

type ServicePrincipal = { id: number; username: string; name: string; client_id: string; entitlement: string };
type OAuthSettings = { token_url: string; client_id: string; control_plane_url: string; scopes: string[]; nats_urls: string[] };
type CreatedPrincipal = { service_principal: ServicePrincipal; client_secret: string; oauth: OAuthSettings };

function Brand() { return <img className="brand" src={brandLogo} alt="LFP Connect" />; }
function normalizeEntitlement(value: string) { return value.startsWith("route:") ? value.slice(6) : value; }

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { credentials: "same-origin", ...init });
  if (response.status === 401) {
    window.location.replace("/api/auth/login");
    throw new Error("Authentication required.");
  }
  const body = response.status === 204 ? undefined : await response.json();
  if (!response.ok) throw new Error(body?.error ?? "Request failed.");
  return body as T;
}

function App() {
  const [identity, setIdentity] = useState<Identity>();
  const [hostname, setHostname] = useState("");
  const [clientName, setClientName] = useState("");
  const [issued, setIssued] = useState<TunnelToken | null>(null);
  const [principals, setPrincipals] = useState<ServicePrincipal[]>([]);
  const [principalName, setPrincipalName] = useState("");
  const [principalEntitlement, setPrincipalEntitlement] = useState("");
  const [createdPrincipal, setCreatedPrincipal] = useState<CreatedPrincipal | null>(null);
  const [principalsLoading, setPrincipalsLoading] = useState(true);
  const [principalsError, setPrincipalsError] = useState("");
  const [deleteCandidate, setDeleteCandidate] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [working, setWorking] = useState(false);
  const [copied, setCopied] = useState("");

  const effectiveEntitlements = useMemo(() =>
    Array.from(new Set((identity?.entitlements ?? []).map(normalizeEntitlement))).sort(), [identity]);

  async function loadPrincipals() {
    setPrincipalsLoading(true); setPrincipalsError("");
    try {
      const value = await api<{ service_principals: ServicePrincipal[] }>("/api/service-principals");
      setPrincipals(value.service_principals);
    } catch (cause) {
      setPrincipalsError(cause instanceof Error ? cause.message : "Service principals could not be loaded.");
    } finally { setPrincipalsLoading(false); }
  }

  useEffect(() => {
    api<Identity>("/api/me")
      .then((value) => {
        setIdentity(value);
        const normalized = value.entitlements.map(normalizeEntitlement);
        setPrincipalEntitlement(normalized.includes(value.required_entitlement) ? value.required_entitlement : normalized[0] ?? "");
      })
      .catch(() => undefined);
    void loadPrincipals();
  }, []);

  const requestedHostname = identity && hostname ? `${hostname}.${identity.required_entitlement}` : "";
  const matchedEntitlement = useMemo(() => {
    if (!requestedHostname) return "";
    return effectiveEntitlements
      .filter((value) => requestedHostname === value || requestedHostname.endsWith(`.${value}`))
      .sort((left, right) => right.length - left.length)[0] ?? "";
  }, [effectiveEntitlements, requestedHostname]);

  async function issue(event: React.FormEvent) {
    event.preventDefault(); setError(""); setIssued(null); setWorking(true);
    try {
      setIssued(await api<TunnelToken>("/api/tunnel-tokens", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostname: requestedHostname, client_name: clientName }),
      }));
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Token issuance failed."); }
    finally { setWorking(false); }
  }

  async function createPrincipal(event: React.FormEvent) {
    event.preventDefault(); setError(""); setCreatedPrincipal(null); setWorking(true);
    try {
      const created = await api<CreatedPrincipal>("/api/service-principals", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: principalName, entitlement: principalEntitlement }),
      });
      setCreatedPrincipal(created);
      setPrincipalName("");
      await loadPrincipals();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Service principal creation failed."); }
    finally { setWorking(false); }
  }

  async function deletePrincipal(principal: ServicePrincipal) {
    setError("");
    try {
      await api<void>(`/api/service-principals/${principal.id}`, { method: "DELETE" });
      if (createdPrincipal?.service_principal.id === principal.id) setCreatedPrincipal(null);
      setDeleteCandidate(null);
      await loadPrincipals();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Deletion failed."); }
  }

  async function copy(label: string, value: string) {
    await navigator.clipboard.writeText(value); setCopied(label);
    window.setTimeout(() => setCopied(""), 1800);
  }

  function downloadBundle(created: CreatedPrincipal) {
    const principal = created.service_principal;
    const hostname = `host.${principal.entitlement}`;
    const secretName = "lfp-pipe-client-secret";
    const config = `client_id = "${principal.client_id}"
nats_url = "${created.oauth.nats_urls[0] ?? "tls://nats.example.com:443"}"
relay_mode = "auto"
claim_ack_timeout_ms = 1500

[oauth]
token_url = "${created.oauth.token_url}"
provider_client_id = "${created.oauth.client_id}"
username = "${principal.username}"
client_secret_file = "./${secretName}"
control_plane_url = "${created.oauth.control_plane_url}"
hostname = "${hostname}"
renew_before_seconds = 60

[[backend_rules]]
pattern = "${hostname}"
backend_addr = "127.0.0.1:443"
http_backend_addr = "127.0.0.1:80"
`;
    const notes = `LFP Connect Pipe client bundle

1. Replace ${hostname} with the public route this client should claim.
2. Replace the private TLS/default and plaintext HTTP backend addresses as needed.
3. Keep ${secretName} private and beside client.toml, or update client_secret_file.
4. Run: lfp-pipe-client --config client.toml
`;
    const archive = zipSync({
      "client.toml": strToU8(config),
      [secretName]: strToU8(created.client_secret),
      "README.txt": strToU8(notes),
    });
    const blob = new Blob([archive], { type: "application/zip" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url; anchor.download = `lfp-pipe-${principal.client_id}.zip`; anchor.click();
    URL.revokeObjectURL(url);
  }

  async function logout() {
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
    window.location.assign("/");
  }

  if (!identity) return <div className="loading"><span className="spinner" /></div>;

  const oauthExample = createdPrincipal ? `[oauth]\ntoken_url = "${createdPrincipal.oauth.token_url}"\nprovider_client_id = "${createdPrincipal.oauth.client_id}"\nusername = "${createdPrincipal.service_principal.username}"\nclient_secret_file = "/run/secrets/lfp_pipe_client_secret"\ncontrol_plane_url = "${createdPrincipal.oauth.control_plane_url}"\nhostname = "host.${createdPrincipal.service_principal.entitlement}"` : "";

  return (
    <div className="shell">
      <header className="topbar"><Brand /><button className="button secondary compact" onClick={logout}><LogOut size={16} /><span>Sign out</span></button></header>
      <main className="main"><section className="dashboard">
        <div className="dashboard-header">
          <div><span className="eyebrow">Pipe</span><h1>Route console</h1></div>
          <div className="identity"><span className="avatar">{(identity.name || identity.email || "A")[0]?.toUpperCase()}</span><span className="identity-copy"><strong>{identity.name || "Authentik user"}</strong><span>{identity.email || identity.subject}</span></span></div>
        </div>

        <div className="dashboard-grid">
          <form className="section-card" onSubmit={issue}>
            <div className="section-title"><span className="icon-box"><KeyRound size={20} /></span><div><h2>Issue temporary credential</h2><p>One client and one exact route.</p></div></div>
            <div className="fields">
              <div className="field"><label htmlFor="client-name">Tunnel client</label><input id="client-name" value={clientName} onChange={(event) => setClientName(event.target.value)} placeholder="regbodesktop" autoComplete="off" required /></div>
              <div className="field"><label htmlFor="hostname">Subdomain</label><div className="input-suffix"><input id="hostname" value={hostname} onChange={(event) => setHostname(event.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))} placeholder="regbodesktop" autoComplete="off" required /><span>.{identity.required_entitlement}</span></div></div>
            </div>
            <div className="submit-row"><span className="helper">Short-lived credential</span><button className="button" disabled={!matchedEntitlement || working}>{working ? "Issuing…" : "Issue credential"}<ArrowRight size={17} /></button></div>
            {issued && <div className="token-result"><div className="token-result-head"><div><strong>{issued.hostname}</strong><br /><span>Expires {new Date(issued.expires_at).toLocaleString()}</span></div><button type="button" className="button secondary compact" onClick={() => copy("token", issued.token)}>{copied === "token" ? <Check size={15} /> : <Copy size={15} />}{copied === "token" ? "Copied" : "Copy"}</button></div><pre className="token-value">{issued.token}</pre></div>}
          </form>
          <aside className="section-card">
            <div className="section-title"><span className="icon-box"><ShieldCheck size={20} /></span><div><h2>Entitlement</h2><p>Effective direct and group grants.</p></div></div>
            {matchedEntitlement ? <div className="entitlement"><Check size={19} /><div><strong>{matchedEntitlement}</strong><span>{requestedHostname}</span></div></div> : <p className="empty-entitlement">No entitlement covers this route.</p>}
          </aside>
        </div>

        <section className="section-card principals-card">
          <div className="section-title"><span className="icon-box"><Server size={20} /></span><div><h2>Service principals</h2><p>Revocable Authentik identities that renew tunnel credentials through OAuth.</p></div></div>
          <form className="principal-form" onSubmit={createPrincipal}>
            <div className="field"><label htmlFor="principal-name">Name</label><input id="principal-name" value={principalName} onChange={(event) => setPrincipalName(event.target.value)} placeholder="desktop-speedtest" required /></div>
            <div className="field"><label htmlFor="principal-entitlement">Entitlement</label><select id="principal-entitlement" value={principalEntitlement} onChange={(event) => setPrincipalEntitlement(event.target.value)} required>{effectiveEntitlements.map((value) => <option key={value} value={value}>{value}</option>)}</select></div>
            <button className="button" disabled={working || !principalEntitlement}>Create principal<ArrowRight size={17} /></button>
          </form>

          {createdPrincipal && <div className="secret-once" role="status">
            <div><strong>Copy this secret now</strong><span>It will not be shown again.</span></div>
            <div className="credential-row"><code>{createdPrincipal.service_principal.username}</code><button className="button secondary compact" onClick={() => copy("username", createdPrincipal.service_principal.username)}>{copied === "username" ? <Check size={15} /> : <Copy size={15} />}Username</button></div>
            <div className="credential-row"><code>{createdPrincipal.client_secret}</code><button className="button secondary compact" onClick={() => copy("secret", createdPrincipal.client_secret)}>{copied === "secret" ? <Check size={15} /> : <Copy size={15} />}Secret</button></div>
            <div className="credential-row"><pre>{oauthExample}</pre><button className="button secondary compact" onClick={() => copy("config", oauthExample)}>{copied === "config" ? <Check size={15} /> : <Copy size={15} />}OAuth config</button></div>
            <button className="button download-button" onClick={() => downloadBundle(createdPrincipal)}><Download size={17} />Download client bundle</button>
          </div>}

          <div className="principal-list">
            {principalsLoading ? <p className="empty-entitlement">Loading service principals…</p> : principalsError ? <p className="error">{principalsError}</p> : principals.length === 0 ? <p className="empty-entitlement">No service principals yet.</p> : principals.map((principal) => <div className="principal-row" key={principal.id}><div><strong>{principal.username}</strong><span>{principal.client_id || "Existing client"} · {principal.entitlement}</span></div><button className={`icon-button${deleteCandidate === principal.id ? " confirm-delete" : ""}`} title={deleteCandidate === principal.id ? `Confirm deletion of ${principal.username}` : `Delete ${principal.username}`} onClick={() => deleteCandidate === principal.id ? void deletePrincipal(principal) : setDeleteCandidate(principal.id)}>{deleteCandidate === principal.id ? "Confirm" : <Trash2 size={17} />}</button></div>)}
          </div>
        </section>
        {error && <p className="error global-error" role="alert">{error}</p>}
      </section></main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<StrictMode><App /></StrictMode>);
