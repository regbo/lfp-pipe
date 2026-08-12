import { StrictMode, useEffect, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { strToU8, zipSync } from "fflate";
import { ArrowRight, Check, Copy, Download, KeyRound, LoaderCircle, LogOut, Server, ShieldCheck, Trash2 } from "lucide-react";
import { Badge, Button, Checkbox, Divider, Group, Input, MantineProvider, Select, TextInput, createTheme } from "@mantine/core";
import { ConfigEditor } from "./config-editor";
import "@mantine/core/styles.css";
import "./styles.css";

const theme = createTheme({
  primaryColor: "coral",
  defaultRadius: "md",
  fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif",
  colors: { coral: ["#fff1ef", "#ffe2de", "#ffc4bd", "#ffa59b", "#ff877b", "#ff6f61", "#e85c50", "#c9473d", "#a93730", "#872b26"] },
  components: {
    TextInput: TextInput.extend({ defaultProps: { size: "xs" } }),
    Select: Select.extend({ defaultProps: { size: "xs", allowDeselect: false } }),
    Button: Button.extend({ defaultProps: { size: "xs" } }),
    InputWrapper: Input.Wrapper.extend({ defaultProps: { inputWrapperOrder: ["label", "input", "description", "error"] } }),
  },
});

type BrandSettings = {
  name: string; logo_url: string; favicon_url: string; color: string;
  color_strong: string; ink: string;
};

const defaultBrand: BrandSettings = {
  name: "LFP Connect", logo_url: "/assets/lfp-connect-auto.svg",
  favicon_url: "/assets/lfp-favicon.svg", color: "#ff6f61",
  color_strong: "#e85c50", ink: "#0b1426",
};

type Identity = {
  subject: string; name: string; email: string; entitlements: string[];
  required_entitlement: string; route_pattern: string; control_plane_url: string;
};

type TunnelToken = {
  token: string; expires_at: string; hostname: string; client_id: string;
  request_subject: string; nats_urls: string[];
};

type ServicePrincipal = { id: number; username: string; name: string; client_id: string; entitlement: string };
type OAuthSettings = { token_url: string; client_id: string; control_plane_url: string; scopes: string[]; nats_urls: string[] };
type CreatedPrincipal = { service_principal: ServicePrincipal; client_secret: string; oauth: OAuthSettings };
type ManagedClient = { username: string; name: string; version: string; platform: string; last_seen: string; online?: boolean };
type Enrollment = { code: string; device_id: string; name: string; platform: string; version: string; expires_at: string };

function applyBrand(brand: BrandSettings) {
  const root = document.documentElement.style;
  root.setProperty("--color-brand", brand.color);
  root.setProperty("--color-brand-strong", brand.color_strong);
  root.setProperty("--color-brand-ink", brand.ink);
  document.title = `${brand.name} Pipe`;
  const favicon = document.querySelector<HTMLLinkElement>('link[rel="icon"]');
  if (favicon) favicon.href = brand.favicon_url;
}

function Brand({ settings }: { settings: BrandSettings }) {
  return <img className="brand" src={settings.logo_url} alt={settings.name} />;
}
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
  const [brand, setBrand] = useState(defaultBrand);
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
  const [creatingPrincipal, setCreatingPrincipal] = useState(false);
  const [deletingPrincipal, setDeletingPrincipal] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [working, setWorking] = useState(false);
  const [copied, setCopied] = useState("");
  const [selectedPrincipals, setSelectedPrincipals] = useState<number[]>([]);
  const [editingPrincipal, setEditingPrincipal] = useState<ServicePrincipal | null>(null);
  const [centralConfig, setCentralConfig] = useState("");
  const [configSaving, setConfigSaving] = useState(false);
  const [saveState, setSaveState] = useState("Saved");
  const [managedClients, setManagedClients] = useState<ManagedClient[]>([]);
  const [enrollments, setEnrollments] = useState<Enrollment[]>([]);
  const [showAdvancedTools, setShowAdvancedTools] = useState(false);
  const skipNextConfigSave = useRef(false);

  const effectiveEntitlements = useMemo(() =>
    Array.from(new Set((identity?.entitlements ?? []).map(normalizeEntitlement))).sort(), [identity]);
  const automationPrincipals = useMemo(() => {
    const managedUsernames = new Set(managedClients.map((client) => client.username));
    return principals.filter((principal) => !managedUsernames.has(principal.username));
  }, [managedClients, principals]);

  async function loadPrincipals() {
    setPrincipalsLoading(true); setPrincipalsError("");
    try {
      const value = await api<{ service_principals: ServicePrincipal[] }>("/api/service-principals");
      setPrincipals(value.service_principals);
    } catch (cause) {
      setPrincipalsError(cause instanceof Error ? cause.message : "Service principals could not be loaded.");
    } finally { setPrincipalsLoading(false); }
  }

  async function loadDevices() {
    const [clients, pending] = await Promise.all([
      api<{ managed_clients: ManagedClient[] }>("/api/managed-clients"),
      api<{ enrollments: Enrollment[] }>("/api/enrollments"),
    ]);
    setManagedClients(clients.managed_clients); setEnrollments(pending.enrollments);
  }

  useEffect(() => {
    fetch("/api/branding", { credentials: "same-origin" })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("branding unavailable")))
      .then((settings: BrandSettings) => { applyBrand(settings); setBrand(settings); })
      .catch(() => applyBrand(defaultBrand));
    api<Identity>("/api/me")
      .then((value) => {
        setIdentity(value);
        const normalized = value.entitlements.map(normalizeEntitlement);
        setPrincipalEntitlement(normalized.includes(value.required_entitlement) ? value.required_entitlement : normalized[0] ?? "");
      })
      .catch(() => undefined);
    void loadPrincipals();
    void loadDevices();
    const deviceTimer = window.setInterval(() => void loadDevices(), 15000);
    return () => window.clearInterval(deviceTimer);
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
    event.preventDefault(); setError(""); setCreatedPrincipal(null); setCreatingPrincipal(true);
    try {
      const created = await api<CreatedPrincipal>("/api/service-principals", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: principalName, entitlement: principalEntitlement }),
      });
      setCreatedPrincipal(created);
      setPrincipalName("");
      await loadPrincipals();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Service principal creation failed."); }
    finally { setCreatingPrincipal(false); }
  }

  async function deletePrincipal(principal: ServicePrincipal) {
    setError(""); setDeletingPrincipal(principal.id);
    try {
      await api<void>(`/api/service-principals/${principal.id}`, { method: "DELETE" });
      if (createdPrincipal?.service_principal.id === principal.id) setCreatedPrincipal(null);
      setDeleteCandidate(null);
      await loadPrincipals();
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Deletion failed."); }
    finally { setDeletingPrincipal(null); }
  }

  async function copy(label: string, value: string) {
    await navigator.clipboard.writeText(value); setCopied(label);
    window.setTimeout(() => setCopied(""), 1800);
  }

  function togglePrincipal(id: number) {
    setSelectedPrincipals((current) => current.includes(id) ? current.filter((value) => value !== id) : [...current, id]);
  }

  async function editConfig(principal: ServicePrincipal) {
    setError("");
    try {
      const response = await api<{ config_toml: string }>(`/api/service-principals/${principal.id}/config`);
      skipNextConfigSave.current = true;
      setCentralConfig(response.config_toml);
      setEditingPrincipal(principal);
      setSaveState("Saved");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Configuration could not be loaded."); }
  }

  async function saveConfig() {
    if (!editingPrincipal) return;
    setConfigSaving(true); setSaveState("Saving…"); setError("");
    try {
      await api(`/api/service-principals/${editingPrincipal.id}/config`, {
        method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ config_toml: centralConfig }),
      });
      setSaveState("Saved");
    } catch (cause) { setSaveState("Save failed"); setError(cause instanceof Error ? cause.message : "Configuration could not be saved."); }
    finally { setConfigSaving(false); }
  }

  useEffect(() => {
    if (!editingPrincipal || !centralConfig) return;
    if (skipNextConfigSave.current) { skipNextConfigSave.current = false; return; }
    setSaveState("Unsaved changes");
    const timer = window.setTimeout(() => void saveConfig(), 900);
    return () => window.clearTimeout(timer);
  }, [centralConfig]);

  async function claimEnrollment(enrollment: Enrollment) {
    setError("");
    const claimed = await api<{ service_principal: ServicePrincipal }>(`/api/enrollments/${enrollment.code}/claim`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ entitlement: principalEntitlement }) });
    const principal = claimed.service_principal;
    setEnrollments((current) => current.filter((candidate) => candidate.code !== enrollment.code));
    setPrincipals((current) => current.some((candidate) => candidate.id === principal.id) ? current : [...current, principal]);
    setManagedClients((current) => current.some((client) => client.username === principal.username) ? current : [...current, { username: principal.username, name: enrollment.name, version: enrollment.version, platform: enrollment.platform, last_seen: new Date().toISOString(), online: false }]);
    await editConfig(principal);
  }

  async function manageClient(client: ManagedClient) {
    const principal = principals.find((candidate) => candidate.username === client.username);
    if (!principal) { setError("This client is connected but its managed configuration is not available yet."); return; }
    await editConfig(principal);
  }

  function exportCurrentConfig() {
    if (!editingPrincipal) return;
    const url = URL.createObjectURL(new Blob([centralConfig], { type: "application/toml" }));
    const anchor = document.createElement("a"); anchor.href = url; anchor.download = `${editingPrincipal.client_id}.toml`; anchor.click(); URL.revokeObjectURL(url);
  }

  async function downloadSelectedConfigs() {
    const selected = principals.filter((principal) => selectedPrincipals.includes(principal.id));
    const documents = await Promise.all(selected.map(async (principal) => ({
      principal,
      response: await api<{ config_toml: string }>(`/api/service-principals/${principal.id}/config`),
    })));
    const archive = zipSync(Object.fromEntries(documents.map(({ principal, response }) => [
      `${principal.client_id || principal.username}.toml`, strToU8(response.config_toml),
    ])));
    const url = URL.createObjectURL(new Blob([archive], { type: "application/zip" }));
    const anchor = document.createElement("a"); anchor.href = url; anchor.download = "lfp-pipe-selected-configs.zip"; anchor.click(); URL.revokeObjectURL(url);
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
      <header className="topbar"><Brand settings={brand} /><Button variant="subtle" leftSection={<LogOut size={16} />} onClick={logout}><span>Sign out</span></Button></header>
      <main className="main"><section className="dashboard">
        <div className="dashboard-header compact-header">
          <div><span className="eyebrow">LFP Pipe</span><h1>Connections</h1></div>
          <div className="identity"><span className="avatar">{(identity.name || identity.email || "A")[0]?.toUpperCase()}</span><span className="identity-copy"><strong>{identity.name || "Authentik user"}</strong><span>{identity.email || identity.subject}</span></span></div>
        </div>

        <div className="console-grid">
          <section className="section-card compact-card"><div className="compact-title"><div><h2>Managed clients</h2><p>Install, approve, then manage routes here.</p></div><Badge size="md" variant="light">{managedClients.filter((client) => client.online !== false).length} online</Badge></div>
          <div className="device-panel flat-panel">
            {enrollments.map((enrollment) => <div className="principal-row" key={enrollment.code}><div><strong>{enrollment.name || enrollment.device_id}</strong><span>{enrollment.platform} · {enrollment.version} · code {enrollment.code}</span></div><Button onClick={() => void claimEnrollment(enrollment)}>Approve and manage</Button></div>)}
            {managedClients.map((client) => { const isManaging = editingPrincipal?.username === client.username; return <div className="managed-client" key={client.username}><div className="principal-row"><div><strong>{client.name || client.username}</strong><span>{[client.platform, client.version].filter(Boolean).join(" · ") || "Waiting for client"}</span></div><Group gap="xs"><Badge size="md" variant="light" color={client.online !== false ? "green" : "gray"}><span className="status-content"><span className="status-dot" aria-hidden="true" />{client.online !== false ? "Online" : "Offline"}</span></Badge><Button className="manage-button" variant={isManaging ? "filled" : "light"} onClick={() => void manageClient(client)}>{isManaging ? "Managing" : "Manage"}</Button></Group></div>
              {isManaging ? <div className="client-config-panel"><div><strong>{client.name || editingPrincipal.client_id}</strong><span>Changes save automatically and are pushed to this client.</span></div><ConfigEditor key={editingPrincipal.id} toml={centralConfig} onChange={setCentralConfig} /><Group className="config-footer" justify="space-between" align="center"><Badge color={saveState === "Saved" ? "green" : "gray"} variant="light">{saveState}</Badge><Button.Group><Button variant="light" leftSection={<Download size={16} />} onClick={exportCurrentConfig}>Export config</Button><Button variant="default" onClick={() => setEditingPrincipal(null)}>Close</Button></Button.Group></Group></div> : null}
            </div>; })}
            {managedClients.length === 0 && enrollments.length === 0 ? <p className="empty-entitlement">No desktop clients connected yet. Install and start the client to enroll it.</p> : null}
          </div>
          </section>

          <section className="section-card compact-card"><div className="compact-title"><div><h2>Automation access</h2><p>Machine credentials for agents, servers, and scripts.</p></div><Button variant="subtle" onClick={() => setShowAdvancedTools((value) => !value)}>{showAdvancedTools ? "Cancel" : "New credential"}</Button></div>
          {showAdvancedTools ? <form className="compact-form" onSubmit={createPrincipal} aria-busy={creatingPrincipal}><TextInput aria-label="Client name" value={principalName} onChange={(event) => setPrincipalName(event.currentTarget.value)} placeholder="Client name" disabled={creatingPrincipal} required /><Select aria-label="Entitlement" value={principalEntitlement} onChange={(value) => setPrincipalEntitlement(value ?? "")} data={effectiveEntitlements} disabled={creatingPrincipal} required /><Button disabled={creatingPrincipal || !principalEntitlement}>{creatingPrincipal ? "Creating…" : "Create"}</Button></form> : null}

          {createdPrincipal && <div className="secret-once" role="status">
            <div><strong>Copy this secret now</strong><span>It will not be shown again.</span></div>
            <div className="credential-row"><code>{createdPrincipal.service_principal.username}</code><Button variant="light" leftSection={copied === "username" ? <Check size={15} /> : <Copy size={15} />} onClick={() => copy("username", createdPrincipal.service_principal.username)}>Username</Button></div>
            <div className="credential-row"><code>{createdPrincipal.client_secret}</code><Button variant="light" leftSection={copied === "secret" ? <Check size={15} /> : <Copy size={15} />} onClick={() => copy("secret", createdPrincipal.client_secret)}>Secret</Button></div>
            <div className="credential-row"><pre>{oauthExample}</pre><Button variant="light" leftSection={copied === "config" ? <Check size={15} /> : <Copy size={15} />} onClick={() => copy("config", oauthExample)}>OAuth config</Button></div>
            <Button className="download-button" leftSection={<Download size={17} />} onClick={() => downloadBundle(createdPrincipal)}>Download client bundle</Button>
          </div>}

          <div className="principal-list">
            {principalsLoading ? <p className="empty-entitlement">Loading automation credentials…</p> : principalsError ? <p className="error">{principalsError}</p> : automationPrincipals.length === 0 ? <p className="empty-entitlement">No separate automation credentials. Managed device identities appear on the left.</p> : automationPrincipals.map((principal) => { const deleting = deletingPrincipal === principal.id; const confirming = deleteCandidate === principal.id; return <div className="principal-row" key={principal.id} aria-busy={deleting}><Checkbox className="route-select" checked={selectedPrincipals.includes(principal.id)} onChange={() => togglePrincipal(principal.id)} label={<span><strong>{principal.username}</strong><span>{principal.client_id || "Machine credential"} · {principal.entitlement}</span></span>} /><Button color="red" variant={confirming ? "filled" : "subtle"} title={deleting ? `Deleting ${principal.username}` : confirming ? `Confirm deletion of ${principal.username}` : `Delete ${principal.username}`} disabled={deletingPrincipal !== null} onClick={() => confirming ? void deletePrincipal(principal) : setDeleteCandidate(principal.id)}>{deleting ? <><LoaderCircle className="button-spinner" size={15} />Deleting…</> : confirming ? "Confirm" : <Trash2 size={17} />}</Button></div>; })}
          </div>
          <div className="list-footer"><span>{selectedPrincipals.length} selected</span><Button variant="light" leftSection={<Download size={15} />} disabled={selectedPrincipals.length === 0} onClick={() => void downloadSelectedConfigs()}>Export selected</Button></div>
          <Divider label="Temporary credential" labelPosition="left" />
          <form className="temporary-credential" onSubmit={issue}><div className="compact-form"><TextInput aria-label="Tunnel client" value={clientName} onChange={(event) => setClientName(event.currentTarget.value)} placeholder="Client name" required /><TextInput aria-label="Subdomain" value={hostname} onChange={(event) => setHostname(event.currentTarget.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))} placeholder="Subdomain" required /><Button disabled={!matchedEntitlement || working}>{working ? "Issuing…" : "Issue"}</Button></div><p className="helper">{matchedEntitlement ? `Authorized under ${matchedEntitlement}` : "Enter an entitled subdomain."}</p>{issued ? <Button type="button" variant="subtle" onClick={() => copy("token", issued.token)}>Copy issued token</Button> : null}</form>
          </section>
        </div>
        {error && <p className="error global-error" role="alert">{error}</p>}
      </section></main>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(<StrictMode><MantineProvider theme={theme} defaultColorScheme="auto"><App /></MantineProvider></StrictMode>);
