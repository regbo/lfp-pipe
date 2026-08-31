import { useEffect, useMemo, useState } from "react";
import { strToU8, zipSync } from "fflate";
import {
  Activity,
  Check,
  ChevronDown,
  Copy,
  Download,
  Ellipsis,
  KeyRound,
  LogOut,
  Menu as MenuIcon,
  Monitor,
  Network,
  Route as RouteIcon,
  Settings as SettingsIcon,
  ShieldCheck,
  Trash2,
  X,
} from "lucide-react";
import { Button, Group, Loader, Menu, Modal, Select, TextInput, UnstyledButton } from "@mantine/core";
import { ConfigEditor } from "./config-editor";
import {
  AccessPage,
  KeysPage,
  MachineDetail,
  MachinesPage,
  RoutesPage,
  SettingsPage,
} from "./console-pages";
import {
  api,
  configRoutes,
  normalizeEntitlement,
  type ConsolePage,
  type CreatedPrincipal,
  type CreationMode,
  type Enrollment,
  type Identity,
  type MachineFilter,
  type ManagedClient,
  type OAuthSettings,
  type ServicePrincipal,
  type TunnelToken,
} from "./console-model";
import { applyBrand, defaultBrand, type BrandSettings } from "./theme";

const navItems = [
  { page: "machines" as const, label: "Machines", icon: Monitor },
  { page: "routes" as const, label: "Routes", icon: RouteIcon },
  { page: "access" as const, label: "Access controls", icon: ShieldCheck },
];

const adminItems = [
  { page: "keys" as const, label: "Keys", icon: KeyRound },
  { page: "settings" as const, label: "Settings", icon: SettingsIcon },
];

function Brand({ settings }: { settings: BrandSettings }) {
  return <div className="brand" role="img" aria-label={settings.name}><img src={settings.logo_url} alt="" width="34" height="34" /><span>{settings.wordmark}</span></div>;
}

function downloadBlob(name: string, body: BlobPart, type: string) {
  const url = URL.createObjectURL(new Blob([body], { type }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = name;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function ManagementConsole() {
  const [brand, setBrand] = useState(defaultBrand);
  const [identity, setIdentity] = useState<Identity>();
  const [activePage, setActivePage] = useState<ConsolePage>("machines");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [selectedMachine, setSelectedMachine] = useState("");
  const [machineSearch, setMachineSearch] = useState("");
  const [routeSearch, setRouteSearch] = useState("");
  const [machineFilter, setMachineFilter] = useState<MachineFilter>("all");

  const [principals, setPrincipals] = useState<ServicePrincipal[]>([]);
  const [managedClients, setManagedClients] = useState<ManagedClient[]>([]);
  const [enrollments, setEnrollments] = useState<Enrollment[]>([]);
  const [configDocuments, setConfigDocuments] = useState<Record<number, string>>({});
  const [principalsLoading, setPrincipalsLoading] = useState(true);
  const [devicesLoading, setDevicesLoading] = useState(true);
  const [principalsError, setPrincipalsError] = useState("");
  const [devicesError, setDevicesError] = useState("");
  const [error, setError] = useState("");

  const [creationMode, setCreationMode] = useState<CreationMode>(null);
  const [principalName, setPrincipalName] = useState("");
  const [principalEntitlement, setPrincipalEntitlement] = useState("");
  const [creatingPrincipal, setCreatingPrincipal] = useState(false);
  const [createdPrincipal, setCreatedPrincipal] = useState<CreatedPrincipal | null>(null);
  const [hostname, setHostname] = useState("");
  const [clientName, setClientName] = useState("");
  const [issued, setIssued] = useState<TunnelToken | null>(null);
  const [working, setWorking] = useState(false);
  const [copied, setCopied] = useState("");

  const [selectedPrincipals, setSelectedPrincipals] = useState<number[]>([]);
  const [deleteCandidate, setDeleteCandidate] = useState<ServicePrincipal | null>(null);
  const [deletingPrincipal, setDeletingPrincipal] = useState(false);
  const [editingPrincipal, setEditingPrincipal] = useState<ServicePrincipal | null>(null);
  const [loadingConfigFor, setLoadingConfigFor] = useState("");
  const [centralConfig, setCentralConfig] = useState("");
  const [savedConfig, setSavedConfig] = useState("");
  const [configSaving, setConfigSaving] = useState(false);
  const [discardConfigOpen, setDiscardConfigOpen] = useState(false);
  const [routeMachine, setRouteMachine] = useState("");
  const [routeMachineOpen, setRouteMachineOpen] = useState(false);

  const effectiveEntitlements = useMemo(
    () => Array.from(new Set((identity?.entitlements ?? []).map(normalizeEntitlement))).sort(),
    [identity],
  );
  const managedUsernames = useMemo(() => new Set(managedClients.map((client) => client.username)), [managedClients]);
  const automationPrincipals = useMemo(
    () => principals.filter((principal) => !managedUsernames.has(principal.username)),
    [managedUsernames, principals],
  );
  const principalByUsername = useMemo(
    () => new Map(principals.map((principal) => [principal.username, principal])),
    [principals],
  );
  const routes = useMemo(
    () => principals.flatMap((principal) => configRoutes(principal, configDocuments[principal.id] ?? "")),
    [configDocuments, principals],
  );
  const routesByUsername = useMemo(() => {
    const grouped = new Map<string, typeof routes>();
    for (const route of routes) grouped.set(route.principal.username, [...(grouped.get(route.principal.username) ?? []), route]);
    return grouped;
  }, [routes]);
  const selectedClient = managedClients.find((client) => client.username === selectedMachine);
  const configDirty = editingPrincipal !== null && centralConfig !== savedConfig;
  const requestedHostname = hostname && principalEntitlement ? `${hostname}.${principalEntitlement}` : "";
  const matchedEntitlement = useMemo(() => {
    if (!requestedHostname) return "";
    return effectiveEntitlements
      .filter((value) => requestedHostname === value || requestedHostname.endsWith(`.${value}`))
      .sort((left, right) => right.length - left.length)[0] ?? "";
  }, [effectiveEntitlements, requestedHostname]);

  async function loadConfigCatalog(items: ServicePrincipal[]) {
    const results = await Promise.allSettled(items.map(async (principal) => ({
      id: principal.id,
      value: await api<{ config_toml: string }>(`/api/service-principals/${principal.id}/config`),
    })));
    setConfigDocuments(Object.fromEntries(results.flatMap((result) => result.status === "fulfilled" ? [[result.value.id, result.value.value.config_toml]] : [])));
  }

  async function loadPrincipals() {
    setPrincipalsLoading(true);
    setPrincipalsError("");
    try {
      const value = await api<{ service_principals: ServicePrincipal[] }>("/api/service-principals");
      setPrincipals(value.service_principals);
      void loadConfigCatalog(value.service_principals);
    } catch (cause) {
      setPrincipalsError(cause instanceof Error ? cause.message : "Keys could not be loaded.");
    } finally {
      setPrincipalsLoading(false);
    }
  }

  async function loadDevices() {
    try {
      const [clients, pending] = await Promise.all([
        api<{ managed_clients: ManagedClient[] }>("/api/managed-clients"),
        api<{ enrollments: Enrollment[] }>("/api/enrollments"),
      ]);
      setManagedClients(clients.managed_clients);
      setEnrollments(pending.enrollments);
      setDevicesError("");
    } catch (cause) {
      setDevicesError(cause instanceof Error ? cause.message : "Machines could not be loaded.");
    } finally {
      setDevicesLoading(false);
    }
  }

  useEffect(() => {
    fetch("/api/branding", { credentials: "same-origin" })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error("branding unavailable")))
      .then((settings: BrandSettings) => {
        const resolved = { ...defaultBrand, ...settings };
        applyBrand(resolved);
        setBrand(resolved);
      })
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

  useEffect(() => {
    const events = new EventSource("/api/managed-client-events", { withCredentials: true });
    const updatePresence = (event: Event) => {
      try {
        const payload = JSON.parse((event as MessageEvent<string>).data) as { managed_clients: ManagedClient[] };
        setManagedClients(payload.managed_clients);
        setDevicesError("");
      } catch {
        // Polling remains active as a fallback if a presence event is malformed.
      }
    };
    events.addEventListener("presence", updatePresence);
    return () => {
      events.removeEventListener("presence", updatePresence);
      events.close();
    };
  }, []);

  function navigate(page: ConsolePage) {
    setActivePage(page);
    setSelectedMachine("");
    setSidebarOpen(false);
  }

  async function editConfig(principal: ServicePrincipal) {
    setError("");
    setLoadingConfigFor(principal.username);
    try {
      const known = configDocuments[principal.id];
      const config = known ?? (await api<{ config_toml: string }>(`/api/service-principals/${principal.id}/config`)).config_toml;
      setCentralConfig(config);
      setSavedConfig(config);
      setEditingPrincipal(principal);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Configuration could not be loaded.");
    } finally {
      setLoadingConfigFor("");
    }
  }

  async function saveConfig() {
    if (!editingPrincipal || !configDirty) return;
    setConfigSaving(true);
    setError("");
    try {
      await api(`/api/service-principals/${editingPrincipal.id}/config`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ config_toml: centralConfig }),
      });
      setSavedConfig(centralConfig);
      setConfigDocuments((current) => ({ ...current, [editingPrincipal.id]: centralConfig }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Configuration could not be saved.");
    } finally {
      setConfigSaving(false);
    }
  }

  function requestCloseConfig() {
    if (configSaving) return;
    if (configDirty) {
      setDiscardConfigOpen(true);
      return;
    }
    setEditingPrincipal(null);
  }

  function discardConfigChanges() {
    setCentralConfig(savedConfig);
    setDiscardConfigOpen(false);
    setEditingPrincipal(null);
  }

  async function createPrincipal(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setCreatedPrincipal(null);
    setCreatingPrincipal(true);
    try {
      const created = await api<CreatedPrincipal>("/api/service-principals", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: principalName, entitlement: principalEntitlement }),
      });
      setCreatedPrincipal(created);
      setPrincipalName("");
      setCreationMode(null);
      await loadPrincipals();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Key creation failed.");
    } finally {
      setCreatingPrincipal(false);
    }
  }

  async function issue(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setIssued(null);
    setWorking(true);
    try {
      setIssued(await api<TunnelToken>("/api/tunnel-tokens", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostname: requestedHostname, client_name: clientName }),
      }));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Temporary key issuance failed.");
    } finally {
      setWorking(false);
    }
  }

  async function claimEnrollment(enrollment: Enrollment) {
    setError("");
    try {
      const claimed = await api<{ service_principal: ServicePrincipal }>(`/api/enrollments/${enrollment.code}/claim`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ entitlement: principalEntitlement }),
      });
      setEnrollments((current) => current.filter((candidate) => candidate.code !== enrollment.code));
      await Promise.all([loadPrincipals(), loadDevices()]);
      await editConfig(claimed.service_principal);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Machine approval failed.");
    }
  }

  async function deletePrincipal() {
    if (!deleteCandidate) return;
    setDeletingPrincipal(true);
    setError("");
    try {
      await api<void>(`/api/service-principals/${deleteCandidate.id}`, { method: "DELETE" });
      setSelectedPrincipals((current) => current.filter((id) => id !== deleteCandidate.id));
      if (selectedMachine === deleteCandidate.username) setSelectedMachine("");
      setDeleteCandidate(null);
      await Promise.all([loadPrincipals(), loadDevices()]);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Removal failed.");
    } finally {
      setDeletingPrincipal(false);
    }
  }

  async function copy(label: string, value: string) {
    await navigator.clipboard.writeText(value);
    setCopied(label);
    window.setTimeout(() => setCopied(""), 1800);
  }

  function togglePrincipal(id: number) {
    setSelectedPrincipals((current) => current.includes(id) ? current.filter((value) => value !== id) : [...current, id]);
  }

  function exportCurrentConfig() {
    if (!editingPrincipal) return;
    downloadBlob(`${editingPrincipal.client_id}.toml`, centralConfig, "application/toml");
  }

  async function downloadSelectedConfigs() {
    const selected = principals.filter((principal) => selectedPrincipals.includes(principal.id));
    const documents = await Promise.all(selected.map(async (principal) => ({
      principal,
      config: configDocuments[principal.id] ?? (await api<{ config_toml: string }>(`/api/service-principals/${principal.id}/config`)).config_toml,
    })));
    downloadBlob("lfp-pipe-selected-configs.zip", zipSync(Object.fromEntries(documents.map(({ principal, config }) => [`${principal.client_id || principal.username}.toml`, strToU8(config)]))), "application/zip");
  }

  function downloadBundle(created: CreatedPrincipal) {
    const principal = created.service_principal;
    const routeHostname = `host.${principal.entitlement}`;
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
hostname = "${routeHostname}"
renew_before_seconds = 60

[[backend_rules]]
pattern = "${routeHostname}"
backend_addr = "127.0.0.1:443"
http_backend_addr = ":80"
`;
    const notes = `LFP Connect Pipe client bundle\n\n1. Replace ${routeHostname} with the public route this client should claim.\n2. Backends accept a bare port, :port for localhost, or host:port.\n3. Keep ${secretName} private and beside client.toml.\n4. Run: lfp-pipe-client --config client.toml\n`;
    downloadBlob(`lfp-pipe-${principal.client_id}.zip`, zipSync({ "client.toml": strToU8(config), [secretName]: strToU8(created.client_secret), "README.txt": strToU8(notes) }), "application/zip");
  }

  async function logout() {
    await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
    window.location.assign("/");
  }

  if (!identity) return <div className="loading" role="status" aria-label="Loading management console"><Loader /></div>;

  const openCreation = (mode: Exclude<CreationMode, null>) => {
    setIssued(null);
    setCreationMode(mode);
  };
  const openMachine = (username: string) => {
    setSelectedMachine(username);
    setActivePage("machines");
  };

  return <div className="console-shell">
    <a className="skip-link" href="#main-content">Skip to content</a>
    <button className={`sidebar-backdrop${sidebarOpen ? " is-open" : ""}`} type="button" aria-label="Close navigation" onClick={() => setSidebarOpen(false)} />
    <aside className={`sidebar${sidebarOpen ? " is-open" : ""}`} aria-label="Primary">
      <div className="sidebar-brand-row"><Brand settings={brand} /><button className="mobile-close" type="button" aria-label="Close navigation" onClick={() => setSidebarOpen(false)}><X size={20} /></button></div>
      <div className="network-identity"><span className="network-icon" aria-hidden="true"><Network size={16} /></span><span><strong>Pipe network</strong><small>{identity.required_entitlement}</small></span></div>
      <nav className="sidebar-nav">
        <span className="nav-label">Network</span>
        {navItems.map(({ page, label, icon: Icon }) => <button key={page} type="button" className="nav-item" aria-current={activePage === page && !selectedMachine ? "page" : undefined} onClick={() => navigate(page)}><Icon size={16} aria-hidden="true" /><span>{label}</span></button>)}
        <span className="nav-label nav-label-spaced">Administration</span>
        {adminItems.map(({ page, label, icon: Icon }) => <button key={page} type="button" className="nav-item" aria-current={activePage === page ? "page" : undefined} onClick={() => navigate(page)}><Icon size={16} aria-hidden="true" /><span>{label}</span></button>)}
      </nav>
      <div className="sidebar-footer">
        <Menu position="top-start" width={224} shadow="md"><Menu.Target><UnstyledButton className="account-menu"><span className="avatar">{(identity.name || identity.email || "A")[0]?.toUpperCase()}</span><span className="identity-copy"><strong>{identity.name || "Authentik user"}</strong><span>{identity.email || identity.subject}</span></span><Ellipsis size={16} aria-hidden="true" /></UnstyledButton></Menu.Target><Menu.Dropdown><Menu.Item color="red" leftSection={<LogOut size={15} />} onClick={() => void logout()}>Sign out</Menu.Item></Menu.Dropdown></Menu>
      </div>
    </aside>
    <div className="mobile-header"><button type="button" aria-label="Open navigation" onClick={() => setSidebarOpen(true)}><MenuIcon size={20} /></button><Brand settings={brand} /></div>

    <main className="console-main" id="main-content">
      {activePage === "machines" && selectedClient ? <MachineDetail client={selectedClient} principal={principalByUsername.get(selectedClient.username)} routes={routesByUsername.get(selectedClient.username) ?? []} identity={identity} loading={loadingConfigFor === selectedClient.username} onBack={() => setSelectedMachine("")} onEdit={(principal) => void editConfig(principal)} onDelete={setDeleteCandidate} /> : null}
      {activePage === "machines" && !selectedClient ? <MachinesPage clients={managedClients} enrollments={enrollments} principals={principalByUsername} routes={routesByUsername} loading={devicesLoading} error={devicesError} search={machineSearch} filter={machineFilter} selected={selectedPrincipals} onSearch={setMachineSearch} onFilter={setMachineFilter} onOpen={openMachine} onEdit={(principal) => void editConfig(principal)} onDelete={setDeleteCandidate} onApprove={(enrollment) => void claimEnrollment(enrollment)} onToggle={togglePrincipal} onCreate={openCreation} onExport={() => void downloadSelectedConfigs()} /> : null}
      {activePage === "routes" ? <RoutesPage routes={routes} search={routeSearch} onSearch={setRouteSearch} onEdit={(principal) => void editConfig(principal)} onAdd={() => setRouteMachineOpen(true)} /> : null}
      {activePage === "access" ? <AccessPage routes={routes} onEdit={(principal) => void editConfig(principal)} /> : null}
      {activePage === "keys" ? <KeysPage principals={automationPrincipals} loading={principalsLoading} error={principalsError} selected={selectedPrincipals} onToggle={togglePrincipal} onCreate={openCreation} onEdit={(principal) => void editConfig(principal)} onDelete={setDeleteCandidate} onExport={() => void downloadSelectedConfigs()} /> : null}
      {activePage === "settings" ? <SettingsPage identity={identity} entitlements={effectiveEntitlements} onMachines={() => navigate("machines")} /> : null}
      {error ? <p className="global-error" role="alert">{error}</p> : null}
    </main>

    <Modal opened={editingPrincipal !== null} onClose={requestCloseConfig} title={editingPrincipal ? `${editingPrincipal.name || editingPrincipal.client_id} configuration` : "Client configuration"} size="min(1120px, calc(100vw - 2rem))" centered closeButtonProps={{ disabled: configSaving, "aria-label": "Close configuration" }} classNames={{ content: "manage-config-content", body: "manage-config-body", header: "manage-config-header" }}>
      {editingPrincipal ? <div className="manage-config-editor"><ConfigEditor key={editingPrincipal.id} toml={centralConfig} onChange={setCentralConfig} /><div className="config-footer"><span className={`save-state${configDirty ? " is-dirty" : ""}`}><span />{configSaving ? "Saving…" : configDirty ? "Unsaved changes" : "Saved"}</span><div className="config-footer-actions"><Button variant="default" leftSection={<Download size={15} />} onClick={exportCurrentConfig}>Export</Button><Button variant="default" disabled={configSaving} onClick={requestCloseConfig}>Close</Button><Button loading={configSaving} disabled={!configDirty} onClick={() => void saveConfig()}>Save changes</Button></div></div></div> : null}
    </Modal>
    <Modal opened={discardConfigOpen} onClose={() => setDiscardConfigOpen(false)} title="Discard unsaved changes?" size="sm" centered><p className="modal-copy">This client configuration has changes that have not been saved.</p><Group justify="flex-end"><Button variant="default" onClick={() => setDiscardConfigOpen(false)}>Keep editing</Button><Button color="red" onClick={discardConfigChanges}>Discard changes</Button></Group></Modal>
    <Modal opened={deleteCandidate !== null} onClose={() => setDeleteCandidate(null)} title={`Remove ${deleteCandidate?.name || deleteCandidate?.client_id || "client"}?`} size="sm" centered><p className="modal-copy">This revokes its credentials and removes its centrally managed configuration.</p><Group justify="flex-end"><Button variant="default" onClick={() => setDeleteCandidate(null)}>Cancel</Button><Button color="red" loading={deletingPrincipal} onClick={() => void deletePrincipal()}>Remove</Button></Group></Modal>

    <Modal opened={creationMode !== null} onClose={() => setCreationMode(null)} title={creationMode === "temporary" ? "Generate temporary key" : "Generate machine key"} size="md" centered>
      {creationMode === "access" ? <form className="stack-form" onSubmit={createPrincipal} aria-busy={creatingPrincipal}><TextInput label="Client name" value={principalName} onChange={(event) => setPrincipalName(event.currentTarget.value)} placeholder="build-server" required /><Select label="Authorized domain" value={principalEntitlement} onChange={(value) => setPrincipalEntitlement(value ?? "")} data={effectiveEntitlements} required /><p className="field-note">The generated secret is shown once. The client can register routes under this domain.</p><Group justify="flex-end"><Button variant="default" type="button" onClick={() => setCreationMode(null)}>Cancel</Button><Button type="submit" loading={creatingPrincipal} disabled={!principalEntitlement}>Generate key</Button></Group></form> : null}
      {creationMode === "temporary" ? <form className="stack-form" onSubmit={issue}><TextInput label="Client name" value={clientName} onChange={(event) => setClientName(event.currentTarget.value)} placeholder="local-test" required /><Select label="Authorized domain" value={principalEntitlement} onChange={(value) => setPrincipalEntitlement(value ?? "")} data={effectiveEntitlements} required /><TextInput label="Subdomain" value={hostname} onChange={(event) => setHostname(event.currentTarget.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))} rightSection={<span className="input-domain">.{principalEntitlement}</span>} rightSectionWidth="auto" required /><p className="field-note">{matchedEntitlement ? `The key will register ${requestedHostname}.` : "Select an authorized domain and enter a subdomain."}</p>{issued ? <div className="issued-token"><code>{issued.token}</code><Button variant="default" leftSection={copied === "token" ? <Check size={15} /> : <Copy size={15} />} onClick={() => void copy("token", issued.token)}>Copy key</Button></div> : null}<Group justify="flex-end"><Button variant="default" type="button" onClick={() => setCreationMode(null)}>Close</Button><Button type="submit" loading={working} disabled={!matchedEntitlement}>Generate key</Button></Group></form> : null}
    </Modal>

    <Modal opened={createdPrincipal !== null} onClose={() => setCreatedPrincipal(null)} title="Machine key created" size="lg" centered closeOnClickOutside={false}>
      {createdPrincipal ? <div className="secret-once"><div className="notice"><KeyRound size={18} aria-hidden="true" /><span><strong>Copy this secret now</strong><small>It will not be shown again.</small></span></div><SecretRow label="Username" value={createdPrincipal.service_principal.username} copied={copied === "username"} onCopy={() => void copy("username", createdPrincipal.service_principal.username)} /><SecretRow label="Client secret" value={createdPrincipal.client_secret} copied={copied === "secret"} onCopy={() => void copy("secret", createdPrincipal.client_secret)} /><Group justify="space-between"><Button variant="default" leftSection={<Download size={15} />} onClick={() => downloadBundle(createdPrincipal)}>Download client bundle</Button><Button onClick={() => setCreatedPrincipal(null)}>Done</Button></Group></div> : null}
    </Modal>

    <Modal opened={routeMachineOpen} onClose={() => setRouteMachineOpen(false)} title="Add route" size="sm" centered><div className="stack-form"><Select label="Machine" placeholder="Select a machine" searchable value={routeMachine} onChange={(value) => setRouteMachine(value ?? "")} data={principals.filter((principal) => managedUsernames.has(principal.username)).map((principal) => ({ value: String(principal.id), label: principal.name || principal.client_id }))} /><p className="field-note">Routes are owned by a machine. Select one to open its route configuration.</p><Group justify="flex-end"><Button variant="default" onClick={() => setRouteMachineOpen(false)}>Cancel</Button><Button disabled={!routeMachine} onClick={() => { const principal = principals.find((item) => String(item.id) === routeMachine); if (principal) void editConfig(principal); setRouteMachineOpen(false); }}>Configure routes</Button></Group></div></Modal>
  </div>;
}

function SecretRow({ label, value, copied, onCopy }: { label: string; value: string; copied: boolean; onCopy: () => void }) {
  return <div className="secret-row"><label>{label}</label><div><code>{value}</code><Button variant="default" leftSection={copied ? <Check size={15} /> : <Copy size={15} />} onClick={onCopy}>{copied ? "Copied" : "Copy"}</Button></div></div>;
}
