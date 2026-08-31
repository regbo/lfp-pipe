import type { ReactNode } from "react";
import {
  Activity,
  ChevronDown,
  Download,
  Ellipsis,
  KeyRound,
  Monitor,
  Plus,
  Route as RouteIcon,
  Search,
  Settings,
  SlidersHorizontal,
  Trash2,
} from "lucide-react";
import { Badge, Button, Checkbox, Loader, Menu, Select, TextInput } from "@mantine/core";
import type {
  CreationMode,
  Enrollment,
  Identity,
  MachineFilter,
  ManagedClient,
  RouteSummary,
  ServicePrincipal,
} from "./console-model";
import { lastSeen } from "./console-model";

export function PageHeader({ title, description, actions }: { title: string; description: string; actions?: ReactNode }) {
  return <header className="page-header"><div><h1>{title}</h1><p>{description}</p></div>{actions ? <div className="page-actions">{actions}</div> : null}</header>;
}

export function AddMenu({ onCreate }: { onCreate: (mode: Exclude<CreationMode, null>) => void }) {
  return <Menu position="bottom-end" width={230} shadow="md">
    <Menu.Target><Button rightSection={<ChevronDown size={14} />}>Add client</Button></Menu.Target>
    <Menu.Dropdown>
      <Menu.Item leftSection={<Monitor size={16} />} onClick={() => onCreate("access")}><strong>Machine key</strong><span className="menu-description">For a managed client or server</span></Menu.Item>
      <Menu.Item leftSection={<Activity size={16} />} onClick={() => onCreate("temporary")}><strong>Temporary key</strong><span className="menu-description">For a short-lived connection</span></Menu.Item>
    </Menu.Dropdown>
  </Menu>;
}

export function Status({ client }: { client: ManagedClient }) {
  const label = !client.presence_known ? "Checking" : client.online ? "Connected" : "Offline";
  const tone = !client.presence_known ? "checking" : client.online ? "online" : "offline";
  return <span className={`status status-${tone}`}><span aria-hidden="true" />{label}</span>;
}

type MachinesPageProps = {
  clients: ManagedClient[];
  enrollments: Enrollment[];
  principals: Map<string, ServicePrincipal>;
  routes: Map<string, RouteSummary[]>;
  loading: boolean;
  error: string;
  search: string;
  filter: MachineFilter;
  selected: number[];
  onSearch: (value: string) => void;
  onFilter: (value: MachineFilter) => void;
  onOpen: (username: string) => void;
  onEdit: (principal: ServicePrincipal) => void;
  onDelete: (principal: ServicePrincipal) => void;
  onApprove: (enrollment: Enrollment) => void;
  onToggle: (id: number) => void;
  onCreate: (mode: Exclude<CreationMode, null>) => void;
  onExport: () => void;
};

export function MachinesPage(props: MachinesPageProps) {
  const query = props.search.trim().toLowerCase();
  const filtered = props.clients.filter((client) => {
    const routeNames = (props.routes.get(client.username) ?? []).map((route) => route.hostname).join(" ");
    const matchesSearch = !query || [client.name, client.username, client.platform, client.version, routeNames].join(" ").toLowerCase().includes(query);
    const matchesFilter = props.filter === "all" || (props.filter === "online" && client.online) || (props.filter === "offline" && client.presence_known && !client.online);
    return matchesSearch && matchesFilter;
  });
  const pending = props.filter === "all" || props.filter === "pending"
    ? props.enrollments.filter((item) => !query || [item.name, item.device_id, item.platform, item.version].join(" ").toLowerCase().includes(query))
    : [];
  return <>
    <PageHeader title="Machines" description="Manage clients connected to your Pipe network." actions={<AddMenu onCreate={props.onCreate} />} />
    <div className="toolbar">
      <TextInput className="search-input" aria-label="Search machines" placeholder="Search by name, platform, version, route…" leftSection={<Search size={16} />} value={props.search} onChange={(event) => props.onSearch(event.currentTarget.value)} />
      <Select className="filter-select" aria-label="Filter machines" leftSection={<SlidersHorizontal size={15} />} value={props.filter} onChange={(value) => props.onFilter((value as MachineFilter) ?? "all")} data={[{ value: "all", label: "All machines" }, { value: "online", label: "Connected" }, { value: "offline", label: "Offline" }, { value: "pending", label: "Pending approval" }]} />
      {props.selected.length > 0 ? <Button variant="default" leftSection={<Download size={15} />} onClick={props.onExport}>Export {props.selected.length}</Button> : null}
    </div>
    <div className="result-count">{filtered.length + pending.length} {(filtered.length + pending.length) === 1 ? "machine" : "machines"}</div>
    <div className="data-table-wrap">
      <table className="data-table">
        <thead><tr><th className="select-column"><span className="sr-only">Select</span></th><th>Machine</th><th>Routes</th><th>Version</th><th>Last seen</th><th className="actions-column"><span className="sr-only">Actions</span></th></tr></thead>
        <tbody>
          {pending.map((enrollment) => <tr key={enrollment.code} className="pending-row"><td /><td><div className="machine-cell"><strong>{enrollment.name || enrollment.device_id}</strong><span>{enrollment.device_id}</span><Badge size="xs" color="yellow" variant="light">Pending approval</Badge></div></td><td>—</td><td><div className="secondary-lines"><strong>{enrollment.version || "Unknown"}</strong><span>{enrollment.platform || "Unknown platform"}</span></div></td><td>Waiting</td><td><Button variant="default" onClick={() => props.onApprove(enrollment)}>Approve</Button></td></tr>)}
          {filtered.map((client) => {
            const principal = props.principals.get(client.username);
            const machineRoutes = props.routes.get(client.username) ?? [];
            return <tr key={client.username}>
              <td className="select-column">{principal ? <Checkbox aria-label={`Select ${client.name || client.username}`} checked={props.selected.includes(principal.id)} onChange={() => props.onToggle(principal.id)} /> : null}</td>
              <td><button className="cell-link machine-cell" type="button" onClick={() => props.onOpen(client.username)}><strong>{client.name || client.username}</strong><span>{client.username}</span>{!client.presence_known ? <Badge size="xs" color="yellow" variant="light">Checking</Badge> : null}</button></td>
              <td>{machineRoutes.length ? <div className="route-cell">{machineRoutes.slice(0, 2).map((route) => <code key={route.hostname}>{route.hostname}</code>)}{machineRoutes.length > 2 ? <span>+{machineRoutes.length - 2} more</span> : null}</div> : <span className="muted">—</span>}</td>
              <td><div className="secondary-lines"><strong>{client.version || "Unknown"}</strong><span>{client.platform || "Unknown platform"}</span></div></td>
              <td><Status client={client} /><time>{lastSeen(client)}</time></td>
              <td className="actions-column">{principal ? <RowMenu label={client.name || client.username} onDetails={() => props.onOpen(client.username)} onEdit={() => props.onEdit(principal)} onDelete={() => props.onDelete(principal)} /> : null}</td>
            </tr>;
          })}
        </tbody>
      </table>
      {!props.loading && !props.error && filtered.length === 0 && pending.length === 0 ? <EmptyState title="No machines found" copy={query || props.filter !== "all" ? "Try a different search or filter." : "Generate a machine key or start a client to enroll it."} /> : null}
      {props.loading ? <LoadingRow label="Loading machines…" /> : null}
      {props.error ? <p className="inline-error">{props.error}</p> : null}
    </div>
  </>;
}

type MachineDetailProps = {
  client?: ManagedClient;
  principal?: ServicePrincipal;
  identity: Identity;
  loading: boolean;
  dirty: boolean;
  saving: boolean;
  children?: ReactNode;
  onBack: () => void;
  onSave: () => void;
  onExport: () => void;
  onDelete: (principal: ServicePrincipal) => void;
};

export function MachineDetail({ client, principal, identity, loading, dirty, saving, children, onBack, onSave, onExport, onDelete }: MachineDetailProps) {
  const title = client?.name || principal?.name || principal?.client_id || client?.username || "Machine";
  const presence = !client?.presence_known ? "Checking connection" : client.online ? "Connected" : `Last seen ${lastSeen(client)}`;
  const description = client
    ? `${client.platform || "Unknown platform"} · ${client.version || "Unknown version"} · ${presence}`
    : `Client configuration · ${principal?.entitlement || identity.required_entitlement}`;
  return <>
    <div className="breadcrumbs"><button type="button" onClick={onBack}>Back</button><span>/</span><span>{title}</span></div>
    <PageHeader title={title} description={description} actions={principal ? <Menu position="bottom-end" width={210}><Menu.Target><Button variant="default" rightSection={<ChevronDown size={14} />}>More</Button></Menu.Target><Menu.Dropdown><Menu.Item leftSection={<Download size={15} />} onClick={onExport}>Export configuration</Menu.Item><Menu.Divider /><Menu.Item color="red" leftSection={<Trash2 size={15} />} onClick={() => onDelete(principal)}>Remove…</Menu.Item></Menu.Dropdown></Menu> : null} />
    <div className="machine-facts" aria-label="Machine identity">
      {client ? <div><span>Status</span><Status client={client} /></div> : null}
      <div><span>Service username</span><code>{client?.username || principal?.username || "—"}</code></div>
      <div><span>Client ID</span><code>{principal?.client_id || "—"}</code></div>
      <div><span>Authorized domain</span><code>{principal?.entitlement || "—"}</code></div>
    </div>
    <section className="configuration-page" aria-label={`${title} configuration`}>
      {loading ? <LoadingRow label="Loading configuration…" /> : children}
      {!loading && !principal ? <EmptyState title="No managed configuration" copy="This connected machine is not linked to a service principal." /> : null}
    </section>
    {principal && !loading ? <div className="config-footer config-page-footer"><span className={`save-state${dirty ? " is-dirty" : ""}`} aria-live="polite"><span />{saving ? "Saving…" : dirty ? "Unsaved changes" : "Saved"}</span><div className="config-footer-actions"><Button loading={saving} disabled={!dirty} onClick={onSave}>Save changes</Button></div></div> : null}
  </>;
}

export function RoutesPage({ routes, search, onSearch, onEdit, onAdd }: { routes: RouteSummary[]; search: string; onSearch: (value: string) => void; onEdit: (principal: ServicePrincipal) => void; onAdd: () => void }) {
  const query = search.trim().toLowerCase();
  const filtered = routes.filter((route) => !query || [route.hostname, route.backend, route.httpBackend, route.principal.name, route.principal.client_id, ...route.paths.flatMap((path) => [path.path, path.backend])].join(" ").toLowerCase().includes(query));
  return <>
    <PageHeader title="Routes" description="Manage public hostnames forwarded through your machines." actions={<Button leftSection={<Plus size={15} />} onClick={onAdd}>Add route</Button>} />
    <div className="toolbar"><TextInput className="search-input" aria-label="Search routes" placeholder="Search by hostname, machine, backend…" leftSection={<Search size={16} />} value={search} onChange={(event) => onSearch(event.currentTarget.value)} /></div>
    <div className="result-count">{filtered.length} {filtered.length === 1 ? "route" : "routes"}</div>
    <div className="data-table-wrap"><table className="data-table"><thead><tr><th>Hostname</th><th>Machine</th><th>Backend</th><th>TLS</th><th>Access</th><th className="actions-column"><span className="sr-only">Actions</span></th></tr></thead><tbody>
      {filtered.map((route, index) => {
        const protectedPaths = route.paths.filter((path) => path.protected).length;
        return <tr key={`${route.principal.id}-${route.hostname}-${index}`}><td><button className="cell-link route-name" type="button" onClick={() => onEdit(route.principal)}>{route.hostname || "Unnamed route"}</button></td><td><div className="secondary-lines"><strong>{route.principal.name || route.principal.client_id}</strong><span>{route.principal.username}</span></div></td><td><div className="secondary-lines"><code>{route.backend || "Inherited"}</code>{route.httpBackend ? <span>HTTP {route.httpBackend}</span> : null}</div></td><td>{route.tls ? "Terminated" : "Passthrough"}</td><td>{protectedPaths ? `${protectedPaths} protected ${protectedPaths === 1 ? "path" : "paths"}` : "Open"}</td><td className="actions-column"><button className="icon-action" type="button" aria-label={`Edit ${route.hostname}`} onClick={() => onEdit(route.principal)}><Ellipsis size={18} /></button></td></tr>;
      })}
    </tbody></table>{filtered.length === 0 ? <EmptyState title={query ? "No routes found" : "No routes registered"} copy={query ? "Try a different search." : "Add a public hostname to a machine configuration."} action={!query ? <Button variant="default" onClick={onAdd}>Add route</Button> : null} /> : null}</div>
  </>;
}

export function AccessPage({ routes, onEdit }: { routes: RouteSummary[]; onEdit: (principal: ServicePrincipal) => void }) {
  const policies = routes.flatMap((route) => route.paths.filter((path) => path.protected).map((path) => ({ route, path })));
  return <>
    <PageHeader title="Access controls" description="Review authentication and role requirements on public paths." />
    <div className="result-count">{policies.length} protected {policies.length === 1 ? "path" : "paths"}</div>
    <div className="data-table-wrap"><table className="data-table"><thead><tr><th>Route</th><th>Path</th><th>Authentication</th><th>Required roles</th><th>Machine</th><th className="actions-column"><span className="sr-only">Actions</span></th></tr></thead><tbody>
      {policies.map(({ route, path }, index) => <tr key={`${route.principal.id}-${route.hostname}-${path.path}-${index}`}><td><strong>{route.hostname}</strong></td><td><code>{path.path}</code></td><td>{path.methods.join(" + ") || "Protected"}</td><td>{path.roles.length ? path.roles.join(", ") : "Any authenticated user"}</td><td>{route.principal.name || route.principal.client_id}</td><td className="actions-column"><button className="icon-action" type="button" aria-label={`Edit access for ${route.hostname}${path.path}`} onClick={() => onEdit(route.principal)}><Ellipsis size={18} /></button></td></tr>)}
    </tbody></table>{policies.length === 0 ? <EmptyState title="No protected paths" copy="Enable path protection in a machine’s route configuration to require bearer tokens, browser sign-in, or roles." /> : null}</div>
  </>;
}

export function KeysPage({ principals, loading, error, selected, onToggle, onCreate, onEdit, onDelete, onExport }: { principals: ServicePrincipal[]; loading: boolean; error: string; selected: number[]; onToggle: (id: number) => void; onCreate: (mode: Exclude<CreationMode, null>) => void; onEdit: (principal: ServicePrincipal) => void; onDelete: (principal: ServicePrincipal) => void; onExport: () => void }) {
  return <>
    <PageHeader title="Keys" description="Manage machine credentials and temporary access to your Pipe network." actions={<Menu position="bottom-end" width={230}><Menu.Target><Button rightSection={<ChevronDown size={14} />}>Generate key</Button></Menu.Target><Menu.Dropdown><Menu.Item leftSection={<KeyRound size={16} />} onClick={() => onCreate("access")}>Machine key</Menu.Item><Menu.Item leftSection={<Activity size={16} />} onClick={() => onCreate("temporary")}>Temporary key</Menu.Item></Menu.Dropdown></Menu>} />
    {selected.length > 0 ? <div className="selection-bar"><span>{selected.length} selected</span><Button variant="default" leftSection={<Download size={15} />} onClick={onExport}>Export configurations</Button></div> : null}
    <div className="data-table-wrap"><table className="data-table"><thead><tr><th className="select-column"><span className="sr-only">Select</span></th><th>Name</th><th>Client ID</th><th>Authorized domain</th><th className="actions-column"><span className="sr-only">Actions</span></th></tr></thead><tbody>
      {principals.map((principal) => <tr key={principal.id}><td className="select-column"><Checkbox aria-label={`Select ${principal.name || principal.client_id}`} checked={selected.includes(principal.id)} onChange={() => onToggle(principal.id)} /></td><td><div className="secondary-lines"><strong>{principal.name || principal.client_id}</strong><span>{principal.username}</span></div></td><td><code>{principal.client_id}</code></td><td><code>{principal.entitlement}</code></td><td className="actions-column"><RowMenu label={principal.name || principal.client_id} onEdit={() => onEdit(principal)} onDelete={() => onDelete(principal)} /></td></tr>)}
    </tbody></table>{loading ? <LoadingRow label="Loading keys…" /> : null}{error ? <p className="inline-error">{error}</p> : null}{!loading && !error && principals.length === 0 ? <EmptyState title="No machine keys" copy="Generate a key for automation, servers, or scripts." action={<Button variant="default" onClick={() => onCreate("access")}>Generate key</Button>} /> : null}</div>
  </>;
}

export function SettingsPage({ identity, entitlements, onMachines }: { identity: Identity; entitlements: string[]; onMachines: () => void }) {
  return <>
    <PageHeader title="Settings" description="Network identity and registration boundaries for this control plane." />
    <section className="settings-section"><div className="settings-heading"><h2>Pipe domain</h2><p>The public suffix used to register routes and issue client credentials.</p></div><dl className="definition-grid"><dt>Domain suffix</dt><dd><code>{identity.required_entitlement}</code></dd><dt>Route pattern</dt><dd><code>{identity.route_pattern}</code></dd><dt>Control plane</dt><dd><code>{identity.control_plane_url}</code></dd></dl></section>
    <section className="settings-section"><div className="settings-heading"><h2>Authorized domains</h2><p>Domains granted by your identity provider.</p></div><div className="domain-list">{entitlements.map((entitlement) => <code key={entitlement}>{entitlement}</code>)}</div></section>
    <section className="settings-section"><div className="settings-heading"><h2>Client configuration</h2><p>Transport, identity, certificates, backends, path routing, and authorization are configured per machine.</p></div><Button variant="default" onClick={onMachines}>Manage machines</Button></section>
  </>;
}

function RowMenu({ label, onDetails, onEdit, onDelete }: { label: string; onDetails?: () => void; onEdit: () => void; onDelete: () => void }) {
  return <Menu position="bottom-end" width={210} shadow="md"><Menu.Target><button className="icon-action" type="button" aria-label={`Actions for ${label}`}><Ellipsis size={18} /></button></Menu.Target><Menu.Dropdown>{onDetails ? <Menu.Item leftSection={<Monitor size={15} />} onClick={onDetails}>View details</Menu.Item> : null}<Menu.Item leftSection={<Settings size={15} />} onClick={onEdit}>Edit configuration…</Menu.Item><Menu.Divider /><Menu.Item color="red" leftSection={<Trash2 size={15} />} onClick={onDelete}>Remove…</Menu.Item></Menu.Dropdown></Menu>;
}

function EmptyState({ title, copy, action }: { title: string; copy: string; action?: ReactNode }) {
  return <div className="empty-state"><strong>{title}</strong><span>{copy}</span>{action}</div>;
}

function LoadingRow({ label }: { label: string }) {
  return <div className="loading-row" role="status"><Loader size="xs" /><span>{label}</span></div>;
}
