import { useState } from "react";
import { Check, Plus, Trash2 } from "lucide-react";
import { parse, stringify } from "smol-toml";
import { Accordion, ActionIcon, Button, Group, NumberInput, Select, SimpleGrid, Stack, TextInput } from "@mantine/core";

type Table = Record<string, unknown>;
type Route = Table & { path_routes?: PathRoute[] };
type PathRoute = Table & { authorization?: Table };

const asTable = (value: unknown): Table => value && typeof value === "object" && !Array.isArray(value) ? value as Table : {};
const asRoutes = (value: unknown): Route[] => Array.isArray(value) ? value as Route[] : [];
const text = (value: unknown) => typeof value === "string" ? value : "";
const number = (value: unknown, fallback: number) => typeof value === "number" ? value : fallback;
const bool = (value: unknown, fallback = false) => typeof value === "boolean" ? value : fallback;
const list = (value: unknown) => Array.isArray(value) ? value.join(", ") : "";
const splitList = (value: string) => value.split(",").map((item) => item.trim()).filter(Boolean);
function childTable(parent: Table, key: string): Table { const existing = asTable(parent[key]); parent[key] = existing; return existing; }

function defaultAuthorization(): Table {
  return {
    enabled: true,
    bearer: true,
    oidc: true,
    issuer: "",
    audiences: [],
    jwks_cache_file: "~/.cache/lfp-pipe/auth/jwks.json",
    roles_claim: "groups",
    required_roles: [],
    role_match: "any",
    algorithms: ["RS256"],
    jwks_refresh_seconds: 3600,
    jwks_max_stale_seconds: 604800,
    forward_authorization: false,
    oidc_client_id: "",
    oidc_client_secret_file: "",
    oidc_scopes: ["openid", "profile", "email", "groups"],
    oidc_callback_path: "/_lfp/auth/callback",
    oidc_logout_path: "/_lfp/auth/logout",
    oidc_session_key_file: "~/.secrets/lfp-pipe/oidc-session-key",
    oidc_session_ttl_seconds: 28800,
  };
}

type ConfigEditorProps = { toml: string; onChange: (toml: string) => void };

export function ConfigEditor({ toml, onChange }: ConfigEditorProps) {
  const [document, setDocument] = useState<Table>(() => parse(toml) as Table);

  function update(mutator: (draft: Table) => void) {
    const draft = structuredClone(document);
    mutator(draft);
    setDocument(draft);
    onChange(stringify(draft));
  }

  const defaults = asTable(document.defaults);
  const oauth = asTable(defaults.oauth);
  const acme = asTable(defaults.acme);
  const defaultTlsTermination = Object.keys(acme).length > 0 && acme.enabled !== false;
  const routes = asRoutes(document.routes);
  const setDefault = (key: string, value: unknown) => update((draft) => { childTable(draft, "defaults")[key] = value; });
  const setOptionalDefault = (key: string, value: string) => update((draft) => {
    const defaults = childTable(draft, "defaults");
    if (value.trim()) defaults[key] = value;
    else delete defaults[key];
  });
  const setOAuth = (key: string, value: unknown) => update((draft) => { childTable(childTable(draft, "defaults"), "oauth")[key] = value; });
  const setAcme = (key: string, value: unknown) => update((draft) => { childTable(childTable(draft, "defaults"), "acme")[key] = value; });
  const setRoute = (index: number, key: string, value: unknown) => update((draft) => { asRoutes(draft.routes)[index][key] = value; });
  const setOptionalRoute = (index: number, key: string, value: string) => update((draft) => {
    const route = asRoutes(draft.routes)[index];
    if (value.trim()) route[key] = value;
    else delete route[key];
  });
  const setRouteTlsTermination = (index: number, enabled: boolean) => update((draft) => {
    const route = asRoutes(draft.routes)[index];
    const settings = childTable(route, "acme");
    if (enabled === defaultTlsTermination) delete settings.enabled;
    else settings.enabled = enabled;
    if (Object.keys(settings).length === 0) delete route.acme;
  });
  const setPath = (routeIndex: number, pathIndex: number, key: string, value: unknown) => update((draft) => { asRoutes(asRoutes(draft.routes)[routeIndex].path_routes)[pathIndex][key] = value; });
  const setAuthorization = (routeIndex: number, pathIndex: number, key: string, value: unknown) => update((draft) => {
    childTable(asRoutes(asRoutes(draft.routes)[routeIndex].path_routes)[pathIndex], "authorization")[key] = value;
  });

  return <div className="structured-config">
    <section className="config-root-section" aria-labelledby="common-settings-heading">
      <div className="config-section-heading">
        <div><h2 id="common-settings-heading">Machine defaults</h2><span>Inherited by every public route unless it has an override.</span></div>
      </div>
      <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="sm">
        <TextField label="Default backend" value={text(defaults.backend_addr)} onChange={(value) => setDefault("backend_addr", value)} hint="Bare port, :port for localhost, or host:port" />
        <TextField label="Plain HTTP backend" value={text(defaults.http_backend_addr)} onChange={(value) => setOptionalDefault("http_backend_addr", value)} hint="Optional; accepts port, :port, or host:port" />
        <TextField label="Backend Host override" value={text(defaults.backend_host)} onChange={(value) => setOptionalDefault("backend_host", value)} hint="Incoming Host is preserved by default" />
        <TextField className="field-span-full" label="NATS URL" value={text(defaults.nats_url)} onChange={(value) => setDefault("nats_url", value)} />
      </SimpleGrid>
      <Accordion className="settings-disclosure" variant="contained">
        <Accordion.Item value="advanced"><Accordion.Control>Advanced common settings</Accordion.Control><Accordion.Panel><Stack gap="lg">
          <SettingsGroup title="Transport">
            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
              <SelectField label="Relay mode" value={text(defaults.relay_mode) || "auto"} options={["auto", "buffered", "splice"]} onChange={(value) => setDefault("relay_mode", value)} />
              <NumberField label="Claim acknowledgement" suffix=" ms" value={number(defaults.claim_ack_timeout_ms, 1500)} onChange={(value) => setDefault("claim_ack_timeout_ms", value)} />
            </SimpleGrid>
          </SettingsGroup>
          <SettingsGroup title="Identity">
            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
              <TextField label="Token URL" value={text(oauth.token_url)} onChange={(value) => setOAuth("token_url", value)} />
              <TextField label="Provider client ID" value={text(oauth.provider_client_id)} onChange={(value) => setOAuth("provider_client_id", value)} />
              <TextField label="Service username" value={text(oauth.username)} onChange={(value) => setOAuth("username", value)} />
              <TextField label="Secret file" value={text(oauth.client_secret_file)} onChange={(value) => setOAuth("client_secret_file", value)} />
              <TextField className="field-span-full" label="Control plane URL" value={text(oauth.control_plane_url)} onChange={(value) => setOAuth("control_plane_url", value)} />
              <TextField className="field-span-full" label="Scopes" value={list(oauth.scopes)} onChange={(value) => setOAuth("scopes", splitList(value))} hint="Comma separated" />
            </SimpleGrid>
          </SettingsGroup>
          <SettingsGroup title="Certificates">
            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
              <TextField label="Contacts" value={list(acme.contacts)} onChange={(value) => setAcme("contacts", splitList(value))} hint="Comma separated mailto addresses" />
              <TextField label="Cache directory" value={text(acme.cache_dir) || "~/.cache/lfp-pipe/acme"} onChange={(value) => setAcme("cache_dir", value)} />
            </SimpleGrid>
            <CheckboxField label="Use production ACME" checked={bool(acme.production)} onChange={(value) => setAcme("production", value)} />
          </SettingsGroup>
        </Stack></Accordion.Panel></Accordion.Item>
      </Accordion>
    </section>

    <section className="config-root-section routes-section" aria-labelledby="routes-heading">
      <div className="config-section-heading"><div><h2 id="routes-heading">Public routes</h2><span>{routes.length === 1 ? "1 registered hostname" : `${routes.length} registered hostnames`}</span></div><Button variant="light" leftSection={<Plus size={15} aria-hidden="true" />} type="button" onClick={() => update((draft) => { const items = asRoutes(draft.routes); items.push({ client_id: `route-${items.length + 1}`, hostname: "", path_routes: [] }); draft.routes = items; })}>Add route</Button></div>
      <div className="route-list">
        {routes.map((route, routeIndex) => <RouteEditor key={routeIndex} route={route} routeIndex={routeIndex} defaultTlsTermination={defaultTlsTermination} setRoute={setRoute} setOptionalRoute={setOptionalRoute} setRouteTlsTermination={setRouteTlsTermination} setPath={setPath} setAuthorization={setAuthorization} update={update} />)}
        {routes.length === 0 ? <div className="routes-empty"><strong>No routes</strong><span>Add a public hostname to start forwarding traffic.</span></div> : null}
      </div>
    </section>
  </div>;
}

function SettingsGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return <div className="settings-group"><h3>{title}</h3>{children}</div>;
}

type RouteEditorProps = {
  route: Route; routeIndex: number;
  defaultTlsTermination: boolean;
  setRoute: (index: number, key: string, value: unknown) => void;
  setOptionalRoute: (index: number, key: string, value: string) => void;
  setRouteTlsTermination: (index: number, enabled: boolean) => void;
  setPath: (route: number, path: number, key: string, value: unknown) => void;
  setAuthorization: (route: number, path: number, key: string, value: unknown) => void;
  update: (mutator: (draft: Table) => void) => void;
};

function RouteEditor({ route, routeIndex, defaultTlsTermination, setRoute, setOptionalRoute, setRouteTlsTermination, setPath, setAuthorization, update }: RouteEditorProps) {
  const paths = asRoutes(route.path_routes) as PathRoute[];
  const routeAcme = asTable(route.acme);
  const tlsTermination = routeAcme.enabled === undefined ? defaultTlsTermination : bool(routeAcme.enabled);
  const routeName = text(route.hostname) || `Route ${routeIndex + 1}`;
  return <article className="route-config">
    <div className="route-header"><div className="route-number" aria-hidden="true">{routeIndex + 1}</div><TextField className="route-hostname" label="Public hostname" value={text(route.hostname)} onChange={(value) => setRoute(routeIndex, "hostname", value)} /><ActionIcon type="button" color="red" variant="subtle" title={`Remove ${routeName}`} aria-label={`Remove ${routeName}`} onClick={() => update((draft) => { asRoutes(draft.routes).splice(routeIndex, 1); })}><Trash2 size={16} aria-hidden="true" /></ActionIcon></div>
    <div className="route-body">
      <SimpleGrid className="route-backends" cols={{ base: 1, sm: 3 }} spacing="sm">
        <TextField label="Host backend" value={text(route.backend_addr)} onChange={(value) => setOptionalRoute(routeIndex, "backend_addr", value)} hint="Bare port, :port for localhost, or host:port" />
        <TextField label="Plain HTTP backend" value={text(route.http_backend_addr)} onChange={(value) => setOptionalRoute(routeIndex, "http_backend_addr", value)} hint="Optional; accepts port, :port, or host:port" />
        <TextField label="Backend Host override" value={text(route.backend_host)} onChange={(value) => setOptionalRoute(routeIndex, "backend_host", value)} hint="Incoming Host is preserved by default" />
      </SimpleGrid>
      <div className="route-transport-options"><CheckboxField label="Terminate TLS" checked={tlsTermination} onChange={(enabled) => setRouteTlsTermination(routeIndex, enabled)} /><span>Pipe detects plain HTTP automatically; every other connection uses the host backend.</span></div>
      <div className="path-list-heading"><strong>Path rules</strong><Button type="button" variant="subtle" leftSection={<Plus size={14} aria-hidden="true" />} onClick={() => update((draft) => { const routes = asRoutes(draft.routes); const pathRoutes = asRoutes(routes[routeIndex].path_routes); pathRoutes.push({ path_prefix: "/", backend_addr: "8080" }); routes[routeIndex].path_routes = pathRoutes; })}>Add path</Button></div>
      {paths.length > 0 ? <div className="path-list">{paths.map((path, pathIndex) => <PathEditor key={pathIndex} path={path} routeIndex={routeIndex} pathIndex={pathIndex} setPath={setPath} setAuthorization={setAuthorization} update={update} />)}</div> : <p className="route-inheritance">All paths use this host backend.</p>}
      <Accordion className="route-disclosure" variant="contained"><Accordion.Item value="route-options"><Accordion.Control>Advanced route settings</Accordion.Control><Accordion.Panel><SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
        <TextField label="Client ID" value={text(route.client_id)} onChange={(value) => setRoute(routeIndex, "client_id", value)} />
        <CheckboxField label="Set proxy headers" checked={route.proxy_headers === undefined ? true : bool(route.proxy_headers)} onChange={(value) => setRoute(routeIndex, "proxy_headers", value)} />
      </SimpleGrid></Accordion.Panel></Accordion.Item></Accordion>
    </div>
  </article>;
}

type PathEditorProps = { path: PathRoute; routeIndex: number; pathIndex: number; setPath: RouteEditorProps["setPath"]; setAuthorization: RouteEditorProps["setAuthorization"]; update: RouteEditorProps["update"] };

function PathEditor({ path, routeIndex, pathIndex, setPath, setAuthorization, update }: PathEditorProps) {
  const authorization = asTable(path.authorization);
  const protectedRoute = Object.keys(authorization).length > 0 && authorization.enabled !== false;
  const bearerEnabled = authorization.bearer === undefined ? true : bool(authorization.bearer);
  const oidcEnabled = authorization.oidc === undefined ? Boolean(text(authorization.oidc_client_id)) : bool(authorization.oidc);
  return <div className="path-config">
    <div className="path-header"><strong>Path {pathIndex + 1}</strong><ActionIcon type="button" color="red" variant="subtle" title={`Remove path ${pathIndex + 1}`} aria-label={`Remove path ${pathIndex + 1}`} onClick={() => update((draft) => { asRoutes(asRoutes(draft.routes)[routeIndex].path_routes).splice(pathIndex, 1); })}><Trash2 size={15} aria-hidden="true" /></ActionIcon></div>
    <div className="path-fields"><TextField className="path-field" label="Path" value={text(path.path_prefix)} onChange={(value) => setPath(routeIndex, pathIndex, "path_prefix", value)} /><TextField className="path-field" label="Backend" value={text(path.backend_addr)} onChange={(value) => setPath(routeIndex, pathIndex, "backend_addr", value)} hint="Bare port, :port for localhost, or host:port" /><CheckboxField label="Protect path" checked={protectedRoute} onChange={(enabled) => update((draft) => { const target = asRoutes(asRoutes(draft.routes)[routeIndex].path_routes)[pathIndex]; const policy = asTable(target.authorization); if (Object.keys(policy).length > 0) { policy.enabled = enabled; target.authorization = policy; } else if (enabled) { target.authorization = defaultAuthorization(); } })} /></div>
    <Accordion className="route-disclosure path-disclosure" variant="contained"><Accordion.Item value="path-options"><Accordion.Control>{protectedRoute ? "Security and request options" : "Request options"}</Accordion.Control><Accordion.Panel><Stack gap="sm">
      <div className="request-options"><TextField label="Backend Host header" value={text(path.backend_host)} onChange={(value) => setPath(routeIndex, pathIndex, "backend_host", value)} /><Group className="request-option-toggles" gap="xl"><CheckboxField label="Strip path prefix" checked={bool(path.strip_path_prefix)} onChange={(value) => setPath(routeIndex, pathIndex, "strip_path_prefix", value)} /><CheckboxField label="Set proxy headers" checked={path.proxy_headers === undefined ? true : bool(path.proxy_headers)} onChange={(value) => setPath(routeIndex, pathIndex, "proxy_headers", value)} /></Group></div>
      {protectedRoute ? <div className="authorization-config">
        <Group className="authorization-methods" gap="xl"><CheckboxField label="Bearer tokens" checked={bearerEnabled} onChange={(value) => setAuthorization(routeIndex, pathIndex, "bearer", value)} /><CheckboxField label="Browser OIDC" checked={oidcEnabled} onChange={(value) => setAuthorization(routeIndex, pathIndex, "oidc", value)} /></Group>
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
        <TextField className="field-span-full" label="Issuer" value={text(authorization.issuer)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "issuer", value)} />
        {bearerEnabled ? <TextField label="Audiences" value={list(authorization.audiences)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "audiences", splitList(value))} hint="Comma separated" /> : null}
        <TextField label="Required roles" value={list(authorization.required_roles)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "required_roles", splitList(value))} hint="Comma separated" />
        <TextField label="Roles claim" value={text(authorization.roles_claim)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "roles_claim", value)} />
        <SelectField label="Role matching" value={text(authorization.role_match) || "any"} options={["any", "all"]} onChange={(value) => setAuthorization(routeIndex, pathIndex, "role_match", value)} />
        {bearerEnabled ? <TextField className="field-span-full" label="JWKS URL" value={text(authorization.jwks_uri)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "jwks_uri", value)} /> : null}
        {bearerEnabled ? <TextField className="field-span-full" label="JWKS cache file" value={text(authorization.jwks_cache_file) || "~/.cache/lfp-pipe/auth/jwks.json"} onChange={(value) => setAuthorization(routeIndex, pathIndex, "jwks_cache_file", value)} /> : null}
        {oidcEnabled ? <TextField label="OIDC client ID" value={text(authorization.oidc_client_id)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "oidc_client_id", value)} /> : null}
        {oidcEnabled ? <TextField label="OIDC secret file" value={text(authorization.oidc_client_secret_file)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "oidc_client_secret_file", value)} /> : null}
        {oidcEnabled ? <TextField className="field-span-full" label="OIDC scopes" value={list(authorization.oidc_scopes) || "openid, profile, email, groups"} onChange={(value) => setAuthorization(routeIndex, pathIndex, "oidc_scopes", splitList(value))} hint="Comma separated" /> : null}
        {oidcEnabled ? <TextField label="Callback path" value={text(authorization.oidc_callback_path) || "/_lfp/auth/callback"} onChange={(value) => setAuthorization(routeIndex, pathIndex, "oidc_callback_path", value)} /> : null}
        {oidcEnabled ? <TextField label="Logout path" value={text(authorization.oidc_logout_path) || "/_lfp/auth/logout"} onChange={(value) => setAuthorization(routeIndex, pathIndex, "oidc_logout_path", value)} /> : null}
        {oidcEnabled ? <TextField label="Session key file" value={text(authorization.oidc_session_key_file) || "~/.secrets/lfp-pipe/oidc-session-key"} onChange={(value) => setAuthorization(routeIndex, pathIndex, "oidc_session_key_file", value)} /> : null}
        {oidcEnabled ? <NumberField label="Session lifetime" suffix=" s" value={number(authorization.oidc_session_ttl_seconds, 28800)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "oidc_session_ttl_seconds", value)} /> : null}
      </SimpleGrid>{bearerEnabled ? <Group gap="xl"><CheckboxField label="Forward Authorization header" checked={bool(authorization.forward_authorization)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "forward_authorization", value)} /></Group> : null}</div> : null}
    </Stack></Accordion.Panel></Accordion.Item></Accordion>
  </div>;
}

type TextFieldProps = { label: string; value: string; onChange: (value: string) => void; hint?: string; className?: string };
function TextField({ onChange, hint, label, ...props }: TextFieldProps) { return <TextInput {...props} label={label} name={label.toLowerCase().replace(/[^a-z0-9]+/g, "-")} autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} data-1p-ignore="true" data-lpignore="true" data-bwignore="true" data-form-type="other" description={hint} size="xs" onChange={(event) => onChange(event.currentTarget.value)} />; }
function NumberField({ label, value, suffix, onChange }: { label: string; value: number; suffix?: string; onChange: (value: number) => void }) { return <NumberInput label={label} value={value} suffix={suffix} size="xs" min={0} onChange={(next) => onChange(Number(next) || 0)} />; }
function SelectField({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) { return <Select label={label} value={value} data={options} size="xs" allowDeselect={false} onChange={(next) => next !== null && onChange(next)} />; }
function CheckboxField({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return <label className="checkbox-field" data-checked={checked || undefined}>
    <input type="checkbox" checked={checked} onChange={(event) => onChange(event.currentTarget.checked)} />
    <span className="checkbox-mark" aria-hidden="true">{checked ? <Check size={14} strokeWidth={3} /> : null}</span>
    <span>{label}</span>
  </label>;
}
