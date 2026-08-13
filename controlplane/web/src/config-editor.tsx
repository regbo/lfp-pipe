import { useState } from "react";
import { Check, ChevronDown, Plus, Trash2 } from "lucide-react";
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
  const routes = asRoutes(document.routes);
  const setDefault = (key: string, value: unknown) => update((draft) => { childTable(draft, "defaults")[key] = value; });
  const setOAuth = (key: string, value: unknown) => update((draft) => { childTable(childTable(draft, "defaults"), "oauth")[key] = value; });
  const setAcme = (key: string, value: unknown) => update((draft) => { childTable(childTable(draft, "defaults"), "acme")[key] = value; });
  const setRoute = (index: number, key: string, value: unknown) => update((draft) => { asRoutes(draft.routes)[index][key] = value; });
  const setPath = (routeIndex: number, pathIndex: number, key: string, value: unknown) => update((draft) => { asRoutes(asRoutes(draft.routes)[routeIndex].path_routes)[pathIndex][key] = value; });
  const setAuthorization = (routeIndex: number, pathIndex: number, key: string, value: unknown) => update((draft) => {
    childTable(asRoutes(asRoutes(draft.routes)[routeIndex].path_routes)[pathIndex], "authorization")[key] = value;
  });

  return <div className="structured-config">
    <section className="config-root-section" aria-labelledby="common-settings-heading">
      <div className="config-section-heading">
        <div><h2 id="common-settings-heading">Common settings</h2><span>Used by every route unless a route overrides them.</span></div>
      </div>
      <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
        <TextField label="TLS backend" value={text(defaults.backend_addr)} onChange={(value) => setDefault("backend_addr", value)} />
        <TextField label="HTTP backend" value={text(defaults.http_backend_addr)} onChange={(value) => setDefault("http_backend_addr", value)} />
        <TextField className="field-span-full" label="NATS URL" value={text(defaults.nats_url)} onChange={(value) => setDefault("nats_url", value)} />
      </SimpleGrid>
      <Accordion className="settings-disclosure" variant="contained">
        <Accordion.Item value="advanced"><Accordion.Control icon={<ChevronDown size={14} aria-hidden="true" />}>Advanced common settings</Accordion.Control><Accordion.Panel><Stack gap="lg">
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
      <div className="config-section-heading"><div><h2 id="routes-heading">Routes</h2><span>{routes.length === 1 ? "1 public hostname" : `${routes.length} public hostnames`}</span></div><Button variant="light" leftSection={<Plus size={15} aria-hidden="true" />} type="button" onClick={() => update((draft) => { const items = asRoutes(draft.routes); items.push({ client_id: `route-${items.length + 1}`, hostname: "", path_routes: [] }); draft.routes = items; })}>Add route</Button></div>
      <div className="route-list">
        {routes.map((route, routeIndex) => <RouteEditor key={routeIndex} route={route} routeIndex={routeIndex} setRoute={setRoute} setPath={setPath} setAuthorization={setAuthorization} update={update} />)}
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
  setRoute: (index: number, key: string, value: unknown) => void;
  setPath: (route: number, path: number, key: string, value: unknown) => void;
  setAuthorization: (route: number, path: number, key: string, value: unknown) => void;
  update: (mutator: (draft: Table) => void) => void;
};

function RouteEditor({ route, routeIndex, setRoute, setPath, setAuthorization, update }: RouteEditorProps) {
  const paths = asRoutes(route.path_routes) as PathRoute[];
  const routeName = text(route.hostname) || `Route ${routeIndex + 1}`;
  return <article className="route-config">
    <div className="route-header"><div className="route-number" aria-hidden="true">{routeIndex + 1}</div><TextField className="route-hostname" label="Public hostname" value={text(route.hostname)} onChange={(value) => setRoute(routeIndex, "hostname", value)} /><ActionIcon type="button" color="red" variant="subtle" title={`Remove ${routeName}`} aria-label={`Remove ${routeName}`} onClick={() => update((draft) => { asRoutes(draft.routes).splice(routeIndex, 1); })}><Trash2 size={16} aria-hidden="true" /></ActionIcon></div>
    <div className="route-body">
      <div className="path-list-heading"><strong>Path rules</strong><Button type="button" variant="subtle" leftSection={<Plus size={14} aria-hidden="true" />} onClick={() => update((draft) => { const routes = asRoutes(draft.routes); const pathRoutes = asRoutes(routes[routeIndex].path_routes); pathRoutes.push({ path_prefix: "/", backend_addr: "127.0.0.1:8080" }); routes[routeIndex].path_routes = pathRoutes; })}>Add path</Button></div>
      {paths.length > 0 ? <div className="path-list">{paths.map((path, pathIndex) => <PathEditor key={pathIndex} path={path} routeIndex={routeIndex} pathIndex={pathIndex} setPath={setPath} setAuthorization={setAuthorization} update={update} />)}</div> : <p className="route-inheritance">All traffic uses the common backends.</p>}
      <Accordion className="route-disclosure" variant="contained"><Accordion.Item value="route-options"><Accordion.Control>Route options</Accordion.Control><Accordion.Panel><SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
        <TextField label="Client ID" value={text(route.client_id)} onChange={(value) => setRoute(routeIndex, "client_id", value)} />
        <TextField label="Backend override" value={text(route.backend_addr)} onChange={(value) => setRoute(routeIndex, "backend_addr", value)} />
      </SimpleGrid></Accordion.Panel></Accordion.Item></Accordion>
    </div>
  </article>;
}

type PathEditorProps = { path: PathRoute; routeIndex: number; pathIndex: number; setPath: RouteEditorProps["setPath"]; setAuthorization: RouteEditorProps["setAuthorization"]; update: RouteEditorProps["update"] };

function PathEditor({ path, routeIndex, pathIndex, setPath, setAuthorization, update }: PathEditorProps) {
  const authorization = asTable(path.authorization);
  const protectedRoute = Object.keys(authorization).length > 0 && authorization.enabled !== false;
  return <div className="path-config">
    <div className="path-fields"><TextField className="path-field" label="Path" value={text(path.path_prefix)} onChange={(value) => setPath(routeIndex, pathIndex, "path_prefix", value)} /><TextField className="path-field" label="Backend" value={text(path.backend_addr)} onChange={(value) => setPath(routeIndex, pathIndex, "backend_addr", value)} /><CheckboxField label="Require JWT" checked={protectedRoute} onChange={(enabled) => update((draft) => { const target = asRoutes(asRoutes(draft.routes)[routeIndex].path_routes)[pathIndex]; const policy = asTable(target.authorization); if (Object.keys(policy).length > 0) { policy.enabled = enabled; target.authorization = policy; } else if (enabled) { target.authorization = { enabled: true, issuer: "", audiences: [], jwks_cache_file: "~/.cache/lfp-pipe/auth/jwks.json", roles_claim: "roles", required_roles: [], role_match: "any", algorithms: ["RS256"], jwks_refresh_seconds: 3600, jwks_max_stale_seconds: 604800, forward_authorization: false }; } })} /><ActionIcon type="button" color="red" variant="subtle" title={`Remove path ${pathIndex + 1}`} aria-label={`Remove path ${pathIndex + 1}`} onClick={() => update((draft) => { asRoutes(asRoutes(draft.routes)[routeIndex].path_routes).splice(pathIndex, 1); })}><Trash2 size={15} aria-hidden="true" /></ActionIcon></div>
    <Accordion className="route-disclosure path-disclosure" variant="contained"><Accordion.Item value="path-options"><Accordion.Control>{protectedRoute ? "Security and request options" : "Request options"}</Accordion.Control><Accordion.Panel><Stack gap="sm">
      <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm"><TextField label="Backend Host header" value={text(path.backend_host)} onChange={(value) => setPath(routeIndex, pathIndex, "backend_host", value)} /><Group gap="xl" align="end"><CheckboxField label="Strip path prefix" checked={bool(path.strip_path_prefix)} onChange={(value) => setPath(routeIndex, pathIndex, "strip_path_prefix", value)} /><CheckboxField label="Set proxy headers" checked={path.proxy_headers === undefined ? true : bool(path.proxy_headers)} onChange={(value) => setPath(routeIndex, pathIndex, "proxy_headers", value)} /></Group></SimpleGrid>
      {protectedRoute ? <div className="authorization-config"><SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
        <TextField className="field-span-full" label="Issuer" value={text(authorization.issuer)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "issuer", value)} />
        <TextField label="Audiences" value={list(authorization.audiences)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "audiences", splitList(value))} hint="Comma separated" />
        <TextField label="Required roles" value={list(authorization.required_roles)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "required_roles", splitList(value))} hint="Comma separated" />
        <TextField label="Roles claim" value={text(authorization.roles_claim)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "roles_claim", value)} />
        <SelectField label="Role matching" value={text(authorization.role_match) || "any"} options={["any", "all"]} onChange={(value) => setAuthorization(routeIndex, pathIndex, "role_match", value)} />
        <TextField className="field-span-full" label="JWKS URL" value={text(authorization.jwks_uri)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "jwks_uri", value)} />
        <TextField className="field-span-full" label="JWKS cache file" value={text(authorization.jwks_cache_file) || "~/.cache/lfp-pipe/auth/jwks.json"} onChange={(value) => setAuthorization(routeIndex, pathIndex, "jwks_cache_file", value)} />
      </SimpleGrid><Group gap="xl"><CheckboxField label="Forward Authorization header" checked={bool(authorization.forward_authorization)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "forward_authorization", value)} /></Group></div> : null}
    </Stack></Accordion.Panel></Accordion.Item></Accordion>
  </div>;
}

type TextFieldProps = { label: string; value: string; onChange: (value: string) => void; hint?: string; className?: string };
function TextField({ onChange, hint, label, ...props }: TextFieldProps) { return <TextInput {...props} label={label} name={label.toLowerCase().replace(/[^a-z0-9]+/g, "-")} autoComplete="off" description={hint} size="xs" onChange={(event) => onChange(event.currentTarget.value)} />; }
function NumberField({ label, value, suffix, onChange }: { label: string; value: number; suffix?: string; onChange: (value: number) => void }) { return <NumberInput label={label} value={value} suffix={suffix} size="xs" min={0} onChange={(next) => onChange(Number(next) || 0)} />; }
function SelectField({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) { return <Select label={label} value={value} data={options} size="xs" allowDeselect={false} onChange={(next) => next !== null && onChange(next)} />; }
function CheckboxField({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return <label className="checkbox-field" data-checked={checked || undefined}>
    <input type="checkbox" checked={checked} onChange={(event) => onChange(event.currentTarget.checked)} />
    <span className="checkbox-mark" aria-hidden="true">{checked ? <Check size={14} strokeWidth={3} /> : null}</span>
    <span>{label}</span>
  </label>;
}
