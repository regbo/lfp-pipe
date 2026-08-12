import { useState } from "react";
import { Plus, Trash2 } from "lucide-react";
import { parse, stringify } from "smol-toml";
import { Accordion, ActionIcon, Button, Checkbox, Fieldset, Group, NumberInput, Select, SimpleGrid, Stack, TextInput } from "@mantine/core";

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
    <div className="config-section-heading"><div><strong>Routes</strong><span>Public hostnames and the local services they reach.</span></div><Button variant="light" size="xs" leftSection={<Plus size={15} />} type="button" onClick={() => update((draft) => { const items = asRoutes(draft.routes); items.push({ client_id: "new-route", hostname: "route.pipe.example.com", path_routes: [] }); draft.routes = items; })}>Add route</Button></div>
    {routes.map((route, routeIndex) => <RouteEditor key={routeIndex} route={route} routeIndex={routeIndex} setRoute={setRoute} setPath={setPath} setAuthorization={setAuthorization} update={update} />)}

    <Accordion className="config-disclosures" variant="separated" multiple>
    <Accordion.Item value="connection-defaults"><Accordion.Control>Connection defaults</Accordion.Control><Accordion.Panel><Stack gap="sm">
      <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
        <TextField label="TLS backend" value={text(defaults.backend_addr)} onChange={(value) => setDefault("backend_addr", value)} />
        <TextField label="HTTP backend" value={text(defaults.http_backend_addr)} onChange={(value) => setDefault("http_backend_addr", value)} />
      </SimpleGrid>
    </Stack></Accordion.Panel></Accordion.Item>

    <Accordion.Item value="transport"><Accordion.Control>Transport and relay</Accordion.Control><Accordion.Panel><Stack gap="sm">
      <TextField label="NATS URL" value={text(defaults.nats_url)} onChange={(value) => setDefault("nats_url", value)} hint="Direct tls:// is the default; wss:// is opt-in" />
      <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
        <SelectField label="Relay mode" value={text(defaults.relay_mode) || "auto"} options={["auto", "buffered", "splice"]} onChange={(value) => setDefault("relay_mode", value)} />
        <NumberField label="Claim acknowledgement" suffix=" ms" value={number(defaults.claim_ack_timeout_ms, 1500)} onChange={(value) => setDefault("claim_ack_timeout_ms", value)} />
      </SimpleGrid>
    </Stack></Accordion.Panel></Accordion.Item>

    <Accordion.Item value="identity"><Accordion.Control>Identity provider</Accordion.Control><Accordion.Panel><Stack gap="sm">
      <TextField label="Token URL" value={text(oauth.token_url)} onChange={(value) => setOAuth("token_url", value)} />
      <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
        <TextField label="Provider client ID" value={text(oauth.provider_client_id)} onChange={(value) => setOAuth("provider_client_id", value)} />
        <TextField label="Service username" value={text(oauth.username)} onChange={(value) => setOAuth("username", value)} />
      </SimpleGrid>
      <TextField label="Secret file placeholder" value={text(oauth.client_secret_file)} onChange={(value) => setOAuth("client_secret_file", value)} />
      <TextField label="Control plane URL" value={text(oauth.control_plane_url)} onChange={(value) => setOAuth("control_plane_url", value)} />
      <TextField label="Scopes" value={list(oauth.scopes)} onChange={(value) => setOAuth("scopes", splitList(value))} hint="Comma separated" />
    </Stack></Accordion.Panel></Accordion.Item>

    <Accordion.Item value="certificates"><Accordion.Control>Certificates and cache</Accordion.Control><Accordion.Panel><Stack gap="sm">
      <TextField label="Contacts" value={list(acme.contacts)} onChange={(value) => setAcme("contacts", splitList(value))} hint="Comma separated mailto addresses" />
      <TextField label="Cache directory" value={text(acme.cache_dir) || "~/.cache/lfp-pipe/acme"} onChange={(value) => setAcme("cache_dir", value)} />
      <CheckboxField label="Use production ACME" checked={bool(acme.production)} onChange={(value) => setAcme("production", value)} />
    </Stack></Accordion.Panel></Accordion.Item>

    {routes.flatMap((route, routeIndex) => (asRoutes(route.path_routes) as PathRoute[]).map((path, pathIndex) => ({ path, routeIndex, pathIndex }))).filter(({ path }) => Object.keys(asTable(path.authorization)).length > 0).map(({ path, routeIndex, pathIndex }) => { const authorization = asTable(path.authorization); return <Accordion.Item key={`${routeIndex}-${pathIndex}`} value={`jwt-${routeIndex}-${pathIndex}`}><Accordion.Control>{`JWT policy · ${text(path.path_prefix)}`}</Accordion.Control><Accordion.Panel><Stack gap="sm">
      <TextField label="Exact issuer" value={text(authorization.issuer)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "issuer", value)} />
      <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} spacing="sm">
        <TextField label="Audiences" value={list(authorization.audiences)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "audiences", splitList(value))} hint="Comma separated" />
        <TextField label="Roles claim" value={text(authorization.roles_claim)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "roles_claim", value)} />
        <TextField label="Required roles" value={list(authorization.required_roles)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "required_roles", splitList(value))} hint="Comma separated" />
        <SelectField label="Role matching" value={text(authorization.role_match) || "any"} options={["any", "all"]} onChange={(value) => setAuthorization(routeIndex, pathIndex, "role_match", value)} />
      </SimpleGrid>
      <TextField label="JWKS URL (optional)" value={text(authorization.jwks_uri)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "jwks_uri", value)} />
      <TextField label="JWKS cache file" value={text(authorization.jwks_cache_file) || "~/.cache/lfp-pipe/auth/jwks.json"} onChange={(value) => setAuthorization(routeIndex, pathIndex, "jwks_cache_file", value)} />
      <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
        <NumberField label="Refresh interval" suffix=" seconds" value={number(authorization.jwks_refresh_seconds, 3600)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "jwks_refresh_seconds", value)} />
        <NumberField label="Maximum stale age" suffix=" seconds" value={number(authorization.jwks_max_stale_seconds, 604800)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "jwks_max_stale_seconds", value)} />
      </SimpleGrid>
      <CheckboxField label="Forward Authorization header" checked={bool(authorization.forward_authorization)} onChange={(value) => setAuthorization(routeIndex, pathIndex, "forward_authorization", value)} />
    </Stack></Accordion.Panel></Accordion.Item>; })}

    </Accordion>
  </div>;
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
  return <Fieldset className="config-group route-config" legend={`Route ${routeIndex + 1}`}>
    <div className="config-grid">
      <TextField className="field-span-wide" label="Hostname" value={text(route.hostname)} onChange={(value) => setRoute(routeIndex, "hostname", value)} />
    </div>
    <div className="config-actions"><Button type="button" variant="light" size="xs" leftSection={<Plus size={15} />} onClick={() => update((draft) => { const routes = asRoutes(draft.routes); const pathRoutes = asRoutes(routes[routeIndex].path_routes); pathRoutes.push({ path_prefix: "/service", backend_addr: "127.0.0.1:8080", strip_path_prefix: true }); routes[routeIndex].path_routes = pathRoutes; })}>Add path</Button><Button type="button" color="red" variant="light" size="xs" leftSection={<Trash2 size={15} />} onClick={() => update((draft) => { asRoutes(draft.routes).splice(routeIndex, 1); })}>Remove route</Button></div>
    {paths.map((path, pathIndex) => <PathEditor key={pathIndex} path={path} routeIndex={routeIndex} pathIndex={pathIndex} setPath={setPath} setAuthorization={setAuthorization} update={update} />)}
    <Accordion className="route-disclosure" variant="contained"><Accordion.Item value="technical"><Accordion.Control>Technical options</Accordion.Control><Accordion.Panel><SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
      <TextField label="Client ID" value={text(route.client_id)} onChange={(value) => setRoute(routeIndex, "client_id", value)} />
      <TextField label="Default backend override" value={text(route.backend_addr)} onChange={(value) => setRoute(routeIndex, "backend_addr", value)} />
    </SimpleGrid></Accordion.Panel></Accordion.Item></Accordion>
  </Fieldset>;
}

type PathEditorProps = { path: PathRoute; routeIndex: number; pathIndex: number; setPath: RouteEditorProps["setPath"]; setAuthorization: RouteEditorProps["setAuthorization"]; update: RouteEditorProps["update"] };

function PathEditor({ path, routeIndex, pathIndex, setPath, setAuthorization, update }: PathEditorProps) {
  const authorization = asTable(path.authorization);
  const protectedRoute = Object.keys(authorization).length > 0;
  return <div className="path-config"><div className="config-section-heading"><strong>Path {pathIndex + 1}</strong><ActionIcon type="button" color="red" variant="subtle" title="Remove path" onClick={() => update((draft) => { asRoutes(asRoutes(draft.routes)[routeIndex].path_routes).splice(pathIndex, 1); })}><Trash2 size={15} /></ActionIcon></div>
    <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
      <TextField label="Path prefix" value={text(path.path_prefix)} onChange={(value) => setPath(routeIndex, pathIndex, "path_prefix", value)} />
      <TextField label="Backend address" value={text(path.backend_addr)} onChange={(value) => setPath(routeIndex, pathIndex, "backend_addr", value)} />
    </SimpleGrid>
    <Group gap="xl" className="path-options">
      <CheckboxField label="Strip path prefix" checked={bool(path.strip_path_prefix)} onChange={(value) => setPath(routeIndex, pathIndex, "strip_path_prefix", value)} />
      <CheckboxField label="Require bearer JWT" checked={protectedRoute} onChange={(enabled) => update((draft) => { const target = asRoutes(asRoutes(draft.routes)[routeIndex].path_routes)[pathIndex]; if (enabled) target.authorization = { issuer: "https://auth.example.com/application/o/provider/", audiences: ["service"], jwks_cache_file: "~/.cache/lfp-pipe/auth/jwks.json", roles_claim: "groups", required_roles: [], role_match: "any", algorithms: ["RS256"], jwks_refresh_seconds: 3600, jwks_max_stale_seconds: 604800, forward_authorization: false }; else delete target.authorization; })} />
    </Group>
    <Accordion className="route-disclosure" variant="contained"><Accordion.Item value="request"><Accordion.Control>Request rewriting</Accordion.Control><Accordion.Panel>
      <TextField label="Backend Host header" value={text(path.backend_host)} onChange={(value) => setPath(routeIndex, pathIndex, "backend_host", value)} />
    </Accordion.Panel></Accordion.Item></Accordion>
  </div>;
}

type TextFieldProps = { label: string; value: string; onChange: (value: string) => void; hint?: string; className?: string };
function TextField({ onChange, hint, ...props }: TextFieldProps) { return <TextInput {...props} description={hint} size="xs" onChange={(event) => onChange(event.currentTarget.value)} />; }
function NumberField({ label, value, suffix, onChange }: { label: string; value: number; suffix?: string; onChange: (value: number) => void }) { return <NumberInput label={label} value={value} suffix={suffix} size="xs" min={0} onChange={(next) => onChange(Number(next) || 0)} />; }
function SelectField({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) { return <Select label={label} value={value} data={options} size="xs" allowDeselect={false} onChange={(next) => next !== null && onChange(next)} />; }
function CheckboxField({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) { return <Checkbox size="sm" checked={checked} onChange={(event) => onChange(event.currentTarget.checked)} label={label} />; }
