import { useState } from "react";
import { Check, ExternalLink, KeyRound, Plus, Route as RouteIcon, Trash2 } from "lucide-react";
import { parse, stringify } from "smol-toml";
import { Accordion, ActionIcon, Autocomplete, Button, Group, Modal, NumberInput, SegmentedControl, Select, SimpleGrid, Stack, TextInput } from "@mantine/core";
import { backendHref, linkHref } from "./link-utils";
import type { IdentityApplication, IdentityGroup, IdentityProvisioningStatus } from "./console-model";

type Table = Record<string, unknown>;
type Route = Table & { path_routes?: PathRoute[] };
type PathRoute = Table & { authorization?: Table };
type InheritanceMode = "inherit" | "on" | "off";
export type ConfigValidationErrors = Record<string, string>;

const asTable = (value: unknown): Table => value && typeof value === "object" && !Array.isArray(value) ? value as Table : {};
const asRoutes = (value: unknown): Route[] => Array.isArray(value) ? value as Route[] : [];
const text = (value: unknown) => typeof value === "string" ? value : "";
const number = (value: unknown, fallback: number) => typeof value === "number" ? value : fallback;
const bool = (value: unknown, fallback = false) => typeof value === "boolean" ? value : fallback;
const list = (value: unknown) => Array.isArray(value) ? value.join(", ") : "";
const splitList = (value: string) => value.split(",").map((item) => item.trim()).filter(Boolean);
const blankTextInherits = new Set(["issuer", "jwks_cache_file", "roles_claim", "oidc_client_id", "oidc_callback_path", "oidc_logout_path", "oidc_session_key_file"]);
const emptyListInherits = new Set(["audiences", "algorithms", "oidc_scopes"]);
const hasErrors = (errors: ConfigValidationErrors, prefix: string) => Object.keys(errors).some((key) => key === prefix || key.startsWith(`${prefix}.`));
function childTable(parent: Table, key: string): Table { const existing = asTable(parent[key]); parent[key] = existing; return existing; }
function enabledMode(settings: Table): InheritanceMode { return settings.enabled === undefined ? "inherit" : bool(settings.enabled) ? "on" : "off"; }
function authorizationState(parent: Table, local: Table) {
  const hasParent = Object.keys(parent).length > 0;
  const hasLocalSettings = Object.keys(local).some((key) => key !== "enabled");
  const mode = local.enabled !== undefined
    ? enabledMode(local)
    : hasParent ? "inherit"
    : hasLocalSettings ? "on"
    : "inherit";
  const inherited = hasParent && parent.enabled !== false;
  return { mode, inherited, enabled: mode === "inherit" ? inherited : mode === "on" };
}
function setAuthorizationValue(target: Table, key: string, value: unknown) {
  const policy = childTable(target, "authorization");
  const inheritsBlankText = blankTextInherits.has(key)
    && typeof value === "string" && !value.trim();
  const inheritsEmptyList = emptyListInherits.has(key)
    && Array.isArray(value) && value.length === 0;
  if (value === undefined || inheritsBlankText || inheritsEmptyList) delete policy[key];
  else policy[key] = value;
  if (Object.keys(policy).length === 0) delete target.authorization;
}
function setAuthorizationEnabled(target: Table, mode: InheritanceMode) {
  if (mode === "inherit") {
    const policy = asTable(target.authorization);
    delete policy.enabled;
    if (Object.keys(policy).length === 0) delete target.authorization;
    else target.authorization = policy;
    return;
  }
  childTable(target, "authorization").enabled = mode === "on";
}
function revealEditor(selector: string) {
  requestAnimationFrame(() => {
    const target = window.document.querySelector<HTMLElement>(selector);
    target?.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "center" });
  });
}

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

function firstDefined<T>(layers: Table[], key: string): T | undefined {
  return layers.find((layer) => layer[key] !== undefined)?.[key] as T | undefined;
}

function firstText(layers: Table[], key: string, fallback = "") {
  return layers.map((layer) => text(layer[key]).trim()).find(Boolean) ?? fallback;
}

function firstNonEmptyList(layers: Table[], key: string, fallback: string[] = []) {
  return layers.map((layer) => Array.isArray(layer[key]) ? layer[key] as string[] : []).find((value) => value.length > 0) ?? fallback;
}

function validateAuthorization(errors: ConfigValidationErrors, prefix: string, layers: Table[]) {
  const bearer = firstDefined<boolean>(layers, "bearer") ?? true;
  const oidcClientId = firstText(layers, "oidc_client_id");
  const oidc = firstDefined<boolean>(layers, "oidc") ?? Boolean(oidcClientId);
  if (!bearer && !oidc) errors[`${prefix}.methods`] = "Enable bearer tokens, browser OIDC, or both.";
  if (!firstText(layers, "issuer")) errors[`${prefix}.issuer`] = "Issuer is required when authentication is on.";
  if (bearer && firstNonEmptyList(layers, "audiences").length === 0) errors[`${prefix}.audiences`] = "Add at least one bearer-token audience.";
  if (oidc && !oidcClientId) errors[`${prefix}.oidc_client_id`] = "OIDC client ID is required when browser OIDC is on.";
  const scopes = firstNonEmptyList(layers, "oidc_scopes", ["openid", "profile", "email", "groups"]);
  if (oidc && !scopes.includes("openid")) errors[`${prefix}.oidc_scopes`] = "OIDC scopes must include openid.";
  const callbackPath = firstText(layers, "oidc_callback_path", "/_lfp/auth/callback");
  const logoutPath = firstText(layers, "oidc_logout_path", "/_lfp/auth/logout");
  const validOidcPath = (value: string) => value.startsWith("/_lfp/auth/") && !value.includes("?") && !value.includes("#");
  if (oidc && !validOidcPath(callbackPath)) errors[`${prefix}.oidc_callback_path`] = "Use a reserved /_lfp/auth/ path without a query or fragment.";
  if (oidc && !validOidcPath(logoutPath)) errors[`${prefix}.oidc_logout_path`] = "Use a reserved /_lfp/auth/ path without a query or fragment.";
  if (oidc && callbackPath === logoutPath) errors[`${prefix}.oidc_logout_path`] = "Logout and callback paths must be different.";
}

function validateClientDocument(document: Table): ConfigValidationErrors {
  const errors: ConfigValidationErrors = {};
  const defaults = asTable(document.defaults);
  const defaultAuthorization = asTable(defaults.authorization);
  const defaultAuth = authorizationState({}, defaultAuthorization);
  const defaultTls = Object.keys(asTable(defaults.acme)).length > 0 && asTable(defaults.acme).enabled !== false;
  const routes = asRoutes(document.routes);

  if (routes.length === 0) errors.routes = "Add at least one public route.";
  if (routes.some((route) => !text(route.nats_url).trim() && !text(defaults.nats_url).trim())) errors["defaults.nats_url"] = "NATS URL is required for every route.";
  const oauth = asTable(defaults.oauth);
  if (Object.keys(oauth).length > 0) {
    for (const [key, label] of [
      ["token_url", "Token URL"],
      ["provider_client_id", "Provider client ID"],
      ["username", "Service username"],
      ["client_secret_file", "Secret file"],
      ["control_plane_url", "Control plane URL"],
    ]) {
      if (!text(oauth[key]).trim()) errors[`defaults.oauth.${key}`] = `${label} is required when identity settings are configured.`;
    }
  }
  if (defaultAuth.enabled) validateAuthorization(errors, "defaults.authorization", [defaultAuthorization]);

  const clientIds = new Map<string, number[]>();
  routes.forEach((route, routeIndex) => {
    const prefix = `routes.${routeIndex}`;
    const clientId = text(route.client_id).trim();
    if (!clientId) errors[`${prefix}.client_id`] = "Client ID is required.";
    else clientIds.set(clientId, [...(clientIds.get(clientId) ?? []), routeIndex]);
    if (!text(route.hostname).trim()) errors[`${prefix}.hostname`] = "Public hostname is required.";
    if (!text(route.backend_addr).trim() && !text(defaults.backend_addr).trim()) errors[`${prefix}.backend_addr`] = "Host backend is required when there is no default backend.";

    const routeAuthorization = asTable(route.authorization);
    const routeAuth = authorizationState(defaultAuthorization, routeAuthorization);
    const routeAuthLayers = [routeAuthorization, defaultAuthorization];
    const routeHasAuthOverrides = Object.keys(routeAuthorization).some((key) => key !== "enabled");
    const routeTlsMode = enabledMode(asTable(route.acme));
    const routeTls = routeTlsMode === "inherit" ? defaultTls : routeTlsMode === "on";
    if (routeAuth.enabled && (routeAuth.mode !== "inherit" || routeHasAuthOverrides)) {
      validateAuthorization(errors, `${prefix}.authorization`, routeAuthLayers);
    }
    if (routeAuth.enabled && !routeTls) errors[`${prefix}.tls`] = "TLS must be on so authenticated HTTP can be inspected.";

    const pathPrefixes = new Map<string, number[]>();
    (asRoutes(route.path_routes) as PathRoute[]).forEach((path, pathIndex) => {
      const pathPrefix = `${prefix}.path_routes.${pathIndex}`;
      const value = text(path.path_prefix).trim();
      if (!value) errors[`${pathPrefix}.path_prefix`] = "Path is required.";
      else if (!value.startsWith("/") || value.includes("?") || value.includes("#")) errors[`${pathPrefix}.path_prefix`] = "Start with / and omit query strings and fragments.";
      else pathPrefixes.set(value, [...(pathPrefixes.get(value) ?? []), pathIndex]);
      if (!text(path.backend_addr).trim()) errors[`${pathPrefix}.backend_addr`] = "Path backend is required.";
      if (!routeTls) errors[`${pathPrefix}.tls`] = "TLS must be on so path routing can inspect HTTP.";
      const pathAuthorization = asTable(path.authorization);
      const inheritedAuthorization = { ...defaultAuthorization, ...routeAuthorization };
      const pathAuth = authorizationState(inheritedAuthorization, pathAuthorization);
      const pathHasAuthOverrides = Object.keys(pathAuthorization).some((key) => key !== "enabled");
      if (pathAuth.enabled && (pathAuth.mode !== "inherit" || pathHasAuthOverrides)) validateAuthorization(errors, `${pathPrefix}.authorization`, [pathAuthorization, routeAuthorization, defaultAuthorization]);
    });
    pathPrefixes.forEach((indexes, value) => {
      if (indexes.length > 1) for (const pathIndex of indexes) errors[`${prefix}.path_routes.${pathIndex}.path_prefix`] = `Path ${value} is duplicated on this route.`;
    });
  });
  clientIds.forEach((indexes, clientId) => {
    if (indexes.length > 1) for (const routeIndex of indexes) errors[`routes.${routeIndex}.client_id`] = `Client ID ${clientId} is used by another route.`;
  });
  return errors;
}

export function validateConfigToml(toml: string): ConfigValidationErrors {
  try {
    return validateClientDocument(parse(toml) as Table);
  } catch {
    return { document: "Configuration must be valid TOML." };
  }
}

type ConfigEditorProps = {
  toml: string;
  onChange: (toml: string) => void;
  provisioning?: IdentityProvisioningStatus;
  identityGroups?: IdentityGroup[];
  onLoadIdentityGroups?: () => Promise<void>;
  onProvisionIdentity?: (hostname: string, callbackPath: string, group: string) => Promise<IdentityApplication>;
};

export function ConfigEditor({ toml, onChange, provisioning, identityGroups = [], onLoadIdentityGroups, onProvisionIdentity }: ConfigEditorProps) {
  const [document, setDocument] = useState<Table>(() => parse(toml) as Table);
  const [provisioningOpen, setProvisioningOpen] = useState(false);
  const [provisioningTarget, setProvisioningTarget] = useState("");
  const [provisioningGroup, setProvisioningGroup] = useState("");
  const [provisioningBusy, setProvisioningBusy] = useState(false);
  const [provisioningError, setProvisioningError] = useState("");

  function update(mutator: (draft: Table) => void) {
    const draft = structuredClone(document);
    mutator(draft);
    setDocument(draft);
    onChange(stringify(draft));
  }

  const defaults = asTable(document.defaults);
  const oauth = asTable(defaults.oauth);
  const oauthConfigured = Object.keys(oauth).length > 0;
  const acme = asTable(defaults.acme);
  const authorization = asTable(defaults.authorization);
  const defaultTlsTermination = Object.keys(acme).length > 0 && acme.enabled !== false;
  const defaultAuthorizationEnabled = Object.keys(authorization).length > 0 && authorization.enabled !== false;
  const defaultTcpPassthrough = bool(defaults.tcp_passthrough, true);
  const routes = asRoutes(document.routes);
  const validationErrors = validateClientDocument(document);
  const identityTargets = routes.flatMap((route, routeIndex) => {
    const hostname = text(route.hostname);
    if (!hostname) return [];
    const routeTarget = [{ value: `route:${routeIndex}`, label: `${hostname} · all paths` }];
    const pathTargets = (asRoutes(route.path_routes) as PathRoute[]).map((path, pathIndex) => ({
      value: `path:${routeIndex}:${pathIndex}`,
      label: `${hostname}${text(path.path_prefix) || "/"}`,
    }));
    return [...routeTarget, ...pathTargets];
  });
  const setDefault = (key: string, value: unknown) => update((draft) => { childTable(draft, "defaults")[key] = value; });
  const setOptionalDefault = (key: string, value: string) => update((draft) => {
    const defaults = childTable(draft, "defaults");
    if (value.trim()) defaults[key] = value;
    else delete defaults[key];
  });
  const setOAuth = (key: string, value: unknown) => update((draft) => { childTable(childTable(draft, "defaults"), "oauth")[key] = value; });
  const setAcme = (key: string, value: unknown) => update((draft) => { childTable(childTable(draft, "defaults"), "acme")[key] = value; });
  const setDefaultAuthorization = (key: string, value: unknown) => update((draft) => { childTable(childTable(draft, "defaults"), "authorization")[key] = value; });
  const setDefaultAuthorizationEnabled = (enabled: boolean) => update((draft) => {
    const policy = childTable(childTable(draft, "defaults"), "authorization");
    if (enabled && Object.keys(policy).length === 0) Object.assign(policy, defaultAuthorization());
    policy.enabled = enabled;
  });
  const setRoute = (index: number, key: string, value: unknown) => update((draft) => { asRoutes(draft.routes)[index][key] = value; });
  const setOptionalRoute = (index: number, key: string, value: string) => update((draft) => {
    const route = asRoutes(draft.routes)[index];
    if (value.trim()) route[key] = value;
    else delete route[key];
  });
  const setRouteTlsTermination = (index: number, mode: InheritanceMode) => update((draft) => {
    const route = asRoutes(draft.routes)[index];
    const settings = childTable(route, "acme");
    if (mode === "inherit") delete settings.enabled;
    else settings.enabled = mode === "on";
    if (Object.keys(settings).length === 0) delete route.acme;
  });
  const setRouteAuthorization = (routeIndex: number, key: string, value: unknown) => update((draft) => {
    setAuthorizationValue(asRoutes(draft.routes)[routeIndex], key, value);
  });
  const setPath = (routeIndex: number, pathIndex: number, key: string, value: unknown) => update((draft) => { asRoutes(asRoutes(draft.routes)[routeIndex].path_routes)[pathIndex][key] = value; });
  const setAuthorization = (routeIndex: number, pathIndex: number, key: string, value: unknown) => update((draft) => {
    const target = asRoutes(asRoutes(draft.routes)[routeIndex].path_routes)[pathIndex];
    setAuthorizationValue(target, key, value);
  });

  async function openIdentityProvisioning() {
    const firstTarget = identityTargets[0]?.value ?? "";
    setProvisioningTarget((current) => current || firstTarget);
    setProvisioningError("");
    setProvisioningOpen(true);
    await onLoadIdentityGroups?.();
  }

  async function provisionIdentity() {
    if (!onProvisionIdentity || !provisioningTarget) return;
    const [kind, routeValue, pathValue] = provisioningTarget.split(":");
    const routeIndex = Number(routeValue);
    const pathIndex = Number(pathValue);
    const route = routes[routeIndex];
    const hostname = text(route?.hostname);
    if (!hostname || !Number.isInteger(routeIndex)) return;
    setProvisioningBusy(true);
    setProvisioningError("");
    try {
      const result = await onProvisionIdentity(hostname, "/_lfp/auth/callback", provisioningGroup.trim());
      update((draft) => {
        const targetRoute = asRoutes(draft.routes)[routeIndex];
        const target = kind === "path"
          ? asRoutes(targetRoute.path_routes)[pathIndex]
          : targetRoute;
        const policy = childTable(target, "authorization");
        Object.assign(policy, {
          enabled: true,
          bearer: false,
          oidc: true,
          issuer: result.issuer,
          roles_claim: "groups",
          required_roles: result.group ? [result.group] : [],
          role_match: "any",
          oidc_client_id: result.client_id,
          oidc_scopes: result.scopes,
          oidc_callback_path: result.callback_path,
          oidc_logout_path: "/_lfp/auth/logout",
          oidc_session_key_file: "~/.secrets/lfp-pipe/oidc-session-key",
          oidc_session_ttl_seconds: 28800,
        });
        delete policy.oidc_client_secret_file;
      });
      setProvisioningOpen(false);
    } catch (cause) {
      setProvisioningError(cause instanceof Error ? cause.message : "Browser sign-in could not be provisioned.");
    } finally {
      setProvisioningBusy(false);
    }
  }

  return <div className="structured-config">
    {provisioning?.enabled && provisioning.can_manage && provisioning.provider ? <section className="identity-provisioning" aria-label="Identity provisioning">
      <div className="identity-provisioning-icon" aria-hidden="true"><KeyRound size={16} /></div>
      <div><strong>Browser sign-in</strong><span>{provisioning.provider.display_name} can provision OIDC access and groups for this machine.</span></div>
      <Button variant="default" size="xs" disabled={identityTargets.length === 0} onClick={() => void openIdentityProvisioning()}>Add sign-in</Button>
    </section> : null}
    <section className="config-root-section" aria-labelledby="common-settings-heading">
      <div className="config-section-heading">
        <div><h2 id="common-settings-heading">Machine defaults</h2><span>Inherited by every public route unless it has an override.</span></div>
      </div>
      <SimpleGrid cols={{ base: 1, sm: 3 }} spacing="sm">
        <LinkField label="Default backend" value={text(defaults.backend_addr)} hrefForValue={backendHref} onChange={(value) => setDefault("backend_addr", value)} hint="Bare port, :port for localhost, or host:port" />
        <LinkField label="Plain HTTP backend" value={text(defaults.http_backend_addr)} hrefForValue={backendHref} onChange={(value) => setOptionalDefault("http_backend_addr", value)} hint="Optional; accepts port, :port, or host:port" />
        <LinkField label="Backend Host override" value={text(defaults.backend_host)} hrefForValue={backendHref} onChange={(value) => setOptionalDefault("backend_host", value)} hint="Incoming Host is preserved by default" />
        <LinkField className="field-span-full" label="NATS URL" value={text(defaults.nats_url)} onChange={(value) => setDefault("nats_url", value)} required error={validationErrors["defaults.nats_url"]} />
      </SimpleGrid>
      <div className="authorization-policy">
        <div className="authorization-scope"><div><strong>Authentication</strong><span>Protect routes by default; each route and path can override this.</span></div><SegmentedControl className="inheritance-control" size="xs" value={defaultAuthorizationEnabled ? "on" : "off"} data={[{ value: "on", label: "On" }, { value: "off", label: "Off" }]} onChange={(value) => setDefaultAuthorizationEnabled(value === "on")} /></div>
        {defaultAuthorizationEnabled ? <AuthorizationDisclosure hasErrors={hasErrors(validationErrors, "defaults.authorization")}><AuthorizationFields authorization={authorization} errorPrefix="defaults.authorization" errors={validationErrors} onChange={setDefaultAuthorization} /></AuthorizationDisclosure> : null}
      </div>
      <Accordion className="settings-disclosure" variant="contained">
        <Accordion.Item value="advanced"><Accordion.Control>Advanced common settings</Accordion.Control><Accordion.Panel><Stack gap="lg">
          <SettingsGroup title="Transport">
            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
              <SelectField label="Relay mode" value={text(defaults.relay_mode) || "auto"} options={["auto", "buffered", "splice"]} onChange={(value) => setDefault("relay_mode", value)} />
              <NumberField label="Claim acknowledgement" suffix=" ms" value={number(defaults.claim_ack_timeout_ms, 1500)} onChange={(value) => setDefault("claim_ack_timeout_ms", value)} />
            </SimpleGrid>
            <div className="authorization-scope"><div><strong>TCP passthrough</strong><span>Allow non-HTTP connections to reach host backends.</span></div><SegmentedControl className="inheritance-control" size="xs" value={defaultTcpPassthrough ? "on" : "off"} data={[{ value: "on", label: "On" }, { value: "off", label: "Off" }]} onChange={(value) => setDefault("tcp_passthrough", value === "on")} /></div>
          </SettingsGroup>
          <SettingsGroup title="Identity">
            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
              <LinkField label="Token URL" value={text(oauth.token_url)} required={oauthConfigured} error={validationErrors["defaults.oauth.token_url"]} onChange={(value) => setOAuth("token_url", value)} />
              <TextField label="Provider client ID" value={text(oauth.provider_client_id)} required={oauthConfigured} error={validationErrors["defaults.oauth.provider_client_id"]} onChange={(value) => setOAuth("provider_client_id", value)} />
              <TextField label="Service username" value={text(oauth.username)} required={oauthConfigured} error={validationErrors["defaults.oauth.username"]} onChange={(value) => setOAuth("username", value)} />
              <TextField label="Secret file" value={text(oauth.client_secret_file)} required={oauthConfigured} error={validationErrors["defaults.oauth.client_secret_file"]} onChange={(value) => setOAuth("client_secret_file", value)} />
              <LinkField className="field-span-full" label="Control plane URL" value={text(oauth.control_plane_url)} required={oauthConfigured} error={validationErrors["defaults.oauth.control_plane_url"]} onChange={(value) => setOAuth("control_plane_url", value)} />
              <TextField className="field-span-full" label="Scopes" value={list(oauth.scopes)} onChange={(value) => setOAuth("scopes", splitList(value))} hint="Comma separated" />
            </SimpleGrid>
          </SettingsGroup>
          <SettingsGroup title="Certificates">
            <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
              <LinkField label="Contacts" value={list(acme.contacts)} onChange={(value) => setAcme("contacts", splitList(value))} hint="Comma separated mailto addresses" multiple />
              <TextField label="Cache directory" value={text(acme.cache_dir) || "~/.cache/lfp-pipe/acme"} onChange={(value) => setAcme("cache_dir", value)} />
            </SimpleGrid>
            <CheckboxField label="Use production ACME" checked={bool(acme.production)} onChange={(value) => setAcme("production", value)} />
          </SettingsGroup>
        </Stack></Accordion.Panel></Accordion.Item>
      </Accordion>
    </section>

    <section className="config-root-section routes-section" aria-labelledby="routes-heading">
      <div className="config-section-heading"><div><h2 id="routes-heading">Public routes</h2><span>{routes.length === 1 ? "1 registered hostname" : `${routes.length} registered hostnames`}</span></div><Button variant="light" leftSection={<Plus size={15} aria-hidden="true" />} type="button" onClick={() => { const nextIndex = routes.length; update((draft) => { const items = asRoutes(draft.routes); items.push({ client_id: `route-${items.length + 1}`, hostname: "", path_routes: [] }); draft.routes = items; }); revealEditor(`[data-route-index="${nextIndex}"]`); }}>Add route</Button></div>
      <div className="route-list">
        {routes.map((route, routeIndex) => <RouteEditor key={routeIndex} route={route} routeIndex={routeIndex} defaults={defaults} defaultTlsTermination={defaultTlsTermination} defaultAuthorization={authorization} defaultTcpPassthrough={defaultTcpPassthrough} validationErrors={validationErrors} setRoute={setRoute} setOptionalRoute={setOptionalRoute} setRouteTlsTermination={setRouteTlsTermination} setRouteAuthorization={setRouteAuthorization} setPath={setPath} setAuthorization={setAuthorization} update={update} />)}
        {routes.length === 0 ? <div className="routes-empty" data-config-error="true" tabIndex={-1}><strong>No routes</strong><span>{validationErrors.routes}</span></div> : null}
      </div>
    </section>
    <Modal opened={provisioningOpen} onClose={() => !provisioningBusy && setProvisioningOpen(false)} title="Add browser sign-in" size="md" centered>
      <div className="stack-form">
        <Select label="Protect" value={provisioningTarget} data={identityTargets} allowDeselect={false} onChange={(value) => value && setProvisioningTarget(value)} />
        <Autocomplete label="Required group" description="Leave blank to allow any signed-in user. Enter a new name to create the group." value={provisioningGroup} data={identityGroups.map((group) => group.name)} onChange={setProvisioningGroup} placeholder="Any signed-in user" />
        <p className="field-note">Pipe will create or update a public PKCE application in {provisioning?.provider?.display_name} and add the exact callback for this hostname.</p>
        {provisioningError ? <p className="inline-error" role="alert">{provisioningError}</p> : null}
        <Group justify="flex-end"><Button variant="default" disabled={provisioningBusy} onClick={() => setProvisioningOpen(false)}>Cancel</Button><Button loading={provisioningBusy} disabled={!provisioningTarget} onClick={() => void provisionIdentity()}>Add sign-in</Button></Group>
      </div>
    </Modal>
  </div>;
}

function SettingsGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return <div className="settings-group"><h3>{title}</h3>{children}</div>;
}

type RouteEditorProps = {
  route: Route; routeIndex: number;
  defaults: Table;
  defaultTlsTermination: boolean;
  defaultAuthorization: Table;
  defaultTcpPassthrough: boolean;
  validationErrors: ConfigValidationErrors;
  setRoute: (index: number, key: string, value: unknown) => void;
  setOptionalRoute: (index: number, key: string, value: string) => void;
  setRouteTlsTermination: (index: number, mode: InheritanceMode) => void;
  setRouteAuthorization: (route: number, key: string, value: unknown) => void;
  setPath: (route: number, path: number, key: string, value: unknown) => void;
  setAuthorization: (route: number, path: number, key: string, value: unknown) => void;
  update: (mutator: (draft: Table) => void) => void;
};

function RouteEditor({ route, routeIndex, defaults, defaultTlsTermination, defaultAuthorization, defaultTcpPassthrough, validationErrors, setRoute, setOptionalRoute, setRouteTlsTermination, setRouteAuthorization, setPath, setAuthorization, update }: RouteEditorProps) {
  const paths = asRoutes(route.path_routes) as PathRoute[];
  const routeAcme = asTable(route.acme);
  const routeAuthorization = asTable(route.authorization);
  const routeTlsMode = enabledMode(routeAcme);
  const routeAuth = authorizationState(defaultAuthorization, routeAuthorization);
  const routeTcpMode: InheritanceMode = route.tcp_passthrough === undefined ? "inherit" : bool(route.tcp_passthrough) ? "on" : "off";
  const routeTcpPassthrough = routeTcpMode === "inherit" ? defaultTcpPassthrough : routeTcpMode === "on";
  const inheritedAuthorization = { ...defaultAuthorization, ...routeAuthorization };
  const routeName = text(route.hostname) || `Route ${routeIndex + 1}`;
  const errorPrefix = `routes.${routeIndex}`;
  return <article className="route-config" data-route-index={routeIndex}>
    <div className="route-header"><div className="route-node" aria-hidden="true"><RouteIcon size={15} /></div><LinkField className="route-hostname" label="Public hostname" value={text(route.hostname)} defaultScheme="https://" onChange={(value) => setRoute(routeIndex, "hostname", value)} required error={validationErrors[`${errorPrefix}.hostname`]} /><ActionIcon type="button" color="red" variant="subtle" title={`Remove ${routeName}`} aria-label={`Remove ${routeName}`} onClick={() => update((draft) => { asRoutes(draft.routes).splice(routeIndex, 1); })}><Trash2 size={16} aria-hidden="true" /></ActionIcon></div>
    <div className="route-body">
      <SimpleGrid className="route-backends" cols={{ base: 1, sm: 3 }} spacing="sm">
        <LinkField label="Host backend" value={text(route.backend_addr)} placeholder={text(defaults.backend_addr)} hrefForValue={backendHref} onChange={(value) => setOptionalRoute(routeIndex, "backend_addr", value)} hint="Bare port, :port for localhost, or host:port" required={Boolean(validationErrors[`${errorPrefix}.backend_addr`])} error={validationErrors[`${errorPrefix}.backend_addr`]} />
        <LinkField label="Plain HTTP backend" value={text(route.http_backend_addr)} placeholder={text(defaults.http_backend_addr)} hrefForValue={backendHref} onChange={(value) => setOptionalRoute(routeIndex, "http_backend_addr", value)} hint="Optional; accepts port, :port, or host:port" />
        <LinkField label="Backend Host override" value={text(route.backend_host)} placeholder={text(defaults.backend_host)} hrefForValue={backendHref} onChange={(value) => setOptionalRoute(routeIndex, "backend_host", value)} hint="Incoming Host is preserved by default" />
      </SimpleGrid>
      <div className="route-policy-options">
        <InheritanceControl label="TLS" value={routeTlsMode} inherited={defaultTlsTermination ? "On" : "Off"} error={validationErrors[`${errorPrefix}.tls`]} onChange={(mode) => setRouteTlsTermination(routeIndex, mode)} />
        <InheritanceControl label="Authentication" value={routeAuth.mode} inherited={routeAuth.inherited ? "On" : "Off"} onChange={(mode) => update((draft) => setAuthorizationEnabled(asRoutes(draft.routes)[routeIndex], mode))} />
        <InheritanceControl label="TCP passthrough" value={routeTcpMode} inherited={defaultTcpPassthrough ? "On" : "Off"} onChange={(mode) => update((draft) => { const target = asRoutes(draft.routes)[routeIndex]; if (mode === "inherit") delete target.tcp_passthrough; else target.tcp_passthrough = mode === "on"; })} />
      </div>
      {routeAuth.enabled && routeTcpPassthrough ? <p className="route-policy-warning">TCP passthrough is on; non-HTTP traffic is not covered by authentication.</p> : null}
      {routeAuth.enabled ? <AuthorizationDisclosure hasErrors={hasErrors(validationErrors, `${errorPrefix}.authorization`)}>
        {routeAuth.mode === "inherit" ? <div className="inherited-policy"><span className="inheritance-dot" aria-hidden="true" />Authentication is inherited; methods and fields can still be overridden here.</div> : null}
        <AuthorizationFields authorization={routeAuthorization} inherited={defaultAuthorization} errorPrefix={`${errorPrefix}.authorization`} errors={validationErrors} linkBase={linkHref(text(route.hostname), "https://").replace(/\/+$/, "")} onChange={(key, value) => setRouteAuthorization(routeIndex, key, value)} />
      </AuthorizationDisclosure> : null}
      <div className="path-list-heading"><strong>Path rules</strong><Button type="button" variant="subtle" leftSection={<Plus size={14} aria-hidden="true" />} onClick={() => { const nextIndex = paths.length; update((draft) => { const routes = asRoutes(draft.routes); const pathRoutes = asRoutes(routes[routeIndex].path_routes); pathRoutes.push({ path_prefix: "/", backend_addr: "8080" }); routes[routeIndex].path_routes = pathRoutes; }); revealEditor(`[data-route-index="${routeIndex}"] [data-path-index="${nextIndex}"]`); }}>Add path</Button></div>
      {paths.length > 0 ? <div className="path-list">{paths.map((path, pathIndex) => <PathEditor key={pathIndex} path={path} publicHostname={text(route.hostname)} routeTlsMode={routeTlsMode} defaultTlsTermination={defaultTlsTermination} inheritedAuthorization={inheritedAuthorization} validationErrors={validationErrors} routeIndex={routeIndex} pathIndex={pathIndex} setRouteTlsTermination={setRouteTlsTermination} setPath={setPath} setAuthorization={setAuthorization} update={update} />)}</div> : <p className="route-inheritance">All paths use this host backend.</p>}
      <Accordion className="route-disclosure" variant="contained"><Accordion.Item value="route-options"><Accordion.Control>Advanced route settings</Accordion.Control><Accordion.Panel><Stack gap="sm">
        <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
          <TextField label="Client ID" value={text(route.client_id)} required error={validationErrors[`${errorPrefix}.client_id`]} onChange={(value) => setRoute(routeIndex, "client_id", value)} />
          <InheritanceControl label="Proxy headers" value={route.proxy_headers === undefined ? "inherit" : bool(route.proxy_headers) ? "on" : "off"} inherited={bool(defaults.proxy_headers, true) ? "On" : "Off"} onChange={(mode) => update((draft) => { const target = asRoutes(draft.routes)[routeIndex]; if (mode === "inherit") delete target.proxy_headers; else target.proxy_headers = mode === "on"; })} />
        </SimpleGrid>
      </Stack></Accordion.Panel></Accordion.Item></Accordion>
    </div>
  </article>;
}

type PathEditorProps = { path: PathRoute; publicHostname: string; routeTlsMode: InheritanceMode; defaultTlsTermination: boolean; inheritedAuthorization: Table; validationErrors: ConfigValidationErrors; routeIndex: number; pathIndex: number; setRouteTlsTermination: RouteEditorProps["setRouteTlsTermination"]; setPath: RouteEditorProps["setPath"]; setAuthorization: RouteEditorProps["setAuthorization"]; update: RouteEditorProps["update"] };

function PathEditor({ path, publicHostname, routeTlsMode, defaultTlsTermination, inheritedAuthorization, validationErrors, routeIndex, pathIndex, setRouteTlsTermination, setPath, setAuthorization, update }: PathEditorProps) {
  const authorization = asTable(path.authorization);
  const publicRouteUrl = linkHref(publicHostname, "https://").replace(/\/+$/, "");
  const pathAuth = authorizationState(inheritedAuthorization, authorization);
  const errorPrefix = `routes.${routeIndex}.path_routes.${pathIndex}`;
  const setAuthorizationMode = (mode: InheritanceMode) => update((draft) => {
    const target = asRoutes(asRoutes(draft.routes)[routeIndex].path_routes)[pathIndex];
    setAuthorizationEnabled(target, mode);
  });
  return <div className="path-config" data-path-index={pathIndex}>
    <div className="path-header"><strong>Path {pathIndex + 1}</strong><ActionIcon type="button" color="red" variant="subtle" title={`Remove path ${pathIndex + 1}`} aria-label={`Remove path ${pathIndex + 1}`} onClick={() => update((draft) => { asRoutes(asRoutes(draft.routes)[routeIndex].path_routes).splice(pathIndex, 1); })}><Trash2 size={15} aria-hidden="true" /></ActionIcon></div>
    <div className="path-fields"><LinkField className="path-field" label="Path" value={text(path.path_prefix)} defaultScheme={publicRouteUrl} required error={validationErrors[`${errorPrefix}.path_prefix`]} onChange={(value) => setPath(routeIndex, pathIndex, "path_prefix", value)} /><LinkField className="path-field" label="Backend" value={text(path.backend_addr)} hrefForValue={backendHref} required error={validationErrors[`${errorPrefix}.backend_addr`]} onChange={(value) => setPath(routeIndex, pathIndex, "backend_addr", value)} hint="Bare port, :port for localhost, or host:port" /><InheritanceControl label="TLS (hostname)" value={routeTlsMode} inherited={defaultTlsTermination ? "On" : "Off"} error={validationErrors[`${errorPrefix}.tls`]} onChange={(mode) => setRouteTlsTermination(routeIndex, mode)} /><InheritanceControl label="Authentication" value={pathAuth.mode} inherited={pathAuth.inherited ? "On" : "Off"} onChange={setAuthorizationMode} /></div>
    {pathAuth.enabled ? <AuthorizationDisclosure hasErrors={hasErrors(validationErrors, `${errorPrefix}.authorization`)}>
      {pathAuth.mode === "inherit" ? <div className="inherited-policy"><span className="inheritance-dot" aria-hidden="true" />Authentication is inherited; methods and fields can still be overridden here.</div> : null}
      <AuthorizationFields authorization={authorization} inherited={inheritedAuthorization} errorPrefix={`${errorPrefix}.authorization`} errors={validationErrors} linkBase={publicRouteUrl} onChange={(key, value) => setAuthorization(routeIndex, pathIndex, key, value)} />
    </AuthorizationDisclosure> : null}
    <Accordion className="route-disclosure path-disclosure" variant="contained"><Accordion.Item value="path-options"><Accordion.Control>Request options</Accordion.Control><Accordion.Panel><Stack gap="sm">
      <div className="request-options"><LinkField label="Backend Host header" value={text(path.backend_host)} hrefForValue={backendHref} onChange={(value) => setPath(routeIndex, pathIndex, "backend_host", value)} /><Group className="request-option-toggles" gap="xl"><CheckboxField label="Strip path prefix" checked={bool(path.strip_path_prefix)} onChange={(value) => setPath(routeIndex, pathIndex, "strip_path_prefix", value)} /><InheritanceControl label="Proxy headers" value={path.proxy_headers === undefined ? "inherit" : bool(path.proxy_headers) ? "on" : "off"} inherited="Route default" onChange={(mode) => update((draft) => { const target = asRoutes(asRoutes(draft.routes)[routeIndex].path_routes)[pathIndex]; if (mode === "inherit") delete target.proxy_headers; else target.proxy_headers = mode === "on"; })} /></Group></div>
    </Stack></Accordion.Panel></Accordion.Item></Accordion>
  </div>;
}

function AuthorizationDisclosure({ children, hasErrors: invalid }: { children: React.ReactNode; hasErrors: boolean }) {
  return <Accordion className="authorization-disclosure" variant="contained" defaultValue={invalid ? "authentication-options" : undefined}>
    <Accordion.Item value="authentication-options">
      <Accordion.Control><span>Authentication options</span>{invalid ? <span className="disclosure-error">Required fields missing</span> : null}</Accordion.Control>
      <Accordion.Panel><Stack gap="sm">{children}</Stack></Accordion.Panel>
    </Accordion.Item>
  </Accordion>;
}

type AuthorizationFieldsProps = { authorization: Table; inherited?: Table; linkBase?: string; errorPrefix: string; errors: ConfigValidationErrors; onChange: (key: string, value: unknown) => void };
function AuthorizationFields({ authorization, inherited = {}, linkBase = "", errorPrefix, errors, onChange }: AuthorizationFieldsProps) {
  const hasParent = Object.keys(inherited).length > 0;
  const resolved = { ...inherited, ...authorization };
  const bearerEnabled = resolved.bearer === undefined ? true : bool(resolved.bearer);
  const oidcEnabled = resolved.oidc === undefined ? Boolean(text(resolved.oidc_client_id)) : bool(resolved.oidc);
  const booleanField = (label: string, key: string, effective: boolean) => hasParent
    ? <InheritanceControl label={label} value={authorization[key] === undefined ? "inherit" : bool(authorization[key]) ? "on" : "off"} inherited={effective ? "On" : "Off"} onChange={(mode) => { if (mode === "inherit") onChange(key, undefined); else onChange(key, mode === "on"); }} />
    : <CheckboxField label={label} checked={effective} onChange={(value) => onChange(key, value)} />;
  const inheritedText = (key: string, fallback = "") => text(inherited[key]) || fallback;
  const inheritedList = (key: string, fallback = "") => list(inherited[key]) || fallback;

  return <div className="authorization-config">
    <div className="authorization-methods">{booleanField("Bearer tokens", "bearer", bearerEnabled)}{booleanField("Browser OIDC", "oidc", oidcEnabled)}</div>
    {errors[`${errorPrefix}.methods`] ? <p className="inline-field-error" role="alert" data-config-error="true" tabIndex={-1}>{errors[`${errorPrefix}.methods`]}</p> : null}
    <SimpleGrid cols={{ base: 1, sm: 2 }} spacing="sm">
      <LinkField className="field-span-full" label="Issuer" value={text(authorization.issuer)} placeholder={inheritedText("issuer")} required={Boolean(errors[`${errorPrefix}.issuer`])} error={errors[`${errorPrefix}.issuer`]} onChange={(value) => onChange("issuer", value)} />
      {bearerEnabled ? <TextField label="Audiences" value={list(authorization.audiences)} placeholder={inheritedList("audiences")} required={Boolean(errors[`${errorPrefix}.audiences`])} error={errors[`${errorPrefix}.audiences`]} onChange={(value) => onChange("audiences", splitList(value))} hint="Comma separated" /> : null}
      <TextField label="Required roles" value={list(authorization.required_roles)} placeholder={inheritedList("required_roles")} onChange={(value) => onChange("required_roles", splitList(value))} hint="Comma separated" />
      <TextField label="Roles claim" value={text(authorization.roles_claim)} placeholder={inheritedText("roles_claim", "groups")} onChange={(value) => onChange("roles_claim", value)} />
      <SelectField label="Role matching" value={text(resolved.role_match) || "any"} options={["any", "all"]} onChange={(value) => onChange("role_match", value)} />
      {bearerEnabled ? <LinkField className="field-span-full" label="JWKS URL" value={text(authorization.jwks_uri)} placeholder={inheritedText("jwks_uri")} onChange={(value) => onChange("jwks_uri", value)} /> : null}
      {bearerEnabled ? <TextField className="field-span-full" label="JWKS cache file" value={text(authorization.jwks_cache_file)} placeholder={inheritedText("jwks_cache_file", "~/.cache/lfp-pipe/auth/jwks.json")} onChange={(value) => onChange("jwks_cache_file", value)} /> : null}
      {oidcEnabled ? <TextField label="OIDC client ID" value={text(authorization.oidc_client_id)} placeholder={inheritedText("oidc_client_id")} required={Boolean(errors[`${errorPrefix}.oidc_client_id`])} error={errors[`${errorPrefix}.oidc_client_id`]} onChange={(value) => onChange("oidc_client_id", value)} /> : null}
      {oidcEnabled ? <TextField label="OIDC secret file (optional)" value={text(authorization.oidc_client_secret_file)} placeholder={inheritedText("oidc_client_secret_file")} onChange={(value) => onChange("oidc_client_secret_file", value)} hint="Only for confidential clients" /> : null}
      {oidcEnabled ? <TextField className="field-span-full" label="OIDC scopes" value={list(authorization.oidc_scopes)} placeholder={inheritedList("oidc_scopes", "openid, profile, email, groups")} required={Boolean(errors[`${errorPrefix}.oidc_scopes`])} error={errors[`${errorPrefix}.oidc_scopes`]} onChange={(value) => onChange("oidc_scopes", splitList(value))} hint="Comma separated" /> : null}
      {oidcEnabled ? <LinkField label="Callback path" value={text(authorization.oidc_callback_path)} placeholder={inheritedText("oidc_callback_path", "/_lfp/auth/callback")} defaultScheme={linkBase} error={errors[`${errorPrefix}.oidc_callback_path`]} onChange={(value) => onChange("oidc_callback_path", value)} /> : null}
      {oidcEnabled ? <LinkField label="Logout path" value={text(authorization.oidc_logout_path)} placeholder={inheritedText("oidc_logout_path", "/_lfp/auth/logout")} defaultScheme={linkBase} error={errors[`${errorPrefix}.oidc_logout_path`]} onChange={(value) => onChange("oidc_logout_path", value)} /> : null}
      {oidcEnabled ? <TextField label="Session key file" value={text(authorization.oidc_session_key_file)} placeholder={inheritedText("oidc_session_key_file", "~/.secrets/lfp-pipe/oidc-session-key")} onChange={(value) => onChange("oidc_session_key_file", value)} /> : null}
      {oidcEnabled ? <NumberField label="Session lifetime" suffix=" s" value={number(authorization.oidc_session_ttl_seconds, number(inherited.oidc_session_ttl_seconds, 28800))} onChange={(value) => onChange("oidc_session_ttl_seconds", value)} /> : null}
    </SimpleGrid>
    {bearerEnabled ? booleanField("Forward Authorization header", "forward_authorization", bool(resolved.forward_authorization)) : null}
  </div>;
}

function InheritanceControl({ label, value, inherited, error, onChange }: { label: string; value: InheritanceMode; inherited: string; error?: string; onChange: (value: InheritanceMode) => void }) {
  return <div className="inheritance-field" data-config-error={error ? "true" : undefined} tabIndex={error ? -1 : undefined}><span className="inheritance-label">{label}</span><SegmentedControl className="inheritance-control" size="xs" value={value} data={[{ value: "inherit", label: "Inherit" }, { value: "on", label: "On" }, { value: "off", label: "Off" }]} onChange={(next) => onChange(next as InheritanceMode)} /><span className={error ? "inline-field-error" : "inheritance-value"}>{error || (value === "inherit" ? `Inherited: ${inherited}` : "Explicit override")}</span></div>;
}

type TextFieldProps = { label: string; value: string; onChange: (value: string) => void; hint?: string; className?: string; placeholder?: string; required?: boolean; error?: string };
function TextField({ onChange, hint, label, error, ...props }: TextFieldProps) { return <TextInput {...props} label={label} error={error} name={label.toLowerCase().replace(/[^a-z0-9]+/g, "-")} autoComplete="off" autoCapitalize="none" autoCorrect="off" spellCheck={false} data-config-error={error ? "true" : undefined} data-1p-ignore="true" data-lpignore="true" data-bwignore="true" data-form-type="other" description={hint} size="xs" onChange={(event) => onChange(event.currentTarget.value)} />; }
function LinkField({ label, value, onChange, hint, className, placeholder, required, error, defaultScheme = "", multiple = false, hrefForValue }: TextFieldProps & { defaultScheme?: string; multiple?: boolean; hrefForValue?: (value: string) => string }) {
  const effectiveValue = value.trim() || placeholder?.trim() || "";
  const values = multiple ? splitList(effectiveValue) : [effectiveValue];
  const links = values.map((item) => ({ label: item, href: hrefForValue ? hrefForValue(item) : linkHref(item, defaultScheme) })).filter((item) => item.href);

  return <div className={`editable-link-field${className ? ` ${className}` : ""}`}>
    <div className="link-input-row">
      <div className="link-open-actions">
        {links.length > 0 ? links.map((item) => <a className="link-open-icon" key={`${item.href}-${item.label}`} href={item.href} target="_blank" rel="noreferrer noopener" title={`Open ${item.label}`} aria-label={`Open ${label}: ${item.label}`}><ExternalLink size={14} aria-hidden="true" /></a>) : <span className="link-open-placeholder" aria-hidden="true" />}
      </div>
      <TextField label={label} value={value} placeholder={placeholder} required={required} error={error} onChange={onChange} hint={hint} />
    </div>
  </div>;
}
function NumberField({ label, value, suffix, onChange }: { label: string; value: number; suffix?: string; onChange: (value: number) => void }) { return <NumberInput label={label} value={value} suffix={suffix} size="xs" min={0} onChange={(next) => onChange(Number(next) || 0)} />; }
function SelectField({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) { return <Select label={label} value={value} data={options} size="xs" allowDeselect={false} onChange={(next) => next !== null && onChange(next)} />; }
function CheckboxField({ label, checked, onChange }: { label: string; checked: boolean; onChange: (value: boolean) => void }) {
  return <label className="checkbox-field" data-checked={checked || undefined}>
    <input type="checkbox" checked={checked} onChange={(event) => onChange(event.currentTarget.checked)} />
    <span className="checkbox-mark" aria-hidden="true">{checked ? <Check size={14} strokeWidth={3} /> : null}</span>
    <span>{label}</span>
  </label>;
}
