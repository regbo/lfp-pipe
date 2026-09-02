import { parse } from "smol-toml";

export type Identity = {
  subject: string;
  name: string;
  email: string;
  entitlements: string[];
  required_entitlement: string;
  route_pattern: string;
  control_plane_url: string;
};

export type IdentityProvider = {
  id: string;
  display_name: string;
  capabilities: string[];
};

export type IdentityProvisioningStatus = {
  enabled: boolean;
  can_manage: boolean;
  provider?: IdentityProvider;
};

export type IdentityGroup = {
  id: string;
  name: string;
};

export type IdentityApplication = {
  provider_id: string;
  application: string;
  issuer: string;
  client_id: string;
  scopes: string[];
  callback_path: string;
  callback_url: string;
  group?: string;
  created_objects: string[];
};

export type TunnelToken = {
  token: string;
  expires_at: string;
  hostname: string;
  client_id: string;
  request_subject: string;
  nats_urls: string[];
};

export type ServicePrincipal = {
  id: number;
  username: string;
  name: string;
  client_id: string;
  entitlement: string;
};

export type OAuthSettings = {
  token_url: string;
  client_id: string;
  control_plane_url: string;
  scopes: string[];
  nats_urls: string[];
};

export type CreatedPrincipal = {
  service_principal: ServicePrincipal;
  client_secret: string;
  oauth: OAuthSettings;
};

export type ManagedClient = {
  username: string;
  name: string;
  version: string;
  platform: string;
  applied_config_revision: string;
  desired_config_revision: string;
  config_synced: boolean;
  last_seen: string;
  online: boolean;
  presence_known: boolean;
};

export type Enrollment = {
  code: string;
  device_id: string;
  name: string;
  platform: string;
  version: string;
  expires_at: string;
};

export type ConsolePage = "machines" | "routes" | "access" | "keys" | "settings";
export type CreationMode = "access" | "temporary" | null;
export type MachineFilter = "all" | "online" | "offline" | "pending";

export type RouteSummary = {
  principal: ServicePrincipal;
  hostname: string;
  backend: string;
  httpBackend: string;
  tls: boolean;
  paths: PathSummary[];
};

export type PathSummary = {
  path: string;
  backend: string;
  protected: boolean;
  methods: string[];
  roles: string[];
};

type ConfigTable = Record<string, unknown>;

export function normalizeEntitlement(value: string) {
  return value.startsWith("route:") ? value.slice(6) : value;
}

function object(value: unknown): ConfigTable {
  return value && typeof value === "object" && !Array.isArray(value) ? value as ConfigTable : {};
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function string(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export function configRoutes(principal: ServicePrincipal, toml: string): RouteSummary[] {
  try {
    const document = object(parse(toml));
    const defaults = object(document.defaults);
    const defaultAcme = object(defaults.acme);
    const defaultAuthorization = object(defaults.authorization);
    const defaultTls = Object.keys(defaultAcme).length > 0 && defaultAcme.enabled !== false;
    return list(document.routes).map((value) => {
      const route = object(value);
      const routeAcme = object(route.acme);
      const routeAuthorization = object(route.authorization);
      const inheritedAuthorization = Object.keys(routeAuthorization).length > 0 ? routeAuthorization : defaultAuthorization;
      const tls = routeAcme.enabled === undefined ? defaultTls : routeAcme.enabled !== false;
      const paths = list(route.path_routes).map((pathValue) => {
        const path = object(pathValue);
        const authorization = object(path.authorization);
        const resolvedAuthorization = { ...inheritedAuthorization, ...authorization };
        const protectedPath = (Object.keys(inheritedAuthorization).length > 0 || Object.keys(authorization).length > 0) && resolvedAuthorization.enabled !== false;
        return {
          path: string(path.path_prefix) || "/",
          backend: string(path.backend_addr) || string(route.http_backend_addr) || string(defaults.http_backend_addr),
          protected: protectedPath,
          methods: protectedPath
            ? [resolvedAuthorization.bearer === false ? "" : "Bearer", resolvedAuthorization.oidc ? "OIDC" : ""].filter(Boolean)
            : [],
          roles: strings(resolvedAuthorization.required_roles),
        };
      });
      return {
        principal,
        hostname: string(route.hostname),
        backend: string(route.backend_addr) || string(defaults.backend_addr),
        httpBackend: string(route.http_backend_addr) || string(defaults.http_backend_addr),
        tls,
        paths,
      };
    });
  } catch {
    return [];
  }
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, { credentials: "same-origin", ...init });
  if (response.status === 401) {
    window.location.replace("/api/auth/login");
    throw new Error("Authentication required.");
  }
  const body = response.status === 204 ? undefined : await response.json();
  if (!response.ok) throw new Error(body?.error ?? "Request failed.");
  return body as T;
}

export function lastSeen(client: ManagedClient) {
  if (!client.presence_known) return "Checking";
  if (client.online) return "Now";
  if (!client.last_seen) return "Never";
  const value = new Date(client.last_seen);
  if (Number.isNaN(value.getTime())) return client.last_seen;
  return value.toLocaleString([], { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

export function clientStatus(client: ManagedClient) {
  if (!client.presence_known) return "Checking";
  if (!client.online) return "Offline";
  return client.config_synced ? "Connected" : "Updating configuration";
}
