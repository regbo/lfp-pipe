import { extname, join, normalize } from "node:path";

const port = Number(process.env.LFP_PREVIEW_PORT ?? "4173");
const root = join(import.meta.dir, "..", "dist");
const demoUsername = "lfp-pipe-regbodesktop-b9e13326";
const demoPrincipal = { id: 101, username: demoUsername, name: "DESKTOP · live demo", client_id: "demo-desktop", entitlement: "desktop.pipe.example.com" };
let demoLastSeen = 0;
let demoDevice = { name: "REGBODESKTOP", version: "", platform: "" };
const encoder = new TextEncoder();
const configs = new Map<number, string>([
  [101, `[defaults]
nats_url = "tls://nats-pipe.example.com:443"
backend_addr = "127.0.0.1:443"
http_backend_addr = "127.0.0.1:80"

[defaults.acme]
contacts = ["mailto:reggie.pierce@gmail.com"]
cache_dir = "~/.cache/lfp-pipe/acme"
production = true

[defaults.oauth]
token_url = "https://auth.example.com/application/o/token/"
provider_client_id = "lfp-pipe"
username = "${demoUsername}"
client_secret_file = "__central__"
control_plane_url = "http://127.0.0.1:4173"

[defaults.authorization]
bearer = true
oidc = false
issuer = "https://auth.example.com/application/o/lfp-pipe/"
audiences = ["lfp-pipe"]
jwks_uri = "https://auth.example.com/application/o/lfp-pipe/jwks/"
jwks_cache_file = "~/.cache/lfp-pipe/auth/jwks.json"
roles_claim = "roles"
required_roles = ["service-user"]
role_match = "any"
algorithms = ["RS256"]
jwks_refresh_seconds = 3600
jwks_max_stale_seconds = 604800
forward_authorization = false

[[routes]]
client_id = "demo-regbodesktop"
hostname = "demo.desktop.pipe.example.com"

[[routes.path_routes]]
path_prefix = "/api"
strip_path_prefix = true
backend_addr = "127.0.0.1:8081"
backend_host = "127.0.0.1:8081"
`],
]);
const principals = [demoPrincipal];

const json = (value: unknown, status = 200) => Response.json(value, { status });
const bearer = (request: Request) => request.headers.get("authorization") ?? "";
const configState = { applied_config_revision: "demo", desired_config_revision: "demo", config_synced: true };
const managedClients = () => ({ managed_clients: demoLastSeen ? [{ username: demoUsername, ...demoDevice, ...configState, last_seen: new Date(demoLastSeen).toISOString(), online: Date.now() - demoLastSeen < 45000, presence_known: true }] : [{ username: demoUsername, ...demoDevice, ...configState, last_seen: "", online: false, presence_known: false }] });

Bun.serve({
  hostname: "127.0.0.1",
  port,
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/api/branding") return json({ name: "LFP Pipe", logo_url: "/assets/lfp-coral.svg", wordmark: "pipe", favicon_url: "/assets/lfp-favicon.svg", color: "#ff6f61", color_strong: "#e85c50", ink: "#0b1426" });
    if (url.pathname === "/api/me") return json({ subject: "preview-user", name: "Local Preview", email: "preview@example.com", entitlements: ["desktop.pipe.example.com", "speedtest.pipe.example.com"], required_entitlement: "pipe.example.com", route_pattern: "*.pipe.example.com", control_plane_url: "https://pipe.example.com" });
    if (url.pathname === "/api/identity-provisioning") return json({ enabled: true, can_manage: true, provider: { id: "authentik", display_name: "Authentik", capabilities: ["applications", "groups", "oidc"] } });
    if (url.pathname === "/api/identity-provisioning/groups") return json({ groups: [{ id: "admins", name: "Pipe admins" }, { id: "users", name: "Pipe users" }] });
    if (/^\/api\/service-principals\/\d+\/identity-applications$/.test(url.pathname) && request.method === "POST") {
      const body = await request.json() as { hostname: string; callback_path: string; group: string };
      return json({ provider_id: "authentik", application: "LFP Pipe routes", issuer: "https://auth.example.com/application/o/lfp-pipe-routes/", client_id: "lfp-pipe-routes", scopes: ["openid", "profile", "email"], callback_path: body.callback_path, callback_url: `https://${body.hostname}${body.callback_path}`, group: body.group, created_objects: ["redirect_uri"] });
    }
    if (url.pathname === "/api/service-principals" && request.method === "GET") return json({ service_principals: principals });
    if (url.pathname === "/api/managed-clients") return json(managedClients());
    if (url.pathname === "/api/managed-client-events") {
      let timer: ReturnType<typeof setInterval>;
      let connectTimer: ReturnType<typeof setTimeout>;
      const stream = new ReadableStream<Uint8Array>({ start(controller) { const send = (payload: object) => controller.enqueue(encoder.encode(`event: presence\ndata: ${JSON.stringify(payload)}\n\n`)); const online = () => ({ managed_clients: [{ username: demoUsername, ...demoDevice, ...configState, last_seen: new Date().toISOString(), online: true, presence_known: true }] }); send(managedClients()); connectTimer = setTimeout(() => send(online()), 2000); timer = setInterval(() => send(online()), 5000); }, cancel() { clearTimeout(connectTimer); clearInterval(timer); } });
      return new Response(stream, { headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" } });
    }
    if (url.pathname === "/api/enrollments") return json({ enrollments: [] });
    if (url.pathname === "/api/client-settings") return json({ token_url: "https://auth.example.com/application/o/token/", provider_client_id: "lfp-pipe", scopes: ["openid", "profile", "entitlements"] });
    if (url.pathname === "/api/client-config") {
      if (!bearer(request).startsWith("Bearer ")) return json({ error: "machine token required" }, 401);
      demoDevice = { name: request.headers.get("X-LFP-Pipe-Device") || "REGBODESKTOP", version: request.headers.get("X-LFP-Pipe-Version") || "", platform: request.headers.get("X-LFP-Pipe-Platform") || "" };
      return json({ config_toml: configs.get(101), username: demoUsername });
    }
    if (url.pathname === "/api/client-events") {
      if (!bearer(request).startsWith("Bearer ")) return json({ error: "machine token required" }, 401);
      demoDevice = { name: request.headers.get("X-LFP-Pipe-Device") || "REGBODESKTOP", version: request.headers.get("X-LFP-Pipe-Version") || "", platform: request.headers.get("X-LFP-Pipe-Platform") || "" };
      demoLastSeen = Date.now();
      let timer: ReturnType<typeof setInterval>;
      const stream = new ReadableStream<Uint8Array>({ start(controller) { controller.enqueue(encoder.encode("event: ready\ndata: connected\n\n")); timer = setInterval(() => { demoLastSeen = Date.now(); controller.enqueue(encoder.encode(": keepalive\n\n")); }, 10000); }, cancel() { clearInterval(timer); } });
      return new Response(stream, { headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" } });
    }
    if (url.pathname === "/api/tunnel-tokens" && request.method === "POST") {
      const response = await fetch("https://pipe.example.com/api/tunnel-tokens", { method: "POST", headers: { "Authorization": bearer(request), "Content-Type": "application/json" }, body: await request.text() });
      return new Response(response.body, { status: response.status, headers: { "Content-Type": response.headers.get("content-type") ?? "application/json" } });
    }
    const match = url.pathname.match(/^\/api\/service-principals\/(\d+)\/config$/);
    if (match) {
      const id = Number(match[1]);
      if (request.method === "GET") return json({ config_toml: configs.get(id) ?? "" });
      if (request.method === "PUT") { const body = await request.json() as { config_toml: string }; configs.set(id, body.config_toml); return json(body); }
    }
    if (url.pathname.startsWith("/api/")) return json({ error: "This action is disabled in local preview." }, 400);

    const requested = normalize(url.pathname === "/" ? "index.html" : url.pathname.slice(1));
    const file = Bun.file(join(root, requested));
    if (await file.exists()) return new Response(file, { headers: { "Content-Type": file.type || (extname(requested) === ".svg" ? "image/svg+xml" : "application/octet-stream") } });
    return new Response(Bun.file(join(root, "index.html")));
  },
});
console.log(`LFP Pipe management preview: http://127.0.0.1:${port}`);
