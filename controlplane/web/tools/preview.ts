import { extname, join, normalize } from "node:path";

const port = Number(process.env.LFP_PREVIEW_PORT ?? "4173");
const root = join(import.meta.dir, "..", "dist");
const demoUsername = "lfp-pipe-regbodesktop-b9e13326";
const demoPrincipal = { id: 101, username: demoUsername, name: "REGBODESKTOP · live demo", client_id: "demo-regbodesktop", entitlement: "regbodesktop.pipe.lfpconnect.io" };
let demoLastSeen = 0;
let demoDevice = { name: "REGBODESKTOP", version: "", platform: "" };
const encoder = new TextEncoder();
const configs = new Map<number, string>([
  [101, `[defaults]
nats_url = "tls://nats-pipe.lfpconnect.io:443"
backend_addr = "127.0.0.1:443"
http_backend_addr = "127.0.0.1:80"

[defaults.acme]
contacts = ["mailto:reggie.pierce@gmail.com"]
cache_dir = "~/.cache/lfp-pipe/acme"
production = true

[defaults.oauth]
token_url = "https://auth.lfpconnect.io/application/o/token/"
provider_client_id = "lfp-pipe"
username = "${demoUsername}"
client_secret_file = "__central__"
control_plane_url = "http://127.0.0.1:4173"

[[routes]]
client_id = "demo-regbodesktop"
hostname = "demo.regbodesktop.pipe.lfpconnect.io"

[[routes.path_routes]]
path_prefix = "/api"
strip_path_prefix = true
backend_addr = "127.0.0.1:8081"
backend_host = "127.0.0.1:8081"

[routes.path_routes.authorization]
issuer = "https://auth.lfpconnect.io/application/o/lfp-pipe/"
audiences = ["lfp-pipe"]
jwks_uri = "https://auth.lfpconnect.io/application/o/lfp-pipe/jwks/"
jwks_cache_file = "~/.cache/lfp-pipe/auth/jwks.json"
roles_claim = "roles"
required_roles = ["service-user"]
role_match = "any"
algorithms = ["RS256"]
jwks_refresh_seconds = 3600
jwks_max_stale_seconds = 604800
forward_authorization = false
`],
]);
const principals = [demoPrincipal];

const json = (value: unknown, status = 200) => Response.json(value, { status });
const bearer = (request: Request) => request.headers.get("authorization") ?? "";
const managedClients = () => ({ managed_clients: demoLastSeen ? [{ username: demoUsername, ...demoDevice, last_seen: new Date(demoLastSeen).toISOString(), online: Date.now() - demoLastSeen < 45000, presence_known: true }] : [{ username: demoUsername, ...demoDevice, last_seen: "", online: false, presence_known: false }] });

Bun.serve({
  hostname: "127.0.0.1",
  port,
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === "/api/branding") return json({ name: "LFP Connect", logo_url: "/assets/lfp-connect-auto.svg", favicon_url: "/assets/lfp-favicon.svg", color: "#ff6f61", color_strong: "#e85c50", ink: "#0b1426" });
    if (url.pathname === "/api/me") return json({ subject: "preview-user", name: "Local Preview", email: "preview@lfpconnect.io", entitlements: ["regbodesktop.pipe.lfpconnect.io", "speedtest.pipe.lfpconnect.io"], required_entitlement: "pipe.lfpconnect.io", route_pattern: "*.pipe.lfpconnect.io", control_plane_url: "https://manage-pipe.lfpconnect.io" });
    if (url.pathname === "/api/service-principals" && request.method === "GET") return json({ service_principals: principals });
    if (url.pathname === "/api/managed-clients") return json(managedClients());
    if (url.pathname === "/api/managed-client-events") {
      let timer: ReturnType<typeof setInterval>;
      let connectTimer: ReturnType<typeof setTimeout>;
      const stream = new ReadableStream<Uint8Array>({ start(controller) { const send = (payload: object) => controller.enqueue(encoder.encode(`event: presence\ndata: ${JSON.stringify(payload)}\n\n`)); const online = () => ({ managed_clients: [{ username: demoUsername, ...demoDevice, last_seen: new Date().toISOString(), online: true, presence_known: true }] }); send(managedClients()); connectTimer = setTimeout(() => send(online()), 2000); timer = setInterval(() => send(online()), 5000); }, cancel() { clearTimeout(connectTimer); clearInterval(timer); } });
      return new Response(stream, { headers: { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" } });
    }
    if (url.pathname === "/api/enrollments") return json({ enrollments: [] });
    if (url.pathname === "/api/client-settings") return json({ token_url: "https://auth.lfpconnect.io/application/o/token/", provider_client_id: "lfp-pipe", scopes: ["openid", "profile", "entitlements"] });
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
      const response = await fetch("https://manage-pipe.lfpconnect.io/api/tunnel-tokens", { method: "POST", headers: { "Authorization": bearer(request), "Content-Type": "application/json" }, body: await request.text() });
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
