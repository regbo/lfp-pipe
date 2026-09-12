import { describe, expect, test } from "bun:test";
import { validateConfigToml } from "../src/config-editor";

describe("browser configuration validation", () => {
  test("accepts a complete authenticated host route without a path", () => {
    const errors = validateConfigToml(`
[defaults]
nats_url = "tls://nats-pipe.example.com:443"
backend_addr = "127.0.0.1:8080"
tcp_passthrough = false

[defaults.acme]
enabled = true

[defaults.authorization]
enabled = true
bearer = true
oidc = false
issuer = "https://auth.example.com/application/o/pipe/"
audiences = ["pipe-api"]

[[routes]]
client_id = "home"
hostname = "home.pipe.example.com"
`);

    expect(errors).toEqual({});
  });

  test("requires the same route and bearer fields as the Rust client", () => {
    const errors = validateConfigToml(`
[defaults.authorization]
enabled = true
bearer = true
oidc = false

[[routes]]
client_id = ""
hostname = ""
`);

    expect(errors["defaults.nats_url"]).toBeTruthy();
    expect(errors["defaults.authorization.issuer"]).toBeTruthy();
    expect(errors["defaults.authorization.audiences"]).toBeTruthy();
    expect(errors["routes.0.client_id"]).toBeTruthy();
    expect(errors["routes.0.hostname"]).toBeTruthy();
    expect(errors["routes.0.backend_addr"]).toBeTruthy();
    expect(errors["routes.0.tls"]).toBeTruthy();
  });

  test("requires TLS and unique valid prefixes for path routing", () => {
    const errors = validateConfigToml(`
[defaults]
nats_url = "nats://127.0.0.1:4222"
backend_addr = "127.0.0.1:8080"

[[routes]]
client_id = "home"
hostname = "home.pipe.example.com"

[[routes.path_routes]]
path_prefix = "/api"
backend_addr = "127.0.0.1:8081"

[[routes.path_routes]]
path_prefix = "/api"
backend_addr = "127.0.0.1:8082"
`);

    expect(errors["routes.0.path_routes.0.tls"]).toBeTruthy();
    expect(errors["routes.0.path_routes.0.path_prefix"]).toContain("duplicated");
    expect(errors["routes.0.path_routes.1.path_prefix"]).toContain("duplicated");
  });
});
