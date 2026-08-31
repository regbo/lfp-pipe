const URI_SCHEME = /^[a-z][a-z0-9+.-]*:/i;
const NON_BROWSER_SCHEME = /^tls:/i;
const BARE_PORT = /^\d+$/;
const LOCAL_PORT = /^:\d+$/;
const HOST_AND_PORT = /^(?:\[[^\]]+\]|[^:/\s]+):\d+$/;

export function linkHref(value: string, defaultScheme = "") {
  const trimmed = value.trim();
  if (!trimmed) return "";
  if (NON_BROWSER_SCHEME.test(trimmed)) return "";
  if (URI_SCHEME.test(trimmed)) return trimmed;
  return defaultScheme ? `${defaultScheme}${trimmed}` : "";
}

export function backendHref(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return "";
  if (BARE_PORT.test(trimmed)) return `http://127.0.0.1:${trimmed}`;
  if (LOCAL_PORT.test(trimmed)) return `http://127.0.0.1${trimmed}`;
  if (HOST_AND_PORT.test(trimmed)) return `http://${trimmed}`;
  return linkHref(trimmed, "http://");
}
