const URI_SCHEME = /^[a-z][a-z0-9+.-]*:/i;

export function linkHref(value: string, defaultScheme = "") {
  const trimmed = value.trim();
  if (!trimmed) return "";
  if (URI_SCHEME.test(trimmed)) return trimmed;
  return defaultScheme ? `${defaultScheme}${trimmed}` : "";
}
