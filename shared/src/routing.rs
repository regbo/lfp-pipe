//! Ordered hostname matching for private backend selection.

use crate::config::BackendRule;

/// Build a hostname-specific subject by reversing its DNS labels.
pub fn hostname_request_subject(prefix: &str, hostname: &str) -> Option<String> {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = hostname.split('.').collect();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return None;
    }
    Some(format!(
        "{}.{}",
        prefix.trim_end_matches('.'),
        labels.into_iter().rev().collect::<Vec<_>>().join(".")
    ))
}

/// Test an exact, wildcard, or default pattern against a detected hostname.
pub fn matches_pattern(pattern: &str, hostname: Option<&str>) -> bool {
    if pattern.is_empty() {
        return hostname.is_none();
    }

    let Some(hostname) = hostname else {
        return false;
    };

    if let Some(rest) = pattern.strip_prefix("*.") {
        return hostname.ends_with(rest)
            && hostname.len() > rest.len()
            && hostname.as_bytes()[hostname.len() - rest.len() - 1] == b'.';
    }

    pattern.eq_ignore_ascii_case(hostname)
}

/// Return the first backend rule matching the detected hostname.
pub fn select_backend<'a>(
    rules: &'a [BackendRule],
    hostname: Option<&str>,
) -> Option<&'a BackendRule> {
    rules
        .iter()
        .find(|rule| matches_pattern(&rule.pattern, hostname))
}

/// Return all rules belonging to a detected hostname.
pub fn matching_backends<'a>(
    rules: &'a [BackendRule],
    hostname: Option<&str>,
) -> Vec<&'a BackendRule> {
    rules
        .iter()
        .filter(|rule| matches_pattern(&rule.pattern, hostname))
        .collect()
}

/// Match an HTTP request path on a URL-segment boundary.
pub fn matches_path_prefix(prefix: &str, path: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    let prefix = prefix.trim_end_matches('/');
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Select the most-specific path rule, falling back to the hostname-only rule.
pub fn select_backend_for_path<'a>(
    rules: &'a [BackendRule],
    hostname: Option<&str>,
    path: &str,
) -> Option<&'a BackendRule> {
    rules
        .iter()
        .filter(|rule| {
            matches_pattern(&rule.pattern, hostname)
                && rule
                    .path_prefix
                    .as_deref()
                    .is_some_and(|prefix| matches_path_prefix(prefix, path))
        })
        .max_by_key(|rule| rule.path_prefix.as_ref().map_or(0, String::len))
        .or_else(|| {
            rules
                .iter()
                .find(|rule| rule.path_prefix.is_none() && matches_pattern(&rule.pattern, hostname))
        })
}

#[cfg(test)]
mod tests {
    use super::{
        hostname_request_subject, matches_path_prefix, matches_pattern, select_backend,
        select_backend_for_path,
    };
    use crate::config::BackendRule;

    #[test]
    fn exact_match_is_case_insensitive() {
        assert!(matches_pattern("Api.Example.com", Some("api.example.com")));
    }

    #[test]
    fn wildcard_requires_subdomain() {
        assert!(matches_pattern("*.example.com", Some("foo.example.com")));
        assert!(!matches_pattern("*.example.com", Some("example.com")));
    }

    #[test]
    fn select_backend_returns_first_match() {
        let rules = vec![
            BackendRule {
                pattern: "*.example.com".to_string(),
                path_prefix: None,
                strip_path_prefix: false,
                backend_addr: "127.0.0.1:8443".to_string(),
                backend_host: None,
                http_backend_addr: None,
                authorization: None,
            },
            BackendRule {
                pattern: "other.example.com".to_string(),
                path_prefix: None,
                strip_path_prefix: false,
                backend_addr: "127.0.0.1:9443".to_string(),
                backend_host: None,
                http_backend_addr: None,
                authorization: None,
            },
        ];

        let selected = select_backend(&rules, Some("foo.example.com")).expect("match");
        assert_eq!(selected.backend_addr, "127.0.0.1:8443");
    }

    #[test]
    fn path_prefix_requires_a_segment_boundary() {
        assert!(matches_path_prefix("/ollama", "/ollama/api/tags"));
        assert!(matches_path_prefix("/ollama", "/ollama"));
        assert!(!matches_path_prefix("/ollama", "/ollama-other"));
    }

    #[test]
    fn most_specific_path_backend_wins() {
        let rules = vec![
            BackendRule {
                pattern: "models.example.com".into(),
                path_prefix: None,
                strip_path_prefix: false,
                backend_addr: ":8000".into(),
                backend_host: None,
                http_backend_addr: None,
                authorization: None,
            },
            BackendRule {
                pattern: "models.example.com".into(),
                path_prefix: Some("/ollama".into()),
                strip_path_prefix: true,
                backend_addr: ":11434".into(),
                backend_host: None,
                http_backend_addr: None,
                authorization: None,
            },
        ];
        let selected =
            select_backend_for_path(&rules, Some("models.example.com"), "/ollama/api/tags")
                .expect("path backend");
        assert_eq!(selected.backend_addr, ":11434");
    }

    #[test]
    fn empty_pattern_matches_default_route_only() {
        assert!(matches_pattern("", None));
        assert!(!matches_pattern("", Some("example.com")));
    }

    #[test]
    fn hostname_subject_reverses_dns_labels() {
        assert_eq!(
            hostname_request_subject("lfp.v1.connect", "Cool.Subdomain.Domain."),
            Some("lfp.v1.connect.domain.subdomain.cool".to_string())
        );
        assert_eq!(
            hostname_request_subject("lfp.v1.connect", "bad.*.test"),
            None
        );
    }
}
