use crate::config::BackendRule;

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

pub fn select_backend<'a>(rules: &'a [BackendRule], hostname: Option<&str>) -> Option<&'a BackendRule> {
    rules
        .iter()
        .find(|rule| matches_pattern(&rule.pattern, hostname))
}

#[cfg(test)]
mod tests {
    use super::{matches_pattern, select_backend};
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
                backend_addr: "127.0.0.1:8443".to_string(),
            },
            BackendRule {
                pattern: "other.example.com".to_string(),
                backend_addr: "127.0.0.1:9443".to_string(),
            },
        ];

        let selected = select_backend(&rules, Some("foo.example.com")).expect("match");
        assert_eq!(selected.backend_addr, "127.0.0.1:8443");
    }

    #[test]
    fn empty_pattern_matches_default_route_only() {
        assert!(matches_pattern("", None));
        assert!(!matches_pattern("", Some("example.com")));
    }
}
