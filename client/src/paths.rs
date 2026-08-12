//! Cross-platform expansion for user-relative configuration paths.

use std::path::{Path, PathBuf};

use anyhow::Context;

/// Expand a leading `~` to the current user's home directory.
///
/// Only `~` and `~/...` (or `~\...` on Windows) are supported. Named-user
/// forms such as `~alice` stay literal so behavior is identical on every OS.
pub(crate) fn expand_home(path: &str) -> anyhow::Result<PathBuf> {
    if path == "~" {
        return dirs::home_dir().context("cannot resolve home directory for ~ path");
    }
    let Some(relative) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) else {
        return Ok(PathBuf::from(path));
    };
    Ok(dirs::home_dir()
        .context("cannot resolve home directory for ~ path")?
        .join(Path::new(relative)))
}

#[cfg(test)]
mod tests {
    use super::expand_home;
    use std::path::PathBuf;

    #[test]
    fn absolute_and_plain_relative_paths_are_unchanged() {
        assert_eq!(
            expand_home("cache/jwks.json").unwrap(),
            PathBuf::from("cache/jwks.json")
        );
    }

    #[test]
    fn home_relative_path_is_expanded() {
        let expanded = expand_home("~/.cache/lfp-pipe/acme").unwrap();
        assert!(expanded.is_absolute());
        assert!(expanded.ends_with(PathBuf::from(".cache/lfp-pipe/acme")));
    }
}
