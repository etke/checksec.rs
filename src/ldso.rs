use crate::ldso::LdSoError::{IncludeDepth, InvalidFormat};
use std::path::{Path, PathBuf};
use std::{fmt, fs, io};

#[derive(Clone)]
pub struct LdSoLookup {
    lookup_dirs: Vec<PathBuf>,
}

impl LdSoLookup {
    #[must_use]
    pub fn search(&self, filename: &str) -> Option<PathBuf> {
        for dir in &self.lookup_dirs {
            let path = dir.join(filename);
            if path.is_file() {
                return Some(path);
            }
        }
        None
    }
}

pub enum LdSoError {
    /// I/O error
    IO(io::Error),
    /// Invalid format
    InvalidFormat(String),
    /// Pattern error
    Pattern(glob::PatternError, PathBuf),
    /// Globbing error
    Glob(glob::GlobError, PathBuf),
    /// Include depth exhaustion
    IncludeDepth(PathBuf),
}

impl fmt::Display for LdSoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IO(err) => err.fmt(f),
            Self::InvalidFormat(str) => str.fmt(f),
            Self::Pattern(perr, path) => {
                write!(f, "Failed to follow glob {}: {}", path.display(), perr)
            }
            Self::Glob(gerr, path) => {
                write!(f, "Failed to match glob {}: {}", path.display(), gerr)
            }
            Self::IncludeDepth(path) => {
                write!(f, "Maximum include depth reached: {}", path.display())
            }
        }
    }
}

impl From<io::Error> for LdSoError {
    fn from(e: io::Error) -> Self {
        LdSoError::IO(e)
    }
}

impl LdSoLookup {
    fn parse_ldso_conf_file(
        conffile: &Path,
        include_depth: u8,
    ) -> Result<Vec<PathBuf>, LdSoError> {
        if include_depth > 4 {
            return Err(IncludeDepth(conffile.to_path_buf()));
        }

        let mut lookup_paths: Vec<PathBuf> = Vec::new();
        let content = fs::read_to_string(conffile)?;

        for line in content.lines() {
            let line = line.trim();

            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(include_path) = line.strip_prefix("include ") {
                if !include_path.starts_with('/') {
                    return Err(InvalidFormat(format!(
                        "Invalid include path: {include_path}"
                    )));
                }
                for file in glob::glob(include_path).map_err(|e| {
                    LdSoError::Pattern(e, PathBuf::from(include_path))
                })? {
                    let file = file.map_err(|e| {
                        LdSoError::Glob(e, PathBuf::from(include_path))
                    })?;
                    lookup_paths.append(
                        &mut LdSoLookup::parse_ldso_conf_file(
                            &file,
                            include_depth + 1,
                        )?,
                    );
                }
                continue;
            }

            if line.starts_with('/') {
                lookup_paths.push(PathBuf::from(
                    line.split('#').next().ok_or_else(|| {
                        InvalidFormat(format!("Invalid path line: {line}"))
                    })?,
                ));
                continue;
            }

            return Err(InvalidFormat(format!("Invalid line: {line}")));
        }

        Ok(lookup_paths)
    }

    /// Initialize a lookup handle from the ld.so.conf configuration of the
    /// system.
    ///
    /// # Errors
    /// Will fail if the ld.so.conf configuration can not be read or has an
    /// invalid format.
    pub fn gen_lookup_dirs() -> Result<LdSoLookup, LdSoError> {
        Ok(LdSoLookup {
            lookup_dirs: LdSoLookup::parse_ldso_conf_file(
                Path::new("/etc/ld.so.conf"),
                0,
            )?,
        })
    }
}
