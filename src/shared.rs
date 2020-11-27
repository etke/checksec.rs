//! Implements shared functionalities between elf/macho modules
#[cfg(feature = "color")]
use colored::Colorize;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Split contents of `DT_RPATH`/`DT_RUNPATH` or @rpath entries
#[derive(Debug, Deserialize, Serialize)]
pub enum Rpath {
    None,
    Yes(String),
    YesRW(String),
}
/// wrapper for Vec<Rpath> to allow easy color output per path entry
#[derive(Debug, Deserialize, Serialize)]
pub struct VecRpath {
    paths: Vec<Rpath>,
}
impl VecRpath {
    #[must_use]
    pub fn new(v: Vec<Rpath>) -> Self {
        Self { paths: v }
    }
}
#[cfg(not(feature = "color"))]
impl fmt::Display for VecRpath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s: Vec<String> = Vec::<String>::new();
        for v in &self.paths {
            match v {
                Rpath::Yes(p) => s.push(p.to_string()),
                Rpath::YesRW(p) => s.push(p.to_string()),
                Rpath::None => s.push("None".to_string()),
            }
        }
        write!(f, "{}", s.join(":"))?;
        Ok(())
    }
}
#[cfg(feature = "color")]
impl fmt::Display for VecRpath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s: Vec<String> = Vec::<String>::new();
        for v in &self.paths {
            match v {
                Rpath::Yes(p) | Rpath::YesRW(p) => s.push(p.red().to_string()),
                Rpath::None => s.push("None".green().to_string()),
            }
        }
        write!(f, "{}", s.join(":"))?;
        Ok(())
    }
}
