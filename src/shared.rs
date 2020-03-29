use colored::*;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Deserialize, Serialize)]
pub enum Rpath {
    None,
    Yes(String),
    YesRW(String),
}
/// wrapper for Vec<Rpath> to allow easy color output per path entry
#[derive(Debug, Deserialize, Serialize)]
pub struct VecRpath {
    pub paths: Vec<Rpath>,
}
impl VecRpath {
    pub fn new(v: Vec<Rpath>) -> VecRpath {
        VecRpath { paths: v }
    }
}
impl fmt::Display for VecRpath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s: Vec<String> = Vec::<String>::new();
        for v in &self.paths {
            match v {
                Rpath::Yes(p) => s.push(p.red().to_string()),
                Rpath::YesRW(p) => s.push(p.red().to_string()),
                Rpath::None => s.push("None".green().to_string()),
            }
        }
        write!(f, "{}", s.join(":"))?;
        Ok(())
    }
}

/// dirty hack to print colorized boolean result
pub fn colorize_bool(tf: bool) -> String {
    if tf {
        format!("{}", tf).bright_green().to_string()
    } else {
        format!("{}", tf).red().to_string()
    }
}
