use clap::ValueEnum;
#[cfg(feature = "color")]
use colored::control;
#[cfg(feature = "color")]
use colored_json::to_colored_json_auto;
use serde_json::{json, to_string_pretty};
#[cfg(feature = "color")]
use std::env;
use std::ffi::OsStr;

use crate::helpers::{binary::Binaries, proc::Processes};

#[derive(Debug, Clone, ValueEnum)]
pub enum Format {
    Text,
    Json,
    JsonPretty,
}

impl std::fmt::Display for Format {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::Json => write!(f, "json"),
            Self::JsonPretty => write!(f, "json (pretty)"),
        }
    }
}

pub struct Settings {
    #[cfg(feature = "color")]
    pub color: bool,
    pub format: Format,
}

impl Settings {
    #[must_use]
    #[cfg(feature = "color")]
    pub fn set(color: bool, format: Format) -> Self {
        if color {
            // honor NO_COLOR if it is set within the environment
            if env::var("NO_COLOR").is_ok() {
                return Self { color: false, format };
            }
        } else {
            control::set_override(false);
        }
        Self { color, format }
    }
    #[must_use]
    #[cfg(not(feature = "color"))]
    pub fn set(format: Format, maps: bool) -> Self {
        Self { format }
    }
}

pub fn print_binary_results(binaries: &Binaries, settings: &Settings) {
    match settings.format {
        Format::Json => {
            println!("{}", &json!(binaries));
        }
        Format::JsonPretty => {
            #[cfg(feature = "color")]
            if settings.color {
                if let Ok(colored_json) =
                    to_colored_json_auto(&json!(binaries))
                {
                    println!("{colored_json}");
                }
            } else if let Ok(json_str) = to_string_pretty(&json!(binaries)) {
                println!("{json_str}");
            }
            #[cfg(not(feature = "color"))]
            if let Ok(json_str) = to_string_pretty(&json!(binaries)) {
                println!("{json_str}");
            }
        }
        Format::Text => {
            for binary in &binaries.binaries {
                println!("{binary}");
            }
        }
    }
}

pub fn print_process_results(
    processes: &Processes,
    settings: &Settings,
    maps: bool,
) {
    match settings.format {
        Format::Json => {
            println!("{}", &json!(processes));
        }
        Format::JsonPretty => {
            #[cfg(feature = "color")]
            if settings.color {
                if let Ok(colored_json) =
                    to_colored_json_auto(&json!(processes))
                {
                    println!("{colored_json}");
                }
            } else if let Ok(json_str) = to_string_pretty(&json!(processes)) {
                println!("{json_str}");
            }
            #[cfg(not(feature = "color"))]
            if let Ok(json_str) = to_string_pretty(&json!(processes)) {
                println!("{json_str}");
            }
        }
        Format::Text => {
            for process in &processes.processes {
                for binary in &process.binary {
                    println!(
                        "{}({})\n \u{21aa} {}",
                        binary
                            .file
                            .file_name()
                            .unwrap_or_else(|| OsStr::new("n/a"))
                            .to_string_lossy(),
                        process.pid,
                        binary
                    );
                }
                #[cfg(all(
                    feature = "maps",
                    any(target_os = "linux", target_os = "windows")
                ))]
                if maps {
                    if let Some(maps) = &process.maps {
                        println!("{:>12}", "\u{21aa} Maps:");
                        for map in maps {
                            println!("\t{map}");
                        }
                    }
                }
            }
        }
    }
}
