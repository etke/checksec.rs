use clap::ValueEnum;
#[cfg(feature = "color")]
use colored::control;
#[cfg(feature = "color")]
use std::env;

#[derive(Clone, Debug, ValueEnum)]
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
    pub libraries: bool,
}

impl Settings {
    #[must_use]
    #[cfg(feature = "color")]
    pub fn set(color: bool, format: Format, libraries: bool) -> Self {
        if color {
            // honor NO_COLOR if it is set within the environment
            if env::var("NO_COLOR").is_ok() {
                return Self { color: false, format, libraries };
            }
        } else {
            control::set_override(false);
        }
        Self { color, format, libraries }
    }
    #[must_use]
    #[cfg(not(feature = "color"))]
    pub fn set(format: Format, libraries: bool) -> Self {
        Self { format, libraries }
    }
}
