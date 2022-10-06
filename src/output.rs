#[cfg(feature = "color")]
use colored::control;
#[cfg(feature = "color")]
use std::env;

pub enum Format {
    Text,
    Json,
    JsonPretty,
}

pub struct Settings {
    #[cfg(feature = "color")]
    pub color: bool,
    pub format: Format,
    pub maps: bool,
    pub libraries: bool,
}

impl Settings {
    #[must_use]
    #[cfg(feature = "color")]
    pub fn set(
        color: bool,
        format: Format,
        maps: bool,
        libraries: bool,
    ) -> Self {
        if color {
            // honor NO_COLOR if it is set within the environment
            if env::var("NO_COLOR").is_ok() {
                return Self { color: false, format, maps, libraries };
            }
        } else {
            control::set_override(false);
        }
        Self { color, format, maps, libraries }
    }
    #[must_use]
    #[cfg(not(feature = "color"))]
    pub fn set(format: Format, maps: bool, libraries: bool) -> Self {
        Self { format, maps, libraries }
    }
}
