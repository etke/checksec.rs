#[cfg(feature = "color")]
use std::env;
#[cfg(feature = "color")]
use colored::control;

pub struct Settings {
    #[cfg(feature = "color")]
    pub color: bool,
    pub json: bool,
    pub pretty: bool,
}

impl Settings {
    #[must_use]
    #[cfg(feature = "color")]
    pub fn set(color: bool, json: bool, pretty: bool) -> Self {
        if color {
            // honor NO_COLOR if it is set within the environment
            if env::var("NO_COLOR").is_ok() {
                return Self { color: false, json, pretty };
            }
        } else {
            control::set_override(false);
        }
        Self { color, json, pretty }
    }
    #[must_use]
    #[cfg(not(feature = "color"))]
    pub fn set(json: bool, pretty: bool) -> Self {
        Self { json, pretty }
    }
}