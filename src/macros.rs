/// dirty hack to return colorized boolean result as a String
#[macro_export]
#[cfg(feature = "color")]
macro_rules! colorize_bool {
    ($tf:expr) => {
        if $tf {
            format!("{:<5}", $tf).bright_green().to_string()
        } else {
            format!("{:<5}", $tf).red().to_string()
        }
    };
}

#[macro_export]
#[cfg(feature = "color")]
macro_rules! underline {
    ($str:expr) => {
        $str.underline()
    };
}

#[macro_export]
#[cfg(not(feature = "color"))]
macro_rules! underline {
    ($str:expr) => {
        $str
    };
}

#[macro_export]
#[cfg(feature = "color")]
macro_rules! bold {
    ($str:expr) => {
        $str.bold()
    };
}

#[macro_export]
#[cfg(not(feature = "color"))]
macro_rules! bold {
    ($str:expr) => {
        $str
    };
}
