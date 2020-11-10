/// dirty hack to return colorized boolean result as a String
#[macro_export]
macro_rules! colorize_bool {
    ($tf:expr) => {
        if $tf {
            format!("{:<5}", $tf).bright_green().to_string()
        } else {
            format!("{:<5}", $tf).red().to_string()
        };
    };
}
