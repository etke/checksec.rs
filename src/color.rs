/// dirty hack to return colorized boolean result as a String
#[macro_export]
macro_rules! colorize_bool {
    ($tf:expr) => {
        if $tf {
            format!("{}", $tf).bright_green().to_string()
        } else {
            format!("{}", $tf).red().to_string()
        };
    };
}
