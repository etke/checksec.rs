#![warn(clippy::pedantic)]
// Do not require 1.65.0
#![allow(clippy::manual_let_else)]
extern crate clap;
extern crate core;
extern crate goblin;
extern crate ignore;
extern crate serde_json;
extern crate sysinfo;

use clap::{arg, command, Parser, Subcommand};
use std::{path::PathBuf, process};

#[cfg(feature = "elf")]
mod elf;
mod helpers;
#[cfg(feature = "macho")]
mod macho;
mod macros;
#[cfg(feature = "pe")]
mod pe;
mod shared;

use helpers::{
    binary::Binaries,
    input::{paths_from_stdin, pids_from_stdin, strings_from_stdin},
    output::{self, print_binary_results, print_process_results},
    proc::Processes,
    scan,
};

#[derive(Debug, Parser)]
#[command(
    author,
    version,
    about,
    override_usage = "checksec <COMMAND> [OPTIONS]"
)]

struct Cli {
    #[command(subcommand)]
    command: Commands,
    /// Disables color output
    #[arg(long = "no-color", global = true)]
    color: bool,
    /// Output format
    #[arg(long, default_value_t = output::Format::Text, global = true)]
    format: output::Format,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Scan binaries or compressed archives by path
    #[command(
        arg_required_else_help = true,
        override_usage = format!(
            "checksec blob [OPTIONS] [PATHS]\n\
            {:<7}command | checksec blob [OPTIONS] --stdin", " "
        )
    )]
    Blob {
        #[arg(requires_if("false", "stdin"))]
        paths: Vec<PathBuf>,
        /// Read paths from stdin
        #[arg(short, long, default_value_t = false)]
        stdin: bool,
        // global options
        #[cfg(feature = "color")]
        #[arg(from_global)]
        color: bool,
        #[arg(from_global)]
        format: output::Format,
    },
    /// Scan binaries by process
    #[command(
        arg_required_else_help = true,
        override_usage = format!(
            "checksec process <command> [OPTIONS]"
        )
    )]
    Process {
        #[command(subcommand)]
        command: ProcCommands,
    },
}

#[derive(Debug, Subcommand)]
enum ProcCommands {
    /// Scan all running processes
    All {
        /// Include process memory maps (linux/windows only)
        #[arg(short, long, default_value_t = false)]
        maps: bool,
        // global options
        #[cfg(feature = "color")]
        #[arg(from_global)]
        color: bool,
        #[arg(from_global)]
        format: output::Format,
    },
    /// Scan processes by PID
    #[command(
        arg_required_else_help = true,
        override_usage = format!(
            "checksec process id [OPTIONS] <PIDS>\n\
            {:<7}command | checksec process id [OPTIONS] --stdin", " "
        )
    )]
    Id {
        #[arg(requires_if("false", "stdin"))]
        pids: Vec<sysinfo::Pid>,
        /// Include process memory maps (linux/windows only)
        #[arg(short, long)]
        maps: bool,
        /// Read process ids from stdin
        #[arg(short, long, default_value_t = false)]
        stdin: bool,
        // global options
        #[cfg(feature = "color")]
        #[arg(from_global)]
        color: bool,
        #[arg(from_global)]
        format: output::Format,
    },
    /// Scan processes by name
    #[command(
        arg_required_else_help = true,
        override_usage = format!(
            "checksec process name [OPTIONS] <PROCNAMES>\n\
            {:<7}command | checksec process name [OPTIONS] --stdin", " "
        )
    )]
    Name {
        #[arg(requires_if("false", "stdin"))]
        procnames: Vec<String>,
        /// Include process memory maps (linux/windows only)
        #[arg(short, long)]
        maps: bool,
        /// Read process names from stdin
        #[arg(short, long, default_value_t = false)]
        stdin: bool,
        // global options
        #[cfg(feature = "color")]
        #[arg(from_global)]
        color: bool,
        #[arg(from_global)]
        format: output::Format,
    },
}

fn main() {
    let args = Cli::parse();

    match args.command {
        Commands::Blob { paths, stdin, color, format } => {
            let settings = output::Settings::set(
                #[cfg(feature = "color")]
                !color,
                format,
            );

            let results = if stdin {
                scan::paths(&paths_from_stdin())
            } else {
                scan::paths(&paths)
            };
            if results.is_empty() {
                eprintln!("No binaries found");
                process::exit(1);
            }
            print_binary_results(&Binaries::new(results), &settings);
        }
        Commands::Process { command } => match command {
            ProcCommands::All { maps, color, format } => {
                let settings = output::Settings::set(
                    #[cfg(feature = "color")]
                    !color,
                    format,
                );
                let results = scan::all_processes();
                if results.is_empty() {
                    eprintln!("No running process found");
                    process::exit(1);
                }
                print_process_results(
                    &Processes::new(results),
                    &settings,
                    maps,
                );
            }
            ProcCommands::Id { pids, stdin, color, maps, format } => {
                let settings = output::Settings::set(
                    #[cfg(feature = "color")]
                    !color,
                    format,
                );

                let results = if stdin {
                    scan::pids(&pids_from_stdin())
                } else {
                    scan::pids(&pids)
                };
                if results.is_empty() {
                    process::exit(1);
                }
                print_process_results(
                    &Processes::new(results),
                    &settings,
                    maps,
                );
            }
            ProcCommands::Name { procnames, stdin, color, maps, format } => {
                let settings = output::Settings::set(
                    #[cfg(feature = "color")]
                    !color,
                    format,
                );
                let results = if stdin {
                    scan::procnames(&strings_from_stdin())
                } else {
                    scan::procnames(&procnames)
                };
                if results.is_empty() {
                    process::exit(1);
                }
                print_process_results(
                    &Processes::new(results),
                    &settings,
                    maps,
                );
            }
        },
    }
}
