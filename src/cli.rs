use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    version,
    about = "Dark Souls II SL2 (PC) decrypt/edit/repack (NG only)"
)]
pub struct Cli {
    /// Input .sl2 file
    pub input: PathBuf,

    /// Output .sl2 path (required for set-ng)
    #[arg(long)]
    pub output: Option<PathBuf>,

    #[command(subcommand)]
    pub cmd: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Show entry list (index + name) and NG value if found
    Show,
    /// Set NG value for a given entry index (0-based BND4 entry that contains USERDATA)
    SetNg {
        /// Entry index (as reported by `show`)
        entry: usize,
        /// New NG value (u32)
        value: u32,
    },
}
