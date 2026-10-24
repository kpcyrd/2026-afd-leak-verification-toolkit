use std::path::PathBuf;

#[derive(Debug, clap::Parser)]
pub struct Args {
    #[clap(subcommand)]
    pub subcommand: Subcommand,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum Subcommand {
    /// List emails
    Ls(Ls),
    /// Populate local DKIM public key cache
    FetchDkim { file: PathBuf },
}

#[derive(Debug, Clone, clap::Parser)]
pub struct Ls {
    pub file: PathBuf,
    #[arg(short = 'D', long)]
    pub dkim_only: bool,
    #[arg(short, long)]
    pub from: bool,
    #[arg(short, long)]
    pub to: bool,
    #[arg(short, long)]
    pub id: bool,
    #[arg(short, long)]
    pub subject: bool,
    #[arg(short, long)]
    pub dkim: bool,
}

impl Ls {
    pub fn inspect(&self) -> bool {
        !self.from && !self.to && !self.id && !self.subject && !self.dkim
    }
}
