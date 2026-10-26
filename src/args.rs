use std::path::PathBuf;

#[derive(Debug, clap::Parser)]
pub struct Args {
    #[arg(short, long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub subcommand: Subcommand,
}

#[derive(Debug, Clone, clap::Subcommand)]
pub enum Subcommand {
    /// List emails
    Ls(Ls),
    /// Verify DKIM signatures
    Verify(Verify),
    /// Populate local DKIM public key cache
    FetchDkim { files: Vec<PathBuf> },
}

#[derive(Debug, Clone, clap::Parser)]
pub struct Ls {
    pub files: Vec<PathBuf>,
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

#[derive(Debug, Clone, clap::Parser)]
pub struct Verify {
    pub files: Vec<PathBuf>,
}
