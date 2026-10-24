pub mod args;
pub mod dns;
pub mod errors;
pub mod mbox;

use crate::args::{Args, Subcommand};
use crate::dns::DkimDnsResolver;
use crate::errors::*;
use clap::Parser;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Write;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.subcommand {
        Subcommand::Ls(ls) => {
            let file = File::open(&ls.file)?;
            let mut reader = mbox::Reader::new(file);

            while let Some(email) = reader.next().transpose()? {
                if ls.dkim_only && email.dkim().is_none() {
                    continue;
                }

                if ls.inspect() {
                    println!("{:#?}", email);
                } else {
                    if ls.from {
                        println!("From: {:?}", email.from);
                    }

                    if ls.to {
                        println!("To: {:?}", email.to);
                    }

                    if ls.id {
                        println!("Message-ID: {:?}", email.message_ids);
                    }

                    if ls.subject
                        && let Some(subject) = &email.subject
                    {
                        println!("Subject: {:?}", subject);
                    }

                    if ls.dkim
                        && let Some(dkim) = email.dkim()
                    {
                        println!("DKIM: {:?}", dkim);
                    }
                }

                println!("---");
            }
        }
        Subcommand::FetchDkim { file } => {
            let resolver = DkimDnsResolver::new()?;

            let file = File::open(&file)?;
            let mut reader = mbox::Reader::new(file);

            let mut missing_dkim = BTreeSet::new();

            while let Some(email) = reader.next().transpose()? {
                if let Some(dkim) = email.dkim() {
                    // println!("{:#?}", email);
                    let dns = format!("{}._domainkey.{}", dkim.selector, dkim.domain);
                    if dns.contains('/') {
                        continue;
                    }
                    let dns = dns.to_ascii_lowercase();
                    let path = format!("dkim/{dns}");

                    if fs::metadata(&path).is_ok() {
                        continue;
                    }

                    println!("{dns}");

                    match resolver.resolve(&dns).await {
                        Ok(records) => {
                            if !records.is_empty() {
                                let mut file =
                                    File::options().append(true).create(true).open(path)?;
                                for record in &records {
                                    file.write_all(record.as_bytes())?;
                                    file.write_all(b"\n")?;
                                }
                            } else {
                                missing_dkim.insert(dns);
                            }

                            println!("records: {records:?}");
                        }
                        Err(err) => {
                            eprintln!("Failed to resolve {:?}: {}", dns, err);
                            missing_dkim.insert(dns);
                        }
                    }

                    println!("---");
                }
            }

            let mut file = File::create("missing-dkim.txt")?;
            for dns in &missing_dkim {
                writeln!(file, "{}", dns)?;
            }
        }
    }

    Ok(())
}
