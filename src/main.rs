pub mod args;
pub mod dkim;
pub mod dns;
pub mod errors;
pub mod mbox;

use crate::args::{Args, Subcommand};
use crate::dns::DkimDnsResolver;
use crate::errors::*;
use clap::Parser;
use colored::Colorize;
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

            while let Some((email, _buf)) = reader.next().transpose()? {
                if ls.dkim_only && email.dkim().is_none() {
                    continue;
                }

                if ls.inspect() {
                    email.print(args.json)?;
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

                if !args.json {
                    println!("---");
                }
            }
        }
        Subcommand::Verify(verify) => {
            let file = File::open(&verify.file)?;
            let mut reader = mbox::Reader::new(file);

            let verifier = dkim::Verifier::new("dkim/")?;

            while let Some((email, mut buf)) = reader.next().transpose()? {
                let Some(dkim) = email.dkim() else {
                    continue;
                };

                email.print(args.json)?;

                // Normalize the final line ending, everything else should already be \r\n
                if let Some(_stripped) = buf.strip_suffix(b"\r\n\n") {
                    buf.truncate(buf.len().saturating_sub(1));
                    buf.extend_from_slice(b"\r\n");
                }

                // Split the email headers off and parse them
                let (headers, body) =
                    mbox::split_headers(&buf).context("Failed to split email headers from body")?;

                let headers = str::from_utf8(headers)?;
                let headers = headers.parse()?;

                println!(
                    "{}",
                    match verifier.verify(dkim, &headers, body).await {
                        Some(true) => "DKIM PASS".green(),
                        Some(false) => "DKIM FAIL".red(),
                        None => "DKIM MISSING PUBLIC KEY".yellow(),
                    }
                );
            }
        }
        Subcommand::FetchDkim { files } => {
            let resolver = DkimDnsResolver::new()?;
            let mut missing_dkim = BTreeSet::new();

            fs::create_dir_all("dkim")?;

            for file in files {
                let file = File::open(&file)?;
                let mut reader = mbox::Reader::new(file);

                while let Some((email, _buf)) = reader.next().transpose()? {
                    if let Some(dkim) = email.dkim() {
                        // println!("{:#?}", email);

                        let Some(dns) = dkim::dns_name(dkim) else {
                            continue;
                        };

                        let path = format!("dkim/{dns}");

                        if fs::metadata(&path).is_ok() {
                            continue;
                        }

                        if missing_dkim.contains(&dns) {
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
            }

            let mut file = File::create("missing-dkim.txt")?;
            for dns in &missing_dkim {
                writeln!(file, "{}", dns)?;
            }
        }
    }

    Ok(())
}
