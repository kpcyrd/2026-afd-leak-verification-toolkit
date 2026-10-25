use crate::errors::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::fs;
use std::future::{Ready, ready};
use std::io;
use std::path::Path;
use std::str::FromStr;
use viadkim::verifier::LookupTxt;
use viadkim::{Config, HeaderFields, VerificationStatus, signature::DkimSignature};

pub fn dns_name(dkim: &DkimSignature) -> Option<String> {
    let dns = format!("{}._domainkey.{}", dkim.selector, dkim.domain);

    if dns.contains('/') {
        return None;
    }

    let dns = dns.to_ascii_lowercase();
    Some(dns)
}

pub struct Sig {
    pub text: String,
    pub value: DkimSignature,
}

impl Debug for Sig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.text)
    }
}

impl FromStr for Sig {
    type Err = viadkim::signature::DkimSignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = s.parse()?;
        Ok(Sig {
            text: s.to_string(),
            value,
        })
    }
}

impl Serialize for Sig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.text)
    }
}

impl<'de> Deserialize<'de> for Sig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let text = String::deserialize(deserializer)?;
        let value = text.parse().map_err(serde::de::Error::custom)?;
        Ok(Sig { text, value })
    }
}

pub struct Verifier {
    records: BTreeMap<String, Vec<String>>,
}

impl Verifier {
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut dir = fs::read_dir(path)?;

        let mut verifier = Verifier {
            records: Default::default(),
        };

        while let Some(entry) = dir.next().transpose()? {
            verifier.import_file(&entry.path())?;
        }

        Ok(verifier)
    }

    pub fn import_file(&mut self, path: &Path) -> Result<()> {
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            return Err(anyhow!("Invalid file name: {path:?}"));
        };

        let content =
            fs::read_to_string(path).with_context(|| anyhow!("Failed to read file: {path:?}"))?;

        let lines = content.lines().map(|line| line.to_string()).collect();
        self.records.insert(file_name.to_string(), lines);

        Ok(())
    }

    pub async fn verify(
        &self,
        dkim: &DkimSignature,
        header: &HeaderFields,
        body: &[u8],
    ) -> Option<bool> {
        let config = Config {
            allow_expired: true,
            ..Default::default()
        };

        let records = self.records.get(&dns_name(dkim)?)?;

        for record in records {
            let record = StaticRecord {
                record: record.clone(),
            };
            let results = viadkim::verify(&record, header, body, &config).await;
            for result in results {
                match result.status {
                    VerificationStatus::Success => return Some(true),
                    VerificationStatus::Failure(..) => (),
                }
            }
        }

        Some(false)
    }
}

#[derive(Debug, Clone)]
pub struct StaticRecord {
    pub record: String,
}

impl LookupTxt for StaticRecord {
    type Answer = Vec<io::Result<Vec<u8>>>;
    type Query<'a>
        = Ready<io::Result<Self::Answer>>
    where
        Self: 'a;

    fn lookup_txt(&self, _name: &str) -> Self::Query<'_> {
        ready(Ok(vec![Ok(self.record.as_bytes().to_vec())]))
    }
}
