use crate::errors::*;
use hickory_resolver::TokioResolver;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;

pub struct DkimDnsResolver {
    resolver: TokioResolver,
}

impl DkimDnsResolver {
    pub fn new() -> Result<Self> {
        let provider = TokioRuntimeProvider::default();

        let (mut config, options) = hickory_resolver::system_conf::read_system_conf()?;
        config.domain = None;
        config.search.clear();

        let mut builder = TokioResolver::builder_with_config(config, provider);
        *builder.options_mut() = options;

        let resolver = builder.build()?;

        Ok(Self { resolver })
    }

    pub async fn resolve(&self, name: &str) -> Result<Vec<String>> {
        let response = self.resolver.txt_lookup(name).await?;

        let mut records = Vec::new();

        for record in response.answers() {
            if let RData::TXT(txt) = &record.data {
                let bytes = txt
                    .txt_data
                    .iter()
                    .flat_map(|chunk| &chunk[..])
                    .copied()
                    .collect::<Vec<_>>();

                let value = String::from_utf8_lossy_owned(bytes);
                records.push(value);
            }
        }

        records.sort();

        Ok(records)
    }
}
