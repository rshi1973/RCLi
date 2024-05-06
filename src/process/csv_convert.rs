use crate::opts::OutputFormat;
use anyhow::{anyhow, Result};
use csv::Reader;
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Record {
    #[serde(rename = "ID")]
    id: u32,
    name: String,
    address: String,
}

pub fn process_csv(input: &str, output: String, format: OutputFormat) -> Result<()> {
    let mut reader = Reader::from_path(input)?;
    let records = reader
        .deserialize()
        .map(|record| record.map_err(|e| anyhow!(e)))
        .collect::<Result<Vec<Record>>>()?;
    println!("{:?}", records);

    //convert records into the specified format
    match format {
        OutputFormat::Json => {
            let json = serde_json::to_string(&records)?;
            std::fs::write(output, json)?;
        }
        OutputFormat::Yaml => {
            let yaml = serde_yaml::to_string(&records)?;
            std::fs::write(output, yaml)?;
        }
    }

    Ok(())
}
