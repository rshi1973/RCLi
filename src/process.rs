use serde::{Serialize, Deserialize};
use csv::Reader;
use anyhow::{Result, anyhow};

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    #[serde(rename = "ID")]
    id: u32,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Address")]
    address: String,
}

pub fn process_csv(input: &str, output: &str) -> Result<()> {
    let mut reader = Reader::from_path(input)?;
    let records = reader
        .deserialize()
        .map(|record| record.map_err(|e| anyhow!(e)))
        .collect::<Result<Vec<Record>>>()?;
    println!("{:?}", records);    

    //write records into json specified by the output file
    let json = serde_json::to_string(&records)?;
    std::fs::write(output, json)?;  

    Ok(())
}