use anyhow::Result;
use clap::Parser;
use rcli::{CmdExector, Opts};
// rcli csv -i input.csv -o output.json --header -d ','
// use zxcvbn::zxcvbn;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let opts: Opts = Opts::parse();

    //match opts.cmd if it the command is csv, read the csv file and print the records
    //and the error handling follows anyhow style using map_err
    opts.cmd.execute().await.map_err(|e| {
        eprintln!("{}", e);
        e
    })?;

    Ok(())
}
