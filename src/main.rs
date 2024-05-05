//rcli csv -i input.csv -o output.json --header -d ','
use clap::Parser;
use anyhow::Result;
use rcli::{Opts, SubCommand, process_csv};

fn main() -> Result<()>{
    let opts: Opts = Opts::parse();
    
    //match opts.cmd if it the command is csv, read the csv file and print the records
    //and the error handling follows anyhow style using map_err
    match opts.cmd {
        SubCommand::Csv(opts) => {
            process_csv(&opts.input, &opts.output)?;
        }
    }
    
    Ok(())
}
