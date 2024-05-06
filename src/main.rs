//rcli csv -i input.csv -o output.json --header -d ','
use anyhow::Result;
use clap::Parser;
use rcli::{process_csv, process_genpass, Opts, SubCommand};

fn main() -> Result<()> {
    let opts: Opts = Opts::parse();

    //match opts.cmd if it the command is csv, read the csv file and print the records
    //and the error handling follows anyhow style using map_err
    match opts.cmd {
        SubCommand::Csv(opts) => {
            let output = if let Some(output) = opts.output {
                output.clone()
            } else {
                format!("output.{}", opts.format)
            };
            process_csv(&opts.input, output, opts.format)?;
        }

        SubCommand::GenPass(opts) => {
            process_genpass(
                opts.length,
                opts.uppercase,
                opts.lowercase,
                opts.number,
                opts.symbols,
            )?;
        }
    }

    Ok(())
}
