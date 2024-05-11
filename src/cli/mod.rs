mod base64;
mod csv;
mod genpass;
mod http_serv;
mod jwt;
mod text;

use anyhow::Result;
use enum_dispatch::enum_dispatch;
use std::path::{self, Path, PathBuf};

pub use self::base64::*;
pub use self::csv::*;
pub use self::genpass::*;
pub use self::http_serv::*;
pub use self::jwt::*;
pub use self::text::*;
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "rcli", version, author, about, long_about = None)]
pub struct Opts {
    #[command(subcommand)]
    pub cmd: SubCommand,
}

#[derive(Debug, Parser)]
#[enum_dispatch(CmdExector)]
pub enum SubCommand {
    #[command(name = "csv", about = "Show CSV, or Convert CSV to other formats")]
    Csv(CsvOpts),
    #[command(name = "genpass", about = "Generate a random password")]
    GenPass(GenPassOpts),
    #[command(subcommand)]
    Base64(Base64SubCommand),
    #[command(subcommand)]
    Text(TextSubCommand),
    #[command(subcommand)]
    Http(HttpSubCommand),
    #[command(subcommand)]
    Jwt(JwtSubCommand),
}

fn verify_file(filename: &str) -> Result<String> {
    // if input is "-" or file exists
    if filename == "-" || Path::new(filename).exists() {
        Ok(filename.into())
    } else {
        Err(anyhow::anyhow!("File does not exist"))
    }
}

fn verify_path(path: &str) -> Result<PathBuf> {
    let p = path::Path::new(path);

    if p.exists() && p.is_dir() {
        Ok(path.into())
    } else {
        Err(anyhow::anyhow!("Path does not exist"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_verify_file() {
        assert!(verify_file("-").is_ok());
        assert!(verify_file("Cargo.toml").is_ok());
        assert!(verify_file("nonexistent").is_err());
    }
}
