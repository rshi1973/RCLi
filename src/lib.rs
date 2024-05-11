mod cli;
mod process;
mod utils;

pub use cli::*;
use enum_dispatch::enum_dispatch;
pub use process::{
    process_csv, process_decode, process_encode, process_genpass, process_http_serv, process_sign,
    process_text_decrypt, process_text_encrypt, process_text_generate, process_text_sign,
    process_text_verify, process_verify,
};
pub use utils::*;

#[allow(async_fn_in_trait)]
#[enum_dispatch]
pub trait CmdExector {
    async fn execute(self) -> anyhow::Result<()>;
}
