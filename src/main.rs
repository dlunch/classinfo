mod class;
mod vtable;

use anyhow::Result;

#[tokio::main]
async fn main() -> Result<()> {
    let _ = pretty_env_logger::init();

    Ok(())
}
