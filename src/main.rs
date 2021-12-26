mod class;
mod vtable;

use anyhow::Result;
use clap::Parser;
use tokio::fs;

#[derive(Parser)]
struct Args {
    file_name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = pretty_env_logger::init();

    let args = Args::parse();

    let file = fs::read(args.file_name).await?;
    let obj = object::File::parse(&*file)?;

    vtable::find_vtables(&obj)?;

    Ok(())
}
