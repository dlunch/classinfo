mod class;
mod context;
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
    let object = object::File::parse(&*file)?;

    let context = context::Context::new(object)?;
    vtable::find_vtables(&context)?;

    Ok(())
}
