mod context;
mod rtti;
mod util;
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

    let vtables = vtable::find_vtables(&context)?;
    for vtable in vtables {
        println!("{:#x}", vtable.address);
        if let Some(class_name) = rtti::try_get_class_info_by_rtti(&context, vtable.address)? {
            println!("{}", class_name);
        }
    }

    Ok(())
}
