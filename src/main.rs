mod instruction;
mod rtti;
mod util;
mod vtable;

use anyhow::{anyhow, Result};
use clap::Parser;
use object::{Object, ObjectSection};
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

    let pointer_size = if object.is_64() { 8 } else { 4 };

    let text_section = object.section_by_name(".text").ok_or(anyhow!("No .text section"))?;
    let data_section = object.section_by_name(".data").ok_or(anyhow!("No .data section"))?;
    let rdata_section = object.section_by_name(".rdata").ok_or(anyhow!("No .rdata section"))?;

    let insns = instruction::disassemble_all(text_section.data()?, text_section.address(), pointer_size)?;

    let (vtables, _) = vtable::find_vtables(&insns, &text_section, &rdata_section, pointer_size)?;
    for vtable in vtables {
        println!("{:#x}", vtable);
        if let Some(class_name) =
            rtti::try_get_class_info_by_rtti(object.relative_address_base(), &data_section, &rdata_section, pointer_size, vtable)?
        {
            println!("{}", class_name);
        }
    }

    Ok(())
}
