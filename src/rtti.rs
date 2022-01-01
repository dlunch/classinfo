use std::str;

use anyhow::{anyhow, Result};
use object::{Object, ObjectSection};

use super::{context::Context, util::convert_pointer};

#[repr(C)]
struct RTTICompleteObjectLocator {
    signature: u32,
    vtable_offset: u32,
    cd_offset: u32,
    type_descriptor: u32,
    class_hierarchy: u32,
}

pub fn cast<T>(data: &[u8]) -> &T {
    unsafe { &*(data.as_ptr() as *const T) }
}

// msvc-specific for now
pub fn try_get_class_info_by_rtti(context: &Context, vtable_base: u64) -> Result<Option<String>> {
    let rdata_section = context.object.section_by_name(".rdata").ok_or(anyhow!("No .rdata section"))?;
    let rdata = rdata_section.data()?;

    let data_section = context.object.section_by_name(".data").ok_or(anyhow!("No .data section"))?;
    let data = data_section.data()?;

    let rtti_locator_base = convert_pointer(
        &rdata[(vtable_base - context.pointer_size as u64 - rdata_section.address()) as usize..],
        context.pointer_size,
    );
    let rtti_locator = cast::<RTTICompleteObjectLocator>(&rdata[(rtti_locator_base - rdata_section.address()) as usize..]);
    log::trace!("{:#x} RTTI Complete Object Locator {:#x}", vtable_base, rtti_locator_base);

    log::trace!("{:#x} RTTI Type Descriptor {:#x}", vtable_base, rtti_locator.type_descriptor);
    let rtti_type_descriptor = if context.pointer_size == 8 {
        &data[(rtti_locator.type_descriptor as u64 + context.object.relative_address_base() - data_section.address()) as usize..]
    } else {
        &data[(rtti_locator.type_descriptor as u64 - data_section.address()) as usize..]
    };

    let type_name = &rtti_type_descriptor[context.pointer_size * 2..];
    let type_name_end = type_name.iter().position(|&x| x == 0).ok_or(anyhow!("Invalid type name"))?;
    let type_name = str::from_utf8(&type_name[..type_name_end])?;

    log::trace!("{:#x} Type Name {:}", vtable_base, type_name);

    // msvc_demangler cannot consume rtti name, like `.?AVtest@@`
    let mangled_name = format!("?{}", &type_name[4..]);
    let demangled_name = msvc_demangler::demangle(&mangled_name, msvc_demangler::DemangleFlags::llvm())?;

    Ok(Some(demangled_name))
}

#[cfg(test)]
mod tests {
    use tokio::fs;

    use super::{try_get_class_info_by_rtti, Context};

    fn init() {
        let mut builder = pretty_env_logger::formatted_builder();

        if let Ok(s) = ::std::env::var("RUST_LOG") {
            builder.parse_filters(&s);
        }

        let _ = builder.is_test(true).try_init();
    }

    #[tokio::test]
    async fn test_x86() -> anyhow::Result<()> {
        init();

        let file = fs::read("./test_data/msvc_rtti1_32.exe").await?;
        let obj = object::File::parse(&*file)?;
        let context = Context::new(obj)?;

        let class_name = try_get_class_info_by_rtti(&context, 0x40e164)?;
        assert_eq!(class_name.unwrap(), "test");

        Ok(())
    }

    #[tokio::test]
    async fn test_x64() -> anyhow::Result<()> {
        init();

        let file = fs::read("./test_data/msvc_rtti1_64.exe").await?;
        let obj = object::File::parse(&*file)?;
        let context = Context::new(obj)?;

        let class_name = try_get_class_info_by_rtti(&context, 0x140010318)?;
        assert_eq!(class_name.unwrap(), "test");

        Ok(())
    }
}
