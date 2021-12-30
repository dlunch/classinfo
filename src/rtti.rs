use std::str;

use anyhow::{anyhow, Result};
use object::{Object, ObjectSection};

use super::{context::Context, util::convert_pointer};

#[repr(C)]
struct RTTICompleteObjectLocator {
    signature: u32,
    vtable_offset: u32,
    cd_offset: u32,
    type_descriptor_rva: u32,
    class_hierarchy_rva: u32,
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

    log::trace!("{:#x} RTTI Type Descriptor {:#x}", vtable_base, rtti_locator.type_descriptor_rva);
    let rtti_type_descriptor =
        &data[(rtti_locator.type_descriptor_rva as u64 + context.object.relative_address_base() - data_section.address()) as usize..];

    let type_name = &rtti_type_descriptor[context.pointer_size * 2..];
    let type_name_end = type_name.iter().position(|&x| x == 0).ok_or(anyhow!("Invalid type name"))?;
    let type_name = str::from_utf8(&type_name[..type_name_end])?;

    log::trace!("{:#x} Type Name {:}", vtable_base, type_name);

    Ok(Some(type_name.to_owned()))
}
