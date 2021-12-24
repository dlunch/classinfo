#![allow(dead_code, unused_variables)] // TODO

use anyhow::{anyhow, Result};
use object::{File, Object, ObjectSection};

use crate::class::Class;

fn convert_pointer(raw: &[u8], pointer_size: usize) -> u64 {
    let value = &raw[0..pointer_size];

    if pointer_size == 8 {
        u64::from_le_bytes(value.try_into().unwrap())
    } else {
        u32::from_le_bytes(value.try_into().unwrap()) as u64
    }
}

pub fn find_vtables(object: &File) -> Result<Vec<Class>> {
    let text_section = object.section_by_name(".text").ok_or(anyhow!("No .text section"))?;

    let data_section = object.section_by_name(".data").ok_or(anyhow!("No .data section"))?;
    let data = data_section.data()?;

    let rdata_section = object.section_by_name(".rdata").ok_or(anyhow!("No .rdata section"))?;
    let rdata = data_section.data()?;

    let pointer_size = if object.is_64() { 8 } else { 4 };

    // 1. Find vtable candidates
    struct State {
        last: Option<u64>,
        all: Vec<u64>,
    }

    let vtable_candidates = rdata
        .windows(pointer_size)
        .enumerate()
        .step_by(pointer_size)
        .fold(State { last: None, all: Vec::new() }, |mut state, (i, x)| {
            let ptr = convert_pointer(x, pointer_size);
            log::debug!("{}", ptr);

            if text_section.address() < ptr && ptr < text_section.address() + text_section.size() {
                if state.last.is_none() {
                    log::trace!("vtable candidate at {}", i);
                    state.last = Some(ptr);
                }
            } else if state.last.is_some() {
                state.all.push(state.last.unwrap());
                state.last = None
            }

            state
        })
        .all;

    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use tokio::fs;

    use super::find_vtables;

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

        find_vtables(&obj)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_x64() -> anyhow::Result<()> {
        init();

        let file = fs::read("./test_data/msvc_rtti1_64.exe").await?;
        let obj = object::File::parse(&*file)?;

        find_vtables(&obj)?;

        Ok(())
    }
}
