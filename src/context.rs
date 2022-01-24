use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use capstone::{
    arch::{x86, BuildsCapstone},
    Capstone,
};
use object::Object;

pub struct Context<'a> {
    pub object: object::File<'a>,
    pub cs: Capstone,
    pub pointer_size: usize,
    pub xrefs: BTreeMap<u64, Vec<u64>>,
}

impl<'a> Context<'a> {
    pub fn new(object: object::File<'a>) -> Result<Self> {
        let pointer_size = if object.is_64() { 8 } else { 4 };

        let cs = Capstone::new()
            .x86()
            .mode(if pointer_size == 4 {
                x86::ArchMode::Mode32
            } else {
                x86::ArchMode::Mode64
            })
            .detail(true)
            .build()
            .map_err(|x| anyhow!(x))?;

        Ok(Self {
            object,
            cs,
            pointer_size,
            xrefs: BTreeMap::new(),
        })
    }
}
