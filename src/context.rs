use anyhow::{anyhow, Result};
use capstone::{
    arch::{x86, BuildsCapstone},
    Capstone, Instructions,
};
use object::{Object, ObjectSection};

pub struct Context<'a> {
    pub object: object::File<'a>,
    pub cs: Capstone,
    pub pointer_size: usize,
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

        Ok(Self { object, cs, pointer_size })
    }

    pub fn disassemble(&'a self) -> Result<Instructions<'a>> {
        let text_section = self.object.section_by_name(".text").ok_or(anyhow!("No .text section"))?;

        self.cs.disasm_all(text_section.data()?, text_section.address()).map_err(|x| anyhow!(x))
    }
}
