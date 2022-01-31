use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use capstone::{
    arch::{x86, BuildsCapstone, DetailsArchInsn},
    Capstone,
};
use object::{Object, ObjectSection};

pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: x86::X86Insn,
    pub operands: Vec<x86::X86Operand>,
}

pub struct Context<'a> {
    pub object: object::File<'a>,
    pub insns: Vec<Instruction>,
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

        let text_section = object.section_by_name(".text").ok_or(anyhow!("No .text section"))?;
        let insns = cs.disasm_all(text_section.data()?, text_section.address()).map_err(|x| anyhow!(x))?;

        let insns = insns
            .iter()
            .map(|x| {
                let mnemonic = x86::X86Insn::from(x.id().0);
                let insn_detail = cs.insn_detail(x).unwrap();
                let arch_detail = insn_detail.arch_detail();

                let operands = arch_detail.x86().unwrap().operands();

                Instruction {
                    address: x.address(),
                    bytes: x.bytes().to_vec(),
                    mnemonic,
                    operands: operands.into_iter().collect(),
                }
            })
            .collect();

        Ok(Self {
            object,
            insns,
            pointer_size,
            xrefs: BTreeMap::new(),
        })
    }
}
