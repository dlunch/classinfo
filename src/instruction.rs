use anyhow::{anyhow, Result};
use capstone::{
    arch::{x86, BuildsCapstone, DetailsArchInsn},
    Capstone,
};

pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: x86::X86Insn,
    pub operands: Vec<x86::X86Operand>,
}

pub fn disassemble_all(code: &[u8], addr: u64, pointer_size: usize) -> Result<Vec<Instruction>> {
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

    let insns = cs.disasm_all(code, addr).map_err(|x| anyhow!(x))?;

    Ok(insns
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
        .collect::<Vec<_>>())
}
