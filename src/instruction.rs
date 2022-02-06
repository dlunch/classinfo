use std::iter;

use anyhow::{anyhow, Result};
use capstone::{
    arch::{x86, BuildsCapstone, DetailsArchInsn},
    Capstone,
};
use memchr::memmem::Finder;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

pub struct Instruction {
    pub human_readable: String,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub mnemonic: x86::X86Insn,
    pub operands: Vec<x86::X86Operand>,
}

fn disassemble(code: &[u8], addr: u64, pointer_size: usize) -> Result<Vec<Instruction>> {
    let mut cs = Capstone::new()
        .x86()
        .mode(if pointer_size == 4 {
            x86::ArchMode::Mode32
        } else {
            x86::ArchMode::Mode64
        })
        .detail(true)
        .build()
        .map_err(|x| anyhow!(x))?;

    cs.set_skipdata(true).map_err(|x| anyhow!(x))?;

    let insns = cs.disasm_all(code, addr).map_err(|x| anyhow!(x))?;

    Ok(insns
        .iter()
        .filter_map(|x| {
            let mnemonic = x86::X86Insn::from(x.id().0);
            if mnemonic == x86::X86Insn::X86_INS_INVALID {
                return None;
            }
            let insn_detail = cs.insn_detail(x).unwrap();
            let arch_detail = insn_detail.arch_detail();

            let operands = arch_detail.x86().unwrap().operands();

            Some(Instruction {
                human_readable: format!("{} {}", x.mnemonic().unwrap_or(""), x.op_str().unwrap_or("")).trim().into(),
                address: x.address(),
                bytes: x.bytes().to_vec(),
                mnemonic,
                operands: operands.into_iter().collect(),
            })
        })
        .collect::<Vec<_>>())
}

pub fn disassemble_all(code: &[u8], addr: u64, pointer_size: usize) -> Result<Vec<Instruction>> {
    let cpus = rayon::current_num_threads();
    let step = code.len() / cpus;

    if step < 0x10000 {
        return disassemble(code, addr, pointer_size);
    }

    let int3_finder = Finder::new(b"\xcc\xcc\xcc\xcc\xcc");
    let nop_finder = Finder::new(b"\x90\x90\x90\x90\x90");
    let zero_finder = Finder::new(b"\x00\x00\x00\x00\x00");

    let split = (0..code.len())
        .step_by(step)
        .map(|x| {
            if x == 0 {
                x
            } else if x + step > code.len() {
                code.len()
            } else {
                let offset = int3_finder
                    .find(&code[x..])
                    .or_else(|| nop_finder.find(&code[x..]))
                    .or_else(|| zero_finder.find(&code[x..]))
                    .unwrap();
                x + offset
            }
        })
        .chain(iter::once(code.len()))
        .collect::<Vec<_>>()
        .windows(2)
        .filter_map(|x| (x[1] != x[0]).then(|| x[0]..x[1]))
        .collect::<Vec<_>>();

    let result = split
        .into_par_iter()
        .map(|x| {
            let start = x.start;
            let end = x.end;

            log::trace!("disassemble: {}..{} {:?}", start, end, std::thread::current().id());
            let result = disassemble(&code[x], addr + start as u64, pointer_size);
            log::trace!("disassemble done: {}..{}", start, end);

            result
        })
        .collect::<Result<Vec<_>, _>>()?; // do we have to collect twice?

    Ok(result.into_iter().flatten().collect())
}
