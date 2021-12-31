use capstone::{
    arch::{x86, DetailsArchInsn},
    Capstone, Insn, RegId,
};
use std::collections::BTreeSet;

use anyhow::{anyhow, Result};
use object::{Object, ObjectSection};

use super::{context::Context, util::convert_pointer};

pub fn find_vtables(context: &Context<'_>) -> Result<Vec<u64>> {
    let text_section = context.object.section_by_name(".text").ok_or(anyhow!("No .text section"))?;

    let rdata_section = context.object.section_by_name(".rdata").ok_or(anyhow!("No .rdata section"))?;
    let rdata = rdata_section.data()?;

    // 1. Find vtable candidates
    struct State {
        last: Option<u64>,
        all: BTreeSet<u64>,
    }

    let vtable_candidates = rdata
        .windows(context.pointer_size)
        .enumerate()
        .step_by(context.pointer_size)
        .fold(
            State {
                last: None,
                all: BTreeSet::new(),
            },
            |mut state, (i, x)| {
                let ptr = convert_pointer(x, context.pointer_size);

                if text_section.address() < ptr && ptr < text_section.address() + text_section.size() {
                    if state.last.is_none() {
                        let addr = i as u64 + rdata_section.address();

                        log::trace!("vtable candidate at {:#x}", addr);
                        state.last = Some(addr);
                    }
                } else if state.last.is_some() {
                    state.all.insert(state.last.unwrap());
                    state.last = None
                }

                state
            },
        )
        .all;

    // 2. Validate vtable candidates by parsing the code.
    let insns = context.disassemble()?;

    let mut vtables = BTreeSet::new();
    let mut it = insns.iter().peekable();
    while let Some(insn) = it.next() {
        let mnemonic = x86::X86Insn::from(insn.id().0);
        let insn_detail = context.cs.insn_detail(insn).map_err(|x| anyhow!(x))?;
        let arch_detail = insn_detail.arch_detail();

        // test if x64; lea reg, [rip + x]; mov [dest], reg
        if mnemonic == x86::X86Insn::X86_INS_LEA {
            let operand_types = arch_detail.x86().unwrap().operands().map(|x| x.op_type).collect::<Vec<_>>();

            if let [x86::X86OperandType::Reg(reg), x86::X86OperandType::Mem(mem)] = &operand_types[..] {
                if mem.base().0 as u32 == x86::X86Reg::X86_REG_RIP {
                    let src_addr = (mem.disp() + insn.address() as i64) as u64 + insn.bytes().len() as u64; // TODO: check overflow

                    if vtable_candidates.contains(&src_addr) && is_mov_from_reg_to_mem(&context.cs, it.peek().unwrap(), reg)? {
                        log::debug!("Found vtable {:#x}", src_addr);
                        vtables.insert(src_addr);
                    }
                }
            }
        }
        // test if x86; mov dword ptr [reg], offset
        if mnemonic == x86::X86Insn::X86_INS_MOV {
            let operand_types = arch_detail.x86().unwrap().operands().map(|x| x.op_type).collect::<Vec<_>>();

            if let [x86::X86OperandType::Mem(_), x86::X86OperandType::Imm(imm)] = &operand_types[..] {
                let src_addr = *imm as u64;
                if vtable_candidates.contains(&src_addr) {
                    log::debug!("Found vtable {:#x}", imm);
                    vtables.insert(src_addr);
                }
            }
        }
    }

    Ok(vtables.into_iter().collect())
}

fn is_mov_from_reg_to_mem(cs: &Capstone, insn: &Insn, reg: &RegId) -> Result<bool> {
    let insn_detail = cs.insn_detail(insn).map_err(|x| anyhow!(x))?;
    let arch_detail = insn_detail.arch_detail();
    let mnemonic = x86::X86Insn::from(insn.id().0);

    if mnemonic != x86::X86Insn::X86_INS_MOV {
        return Ok(false);
    }
    let operand_types = arch_detail.x86().unwrap().operands().map(|x| x.op_type).collect::<Vec<_>>();

    if let [x86::X86OperandType::Mem(_), x86::X86OperandType::Reg(insn_reg)] = &operand_types[..] {
        if insn_reg == reg {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use tokio::fs;

    use super::{find_vtables, Context};

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

        let vtables = find_vtables(&context)?;
        assert_eq!(vtables, &[0x40e164, 0x40e16c, 0x40e174, 0x40e194, 0x40e1b0, 0x40ecb0]);

        Ok(())
    }

    #[tokio::test]
    async fn test_x64() -> anyhow::Result<()> {
        init();

        let file = fs::read("./test_data/msvc_rtti1_64.exe").await?;
        let obj = object::File::parse(&*file)?;
        let context = Context::new(obj)?;

        let vtables = find_vtables(&context)?;

        assert_eq!(vtables, &[0x140010318, 0x140010338, 0x140010368, 0x140010390, 0x1400113a0]);

        Ok(())
    }
}
