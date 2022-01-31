use capstone::{arch::x86, RegId};
use std::collections::BTreeSet;

use anyhow::Result;
use object::{ObjectSection, Section};

use super::{instruction::Instruction, util::convert_pointer};

#[allow(clippy::type_complexity)]
pub fn find_vtables(
    insns: &[Instruction],
    text_section: &Section,
    rdata_section: &Section,
    pointer_size: usize,
) -> Result<(Vec<u64>, Vec<(u64, u64)>)> {
    let rdata = rdata_section.data()?;

    // 1. Find vtable candidates
    struct State {
        last: Option<u64>,
        all: BTreeSet<u64>,
    }

    let vtable_candidates = rdata
        .windows(pointer_size)
        .enumerate()
        .step_by(pointer_size)
        .fold(
            State {
                last: None,
                all: BTreeSet::new(),
            },
            |mut state, (i, x)| {
                let ptr = convert_pointer(x, pointer_size);

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
    let mut vtables = BTreeSet::new();
    let mut xrefs = Vec::new();

    let mut it = insns.iter().peekable();
    while let Some(insn) = it.next() {
        // test if x64; lea reg, [rip + x]; mov [dest], reg
        if insn.mnemonic == x86::X86Insn::X86_INS_LEA {
            let operand_types = insn.operands.iter().map(|x| &x.op_type).collect::<Vec<_>>();

            if let [x86::X86OperandType::Reg(reg), x86::X86OperandType::Mem(mem)] = &operand_types[..] {
                if mem.base().0 as u32 == x86::X86Reg::X86_REG_RIP {
                    let src_addr = (mem.disp() + insn.address as i64) as u64 + insn.bytes.len() as u64; // TODO: check overflow

                    if vtable_candidates.contains(&src_addr) && is_mov_from_reg_to_mem(it.peek().unwrap(), reg)? {
                        log::debug!("Found vtable {:#x}", src_addr);

                        vtables.insert(src_addr);
                        xrefs.push((src_addr, insn.address));
                    }
                }
            }
        }
        // test if x86; mov dword ptr [reg], offset
        if insn.mnemonic == x86::X86Insn::X86_INS_MOV {
            let operand_types = insn.operands.iter().map(|x| &x.op_type).collect::<Vec<_>>();

            if let [x86::X86OperandType::Mem(_), x86::X86OperandType::Imm(imm)] = &operand_types[..] {
                let src_addr = *imm as u64;
                if vtable_candidates.contains(&src_addr) {
                    log::debug!("Found vtable {:#x}", imm);

                    vtables.insert(src_addr);
                    xrefs.push((src_addr, insn.address));
                }
            }
        }
    }

    Ok((vtables.into_iter().collect(), xrefs))
}

fn is_mov_from_reg_to_mem(insn: &Instruction, reg: &RegId) -> Result<bool> {
    if insn.mnemonic != x86::X86Insn::X86_INS_MOV {
        return Ok(false);
    }
    let operand_types = insn.operands.iter().map(|x| &x.op_type).collect::<Vec<_>>();

    if let [x86::X86OperandType::Mem(_), x86::X86OperandType::Reg(insn_reg)] = &operand_types[..] {
        if insn_reg == reg {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use anyhow::anyhow;
    use object::{Object, ObjectSection};
    use tokio::fs;

    use super::find_vtables;
    use crate::instruction::disassemble_all;

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
        let object = object::File::parse(&*file)?;

        let pointer_size = if object.is_64() { 8 } else { 4 };

        let text_section = object.section_by_name(".text").ok_or(anyhow!("No .text section"))?;
        let rdata_section = object.section_by_name(".rdata").ok_or(anyhow!("No .rdata section"))?;

        let insns = disassemble_all(text_section.data()?, text_section.address(), pointer_size)?;

        let (vtables, xrefs) = find_vtables(&insns, &text_section, &rdata_section, pointer_size)?;
        println!("{:#x?}", xrefs);
        assert_eq!(vtables, [0x40e164, 0x40e16c, 0x40e174, 0x40e194, 0x40e1b0, 0x40ecb0,]);
        assert_eq!(
            xrefs,
            [
                (0x40e164, 0x40104a,),
                (0x40e16c, 0x4010e6,),
                (0x40e194, 0x40135e,),
                (0x40e194, 0x40137c,),
                (0x40e1b0, 0x401391,),
                (0x40e1b0, 0x4013af,),
                (0x40e174, 0x4013bf,),
                (0x40e174, 0x4013e5,),
                (0x40e174, 0x4013fc,),
                (0x40ecb0, 0x403ae4,),
                (0x40ecb0, 0x403b02,),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_x64() -> anyhow::Result<()> {
        init();

        let file = fs::read("./test_data/msvc_rtti1_64.exe").await?;
        let object = object::File::parse(&*file)?;
        let pointer_size = if object.is_64() { 8 } else { 4 };

        let text_section = object.section_by_name(".text").ok_or(anyhow!("No .text section"))?;
        let rdata_section = object.section_by_name(".rdata").ok_or(anyhow!("No .rdata section"))?;

        let insns = disassemble_all(text_section.data()?, text_section.address(), pointer_size)?;

        let (vtables, xrefs) = find_vtables(&insns, &text_section, &rdata_section, pointer_size)?;
        assert_eq!(vtables, [0x140010318, 0x140010338, 0x140010368, 0x140010390, 0x1400113a0]);
        assert_eq!(
            xrefs,
            [
                (0x140010318, 0x14000106a,),
                (0x140010368, 0x1400013d9,),
                (0x140010368, 0x1400013fc,),
                (0x140010390, 0x140001435,),
                (0x140010390, 0x140001458,),
                (0x140010338, 0x14000149c,),
                (0x1400113a0, 0x1400044dd,),
                (0x1400113a0, 0x140004500,),
            ]
        );
        Ok(())
    }
}
