use capstone::{
    arch::{x86, DetailsArchInsn},
    Capstone, Insn, RegId,
};
use std::collections::{btree_map::Entry, BTreeMap, BTreeSet};

use anyhow::{anyhow, Result};
use object::{Object, ObjectSection};

use super::{context::Context, util::convert_pointer};

#[derive(Eq, PartialEq, Debug)]
pub struct VTable {
    pub address: u64,
    pub references: Vec<u64>,
}

pub fn find_vtables(context: &Context<'_>) -> Result<Vec<VTable>> {
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
    let insns = context
        .cs
        .disasm_all(text_section.data()?, text_section.address())
        .map_err(|x| anyhow!(x))?;

    let mut vtables = BTreeMap::new();

    fn vtable_found(vtables: &mut BTreeMap<u64, VTable>, address: u64, reference: u64) {
        if let Entry::Vacant(e) = vtables.entry(address) {
            e.insert(VTable {
                address,
                references: vec![reference],
            });
        } else {
            vtables.get_mut(&address).unwrap().references.push(reference);
        }
    }

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

                        vtable_found(&mut vtables, src_addr, insn.address());
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

                    vtable_found(&mut vtables, src_addr, insn.address());
                }
            }
        }
    }

    Ok(vtables.into_iter().map(|(_, v)| v).collect())
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

    use super::{find_vtables, Context, VTable};

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
        assert_eq!(
            vtables,
            &[
                VTable {
                    address: 0x40e164,
                    references: vec![0x40104a,],
                },
                VTable {
                    address: 0x40e16c,
                    references: vec![0x4010e6,],
                },
                VTable {
                    address: 0x40e174,
                    references: vec![0x4013bf, 0x4013e5, 0x4013fc,],
                },
                VTable {
                    address: 0x40e194,
                    references: vec![0x40135e, 0x40137c,],
                },
                VTable {
                    address: 0x40e1b0,
                    references: vec![0x401391, 0x4013af,],
                },
                VTable {
                    address: 0x40ecb0,
                    references: vec![0x403ae4, 0x403b02,],
                },
            ]
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_x64() -> anyhow::Result<()> {
        init();

        let file = fs::read("./test_data/msvc_rtti1_64.exe").await?;
        let obj = object::File::parse(&*file)?;
        let context = Context::new(obj)?;

        let vtables = find_vtables(&context)?;
        assert_eq!(
            vtables,
            &[
                VTable {
                    address: 0x140010318,
                    references: vec![0x14000106a,],
                },
                VTable {
                    address: 0x140010338,
                    references: vec![0x14000149c,],
                },
                VTable {
                    address: 0x140010368,
                    references: vec![0x1400013d9, 0x1400013fc,],
                },
                VTable {
                    address: 0x140010390,
                    references: vec![0x140001435, 0x140001458,],
                },
                VTable {
                    address: 0x1400113a0,
                    references: vec![0x1400044dd, 0x140004500,],
                },
            ]
        );

        Ok(())
    }
}
