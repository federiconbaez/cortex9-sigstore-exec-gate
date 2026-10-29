//! Minimal static checks over an x86_64 ELF image (no external parser).

use anyhow::{bail, Result};

pub const PT_INTERP: u32 = 3;
pub const PT_GNU_STACK: u32 = 0x6474_e551;
pub const PF_X: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfInfo {
    pub interp: Option<String>,
    pub gnu_stack: Option<u32>,
    pub etype: u16,
}

fn u16le(b: &[u8], o: usize) -> Result<u16> {
    let s = b
        .get(o..o + 2)
        .ok_or_else(|| anyhow::anyhow!("truncated ELF"))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn u32le(b: &[u8], o: usize) -> Result<u32> {
    let s = b
        .get(o..o + 4)
        .ok_or_else(|| anyhow::anyhow!("truncated ELF"))?;
    Ok(u32::from_le_bytes(s.try_into().unwrap()))
}
fn u64le(b: &[u8], o: usize) -> Result<u64> {
    let s = b
        .get(o..o + 8)
        .ok_or_else(|| anyhow::anyhow!("truncated ELF"))?;
    Ok(u64::from_le_bytes(s.try_into().unwrap()))
}

/// Parse and enforce the static policy:
/// * ELF64, little endian, EM_X86_64, ET_EXEC or ET_DYN
///   (32-bit images are refused: they would run through the ia32 syscall ABI);
/// * a PT_GNU_STACK header must exist and must not carry PF_X when
///   `require_nx_stack` is set (otherwise the kernel maps an executable stack).
pub fn inspect(b: &[u8], require_nx_stack: bool) -> Result<ElfInfo> {
    if b.len() < 64 || &b[0..4] != b"\x7fELF" {
        bail!("not an ELF image");
    }
    if b[4] != 2 {
        bail!("refused: not ELFCLASS64 (32-bit images are out of policy)");
    }
    if b[5] != 1 {
        bail!("refused: not little endian");
    }
    let etype = u16le(b, 16)?;
    if etype != 2 && etype != 3 {
        bail!("refused: e_type {etype} is not ET_EXEC/ET_DYN");
    }
    if u16le(b, 18)? != 62 {
        bail!("refused: e_machine is not EM_X86_64");
    }
    let phoff = u64le(b, 32)? as usize;
    let phentsize = u16le(b, 54)? as usize;
    let phnum = u16le(b, 56)? as usize;
    if phentsize < 56 {
        bail!("bad e_phentsize");
    }
    let mut interp = None;
    let mut gnu_stack = None;
    for i in 0..phnum {
        let o = i
            .checked_mul(phentsize)
            .and_then(|x| x.checked_add(phoff))
            .ok_or_else(|| anyhow::anyhow!("program header offset overflow"))?;
        let ptype = u32le(b, o)?;
        let flags = u32le(b, o + 4)?;
        if ptype == PT_INTERP {
            let off = u64le(b, o + 8)? as usize;
            let sz = u64le(b, o + 32)? as usize;
            let end = off
                .checked_add(sz)
                .ok_or_else(|| anyhow::anyhow!("overflow"))?;
            let raw = b
                .get(off..end)
                .ok_or_else(|| anyhow::anyhow!("PT_INTERP out of bounds"))?;
            let raw = raw.split(|c| *c == 0).next().unwrap_or(&[]);
            let s = std::str::from_utf8(raw)?;
            if !s.starts_with('/') {
                bail!("refused: PT_INTERP is not absolute");
            }
            interp = Some(s.to_string());
        } else if ptype == PT_GNU_STACK {
            gnu_stack = Some(flags);
        }
    }
    if require_nx_stack {
        match gnu_stack {
            None => bail!("refused: no PT_GNU_STACK (kernel may default to an executable stack)"),
            Some(f) if f & PF_X != 0 => bail!("refused: PT_GNU_STACK requests an executable stack"),
            _ => {}
        }
    }
    Ok(ElfInfo {
        interp,
        gnu_stack,
        etype,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf_and_truncated() {
        assert!(inspect(b"#!/bin/sh\necho hi\n", true).is_err());
        assert!(inspect(b"\x7fELF", true).is_err());
    }

    #[test]
    fn inspects_own_test_binary() {
        let exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let info = inspect(&exe, true).expect("rust test binary should pass the static policy");
        assert!(info.gnu_stack.is_some());
    }

    #[test]
    fn rejects_32bit_and_exec_stack() {
        let mut exe = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let mut b32 = exe.clone();
        b32[4] = 1;
        assert!(inspect(&b32, true)
            .unwrap_err()
            .to_string()
            .contains("ELFCLASS64"));
        let phoff = u64le(&exe, 32).unwrap() as usize;
        let n = u16le(&exe, 56).unwrap() as usize;
        let mut patched = false;
        for i in 0..n {
            let o = phoff + i * 56;
            if u32le(&exe, o).unwrap() == PT_GNU_STACK {
                exe[o + 4] |= PF_X as u8;
                patched = true;
            }
        }
        assert!(patched);
        assert!(inspect(&exe, true)
            .unwrap_err()
            .to_string()
            .contains("executable stack"));
        assert!(inspect(&exe, false).is_ok());
    }
}
