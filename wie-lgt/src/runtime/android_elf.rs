//! Experimental Android ARM ELF32 ET_DYN mapper for LGT Clets.
//!
//! This mapper is intentionally non-executable while Android dynamic imports
//! and DT_NEEDED providers are unresolved. It is opt-in and does not change the
//! original LGT ET_EXEC loader.

use alloc::{format, vec, vec::Vec};

use wie_core_arm::ArmCore;
use wie_util::{Result, WieError};

const BASE: u32 = 0x1000_0000;
const MAX_IMAGE: usize = 64 * 1024 * 1024;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NEEDED: u32 = 1;
const DT_PLTRELSZ: u32 = 2;
const DT_REL: u32 = 17;
const DT_RELSZ: u32 = 18;
const DT_RELENT: u32 = 19;
const DT_PLTREL: u32 = 20;
const DT_JMPREL: u32 = 23;
const R_ARM_GLOB_DAT: u32 = 21;
const R_ARM_JUMP_SLOT: u32 = 22;
const R_ARM_RELATIVE: u32 = 23;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfMapping {
    pub entry: u32,
    pub needed: usize,
    pub relative: usize,
    pub unresolved: usize,
}

#[derive(Clone, Copy)]
struct Segment {
    kind: u32,
    file_offset: usize,
    vaddr: usize,
    filesz: usize,
    memsz: usize,
}

fn invalid(reason: &str) -> WieError {
    WieError::FatalError(format!("Android ELF32: {reason}"))
}

fn u16_at(data: &[u8], at: usize) -> Result<u16> {
    let b = data.get(at..at.saturating_add(2)).ok_or_else(|| invalid("short u16"))?;
    if b.len() != 2 {
        return Err(invalid("short u16"));
    }
    Ok(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32> {
    let b = data.get(at..at.saturating_add(4)).ok_or_else(|| invalid("short u32"))?;
    if b.len() != 4 {
        return Err(invalid("short u32"));
    }
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn put32(data: &mut [u8], at: usize, value: u32) -> Result<()> {
    let b = data.get_mut(at..at.saturating_add(4)).ok_or_else(|| invalid("relocation out of bounds"))?;
    if b.len() != 4 {
        return Err(invalid("relocation out of bounds"));
    }
    b.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn offset(addr: usize, len: usize, low: usize, high: usize) -> Result<usize> {
    if addr < low || addr.checked_add(len).is_none_or(|end| end > high) {
        return Err(invalid("virtual address outside mapped image"));
    }
    Ok(addr - low)
}

fn relocate(image: &mut [u8], low: usize, high: usize, dynamic: &[(u32, u32)]) -> Result<(usize, usize)> {
    let tag = |key: u32| dynamic.iter().find_map(|(t, v)| (*t == key).then_some(*v as usize));
    if tag(DT_RELENT).is_some_and(|len| len != 8) {
        return Err(invalid("unsupported REL entry size"));
    }
    if tag(DT_PLTREL).is_some_and(|kind| kind != DT_REL as usize) {
        return Err(invalid("RELA PLT entries unsupported"));
    }
    let mut relative = 0usize;
    let mut unresolved = 0usize;
    for (table, len) in [
        (tag(DT_REL), tag(DT_RELSZ).unwrap_or(0)),
        (tag(DT_JMPREL), tag(DT_PLTRELSZ).unwrap_or(0)),
    ] {
        if len == 0 {
            continue;
        }
        let addr = table.ok_or_else(|| invalid("relocation table address missing"))?;
        if len % 8 != 0 {
            return Err(invalid("malformed REL size"));
        }
        let start = offset(addr, len, low, high)?;
        // Snapshot the table: relocations are allowed to modify their image.
        let records = image[start..start + len].to_vec();
        for row in records.chunks_exact(8) {
            let place = u32::from_le_bytes(row[0..4].try_into().unwrap()) as usize;
            let info = u32::from_le_bytes(row[4..8].try_into().unwrap());
            let at = offset(place, 4, low, high)?;
            match info & 0xff {
                R_ARM_RELATIVE if (info >> 8) == 0 => {
                    let original = u32_at(image, at)?;
                    put32(image, at, original.wrapping_add(BASE.wrapping_sub(low as u32)))?;
                    relative += 1;
                }
                R_ARM_GLOB_DAT | R_ARM_JUMP_SLOT if (info >> 8) != 0 => {
                    // Do not invent addresses for Android/phone/WIPI imports.
                    unresolved += 1;
                }
                _ => return Err(invalid("unknown ARM relocation")),
            }
        }
    }
    Ok((relative, unresolved))
}

/// Load the segments and relative relocations; never execute this image until
/// the dynamic linker, import ABI, and Clet event registration are implemented.
pub fn map_android_elf(core: &mut ArmCore, data: &[u8]) -> Result<ElfMapping> {
    if data.get(0..6) != Some(&b"\x7fELF\x01\x01"[..])
        || u16_at(data, 16)? != 3
        || u16_at(data, 18)? != 40
    {
        return Err(invalid("requires little-endian ARM ELF32 ET_DYN"));
    }
    let phoff = u32_at(data, 28)? as usize;
    let count = u16_at(data, 44)? as usize;
    if u16_at(data, 42)? != 32 || count == 0
        || phoff.checked_add(count * 32).is_none_or(|end| end > data.len())
    {
        return Err(invalid("invalid program headers"));
    }
    let mut segments = Vec::new();
    for i in 0..count {
        let at = phoff + 32 * i;
        let seg = Segment {
            kind: u32_at(data, at)?,
            file_offset: u32_at(data, at + 4)? as usize,
            vaddr: u32_at(data, at + 8)? as usize,
            filesz: u32_at(data, at + 16)? as usize,
            memsz: u32_at(data, at + 20)? as usize,
        };
        if seg.filesz > seg.memsz
            || seg.file_offset.checked_add(seg.filesz).is_none_or(|end| end > data.len())
            || seg.vaddr.checked_add(seg.memsz).is_none()
        {
            return Err(invalid("invalid segment bounds"));
        }
        segments.push(seg);
    }
    let low = segments.iter().filter(|s| s.kind == PT_LOAD)
        .map(|s| s.vaddr).min().ok_or_else(|| invalid("missing PT_LOAD"))?;
    let high = segments.iter().filter(|s| s.kind == PT_LOAD)
        .map(|s| s.vaddr + s.memsz).max().ok_or_else(|| invalid("missing PT_LOAD"))?;
    if high <= low || high - low > MAX_IMAGE || high > (u32::MAX - BASE) as usize {
        return Err(invalid("mapped image too large"));
    }
    let mut image = vec![0u8; high - low];
    for s in segments.iter().filter(|s| s.kind == PT_LOAD) {
        let off = offset(s.vaddr, s.memsz, low, high)?;
        image[off..off + s.filesz].copy_from_slice(&data[s.file_offset..s.file_offset + s.filesz]);
    }
    let mut dynamic = Vec::new();
    for s in segments.iter().filter(|s| s.kind == PT_DYNAMIC) {
        if s.filesz % 8 != 0 {
            return Err(invalid("invalid dynamic segment size"));
        }
        for at in (s.file_offset..s.file_offset + s.filesz).step_by(8) {
            let key = u32_at(data, at)?;
            if key == 0 {
                break;
            }
            dynamic.push((key, u32_at(data, at + 4)?));
        }
    }
    if dynamic.is_empty() {
        return Err(invalid("missing dynamic table"));
    }
    let needed = dynamic.iter().filter(|(key, _)| *key == DT_NEEDED).count();
    let (relative, unresolved) = relocate(&mut image, low, high, &dynamic)?;
    let entry = u32_at(data, 24)? as usize;
    if entry < low || entry >= high {
        return Err(invalid("entrypoint outside image"));
    }
    core.load(&image, BASE, image.len())?;
    Ok(ElfMapping {
        entry: BASE + (entry - low) as u32,
        needed,
        relative,
        unresolved,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_relocations_use_load_bias() -> Result<()> {
        let mut image = vec![0u8; 64];
        put32(&mut image, 4, 42)?;
        put32(&mut image, 16, 0x1004)?;
        put32(&mut image, 20, R_ARM_RELATIVE)?;
        put32(&mut image, 24, 0x1008)?;
        put32(&mut image, 28, (1 << 8) | R_ARM_JUMP_SLOT)?;
        let (relative, unresolved) = relocate(
            &mut image, 0x1000, 0x1040,
            &[(DT_REL, 0x1010), (DT_RELSZ, 16), (DT_RELENT, 8)],
        )?;
        assert_eq!((relative, unresolved), (1, 1));
        assert_eq!(u32_at(&image, 4)?, BASE.wrapping_sub(0x1000) + 42);
        Ok(())
    }

    #[test]
    fn unknown_relocation_is_not_accepted() -> Result<()> {
        let mut image = vec![0u8; 40];
        put32(&mut image, 16, 0x1000)?;
        put32(&mut image, 20, 0x7f)?;
        assert!(relocate(&mut image, 0x1000, 0x1028, &[(DT_REL, 0x1010), (DT_RELSZ, 8)]).is_err());
        Ok(())
    }
}
