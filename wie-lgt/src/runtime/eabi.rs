//! AAPCS32 soft-float and division helpers for Android-linked LGT modules.
//! Experimental: only symbol-exact imports are registered; game execution
//! remains guarded until the non-EABI LGT/Android ABI is complete.

use wie_core_arm::{ArmCore, SvcId};
use wie_util::{Result, WieError};

use super::SVC_CATEGORY_EABI;

const IDIV: u32 = 0;
const IDIVMOD: u32 = 1;
const UIDIVMOD: u32 = 2;
const LDIVMOD: u32 = 3;
const I2F: u32 = 4;
const I2D: u32 = 5;
const F2D: u32 = 6;
const D2F: u32 = 7;
const D2IZ: u32 = 8;
const FMUL: u32 = 9;
const FDIV: u32 = 10;
const FCMPGE: u32 = 11;
const DADD: u32 = 12;
const DSUB: u32 = 13;
const DMUL: u32 = 14;
const DDIV: u32 = 15;
const DCMPEQ: u32 = 16;
const DCMPGE: u32 = 17;
const DCMPGT: u32 = 18;
const DCMPLT: u32 = 19;

pub(super) fn symbol_id(name: &str) -> Option<u32> {
    Some(match name {
        "__aeabi_idiv" => IDIV,
        "__aeabi_idivmod" => IDIVMOD,
        "__aeabi_uidivmod" => UIDIVMOD,
        "__aeabi_ldivmod" => LDIVMOD,
        "__aeabi_i2f" => I2F,
        "__aeabi_i2d" => I2D,
        "__aeabi_f2d" => F2D,
        "__aeabi_d2f" => D2F,
        "__aeabi_d2iz" => D2IZ,
        "__aeabi_fmul" => FMUL,
        "__aeabi_fdiv" => FDIV,
        "__aeabi_fcmpge" => FCMPGE,
        "__aeabi_dadd" => DADD,
        "__aeabi_dsub" => DSUB,
        "__aeabi_dmul" => DMUL,
        "__aeabi_ddiv" => DDIV,
        "__aeabi_dcmpeq" => DCMPEQ,
        "__aeabi_dcmpge" => DCMPGE,
        "__aeabi_dcmpgt" => DCMPGT,
        "__aeabi_dcmplt" => DCMPLT,
        _ => return None,
    })
}

fn float64(lo: u32, hi: u32) -> f64 {
    f64::from_bits(u64::from(lo) | (u64::from(hi) << 32))
}

fn words64(n: u64) -> [u32; 2] {
    [n as u32, (n >> 32) as u32]
}

fn eval(id: u32, [r0, r1, r2, r3]: [u32; 4]) -> Result<(usize, [u32; 4])> {
    let a = float64(r0, r1);
    let b = float64(r2, r3);
    let mut out = [0u32; 4];
    let size = match id {
        IDIV | IDIVMOD => {
            if r1 == 0 { return Err(WieError::FatalError("EABI signed division by zero".into())); }
            let n = r0 as i32;
            let d = r1 as i32;
            out[0] = n.wrapping_div(d) as u32;
            if id == IDIVMOD {
                out[1] = n.wrapping_rem(d) as u32;
                2
            } else { 1 }
        }
        UIDIVMOD => {
            if r1 == 0 { return Err(WieError::FatalError("EABI unsigned division by zero".into())); }
            out[0] = r0 / r1;
            out[1] = r0 % r1;
            2
        }
        LDIVMOD => {
            let n = (u64::from(r0) | (u64::from(r1) << 32)) as i64;
            let d = (u64::from(r2) | (u64::from(r3) << 32)) as i64;
            if d == 0 { return Err(WieError::FatalError("EABI 64-bit division by zero".into())); }
            let quotient = words64(n.wrapping_div(d) as u64);
            let remainder = words64(n.wrapping_rem(d) as u64);
            out = [quotient[0], quotient[1], remainder[0], remainder[1]];
            4
        }
        I2F => { out[0] = (r0 as i32 as f32).to_bits(); 1 }
        I2D => { out[..2].copy_from_slice(&words64((r0 as i32 as f64).to_bits())); 2 }
        F2D => { out[..2].copy_from_slice(&words64((f32::from_bits(r0) as f64).to_bits())); 2 }
        D2F => { out[0] = (a as f32).to_bits(); 1 }
        D2IZ => { out[0] = (a as i32) as u32; 1 }
        FMUL => { out[0] = (f32::from_bits(r0) * f32::from_bits(r1)).to_bits(); 1 }
        FDIV => { out[0] = (f32::from_bits(r0) / f32::from_bits(r1)).to_bits(); 1 }
        FCMPGE => { out[0] = u32::from(f32::from_bits(r0) >= f32::from_bits(r1)); 1 }
        DADD | DSUB | DMUL | DDIV => {
            let result = match id { DADD => a + b, DSUB => a - b, DMUL => a * b, _ => a / b };
            out[..2].copy_from_slice(&words64(result.to_bits()));
            2
        }
        DCMPEQ | DCMPGE | DCMPGT | DCMPLT => {
            out[0] = u32::from(match id {
                DCMPEQ => a == b, DCMPGE => a >= b, DCMPGT => a > b, _ => a < b,
            });
            1
        }
        _ => return Err(WieError::FatalError("Unknown ARM EABI helper".into())),
    };
    Ok((size, out))
}

async fn handle_eabi_svc(core: &mut ArmCore, _: &mut (), id: SvcId) -> Result<()> {
    let (_, return_pc) = core.read_pc_lr()?;
    let args = [
        core.read_param(0)?, core.read_param(1)?,
        core.read_param(2)?, core.read_param(3)?,
    ];
    let (count, result) = eval(id.0, args)?;
    core.write_return_value(&result[..count])?;
    core.set_next_pc(return_pc)
}

pub(super) fn register(core: &mut ArmCore) -> Result<()> {
    core.register_svc_handler(SVC_CATEGORY_EABI, handle_eabi_svc, &())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_and_unsigned_division() -> Result<()> {
        assert_eq!(eval(IDIVMOD, [(-21i32) as u32, 4, 0, 0])?, (2, [(-5i32) as u32, (-1i32) as u32, 0, 0]));
        assert_eq!(eval(UIDIVMOD, [21, 4, 0, 0])?, (2, [5, 1, 0, 0]));
        assert!(eval(IDIV, [20, 0, 0, 0]).is_err());
        Ok(())
    }
    #[test]
    fn double_arguments_use_two_registers() -> Result<()> {
        let a = words64(7.5f64.to_bits());
        let b = words64(2.5f64.to_bits());
        let (_, result) = eval(DSUB, [a[0], a[1], b[0], b[1]])?;
        assert_eq!(float64(result[0], result[1]), 5.0);
        assert_eq!(eval(DCMPGT, [a[0], a[1], b[0], b[1]])?.1[0], 1);
        Ok(())
    }
    #[test]
    fn long_division_writes_four_result_words() -> Result<()> {
        let n = words64((-1_000_000_000_000i64) as u64);
        let d = words64(3);
        let (count, out) = eval(LDIVMOD, [n[0], n[1], d[0], d[1]])?;
        assert_eq!(count, 4);
        assert_eq!((u64::from(out[0]) | (u64::from(out[1]) << 32)) as i64, -333_333_333_333);
        assert_eq!((u64::from(out[2]) | (u64::from(out[3]) << 32)) as i64, -1);
        Ok(())
    }
}
