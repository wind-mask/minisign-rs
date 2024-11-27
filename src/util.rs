use std::cmp;

use crate::{errors::Result, ErrorKind, SError};
pub fn raw_scrypt_params(memlimit: usize, opslimit: u64, n_log2_max: u8) -> Result<scrypt::Params> {
    let opslimit = cmp::max(32768, opslimit);
    let mut n_log2 = 1u8;
    let r = 8u32;
    let p;
    if opslimit < (memlimit / 32) as u64 {
        p = 1;
        let maxn = opslimit / (u64::from(r) * 4);
        while n_log2 < 63 {
            if 1u64 << n_log2 > maxn / 2 {
                break;
            }
            n_log2 += 1;
        }
    } else {
        let maxn = memlimit as u64 / (u64::from(r) * 128);
        while n_log2 < 63 {
            if 1u64 << n_log2 > maxn / 2 {
                break;
            }
            n_log2 += 1;
        }
        let maxrp = cmp::min(0x3fff_ffff_u32, ((opslimit / 4) / (1u64 << n_log2)) as u32);
        p = maxrp / r;
    }
    if n_log2 > n_log2_max {
        return Err(SError::new(ErrorKind::Kdf, "scrypt parameters too high"));
    }
    scrypt::Params::new(n_log2, r, p, scrypt::Params::RECOMMENDED_LEN).map_err(Into::into)
}
