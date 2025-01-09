//! # Bitcoin Binary Output Script Descriptor (BOSD)
//!
//! BOSD uses a simple binary format consisting of
//! a 1-byte type tag followed by a cryptographic payload.
//! The format is designed to be compact
//! and efficiently represent standard Bitcoin output types:
//! 
//! | Type | Payload Len | Payload Interpretation |
//! | ---- | ----------- | ---------------------- |
//! | 0    | ..=80       | `OP_RETURN` payload    |
//! | 1    | 20          | P2PKH hash             |
//! | 2    | 20          | P2SH hash              |
//! | 3    | 20          | P2WPKH hash            |
//! | 3    | 32          | P2WSH hash             |
//! | 4    | 32          | P2TR X-only PubKey     |

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
