//! SHA3-256 (FIPS 202) and RFC 4648 base32, for deriving a v3 onion address
//! from its public key: base32(PUBKEY || SHA3-256(".onion checksum" || PUBKEY
//! || 0x03)[:2] || 0x03).

const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];
const ROT: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

fn keccak_f(a: &mut [u64; 25]) {
    for rc in RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(ROT[x + 5 * y]);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        a[0] ^= rc;
    }
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    const RATE: usize = 136;
    let mut st = [0u64; 25];
    let mut msg = data.to_vec();
    msg.push(0x06);
    while msg.len() % RATE != 0 {
        msg.push(0);
    }
    let last = msg.len() - 1;
    msg[last] |= 0x80;
    for block in msg.chunks(RATE) {
        for (i, lane) in block.chunks(8).enumerate() {
            let mut w = [0u8; 8];
            w.copy_from_slice(lane);
            st[i] ^= u64::from_le_bytes(w);
        }
        keccak_f(&mut st);
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&st[i].to_le_bytes());
    }
    out
}

pub fn base32_lower(data: &[u8]) -> String {
    const A: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in data {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// derive_onion(pubkey): the v3 address for a 32-byte Ed25519 public key.
pub fn derive_onion(pubkey: &[u8]) -> Option<String> {
    if pubkey.len() != 32 {
        return None;
    }
    let mut m = b".onion checksum".to_vec();
    m.extend_from_slice(pubkey);
    m.push(3);
    let ck = sha3_256(&m);
    let mut raw = pubkey.to_vec();
    raw.extend_from_slice(&ck[..2]);
    raw.push(3);
    Some(base32_lower(&raw) + ".onion")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn known_vectors() {
        assert_eq!(
            hex(&sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
        assert_eq!(
            hex(&sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
        let long = vec![b'a'; 200];
        assert_eq!(
            hex(&sha3_256(&long)),
            "cce34485baf2bf2aca99b94833892a4f52896d3d153f7b840cc4f9fe695f1387"
        );
    }

    #[test]
    fn onion_of_zero_key() {
        // python3 -c 'import hashlib,base64;p=bytes(32);c=hashlib.sha3_256(b".onion checksum"+p+b"\x03").digest()[:2];print(base64.b32encode(p+c+b"\x03").decode().lower())'
        let o = derive_onion(&[0u8; 32]).unwrap();
        assert_eq!(
            o,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaam2dqd.onion"
        );
    }
}
