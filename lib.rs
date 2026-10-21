//! Carny: a toy ring-gated stream cipher.
//!
//! A message is sealed for a specific distance "ring" (a balanced-ternary
//! number). Receivers at any other ring derive a different keystream, so the
//! checksum fails and `open` returns `None`. The decay is the point.
//!
//! NOT real cryptography. SplitMix64 is invertible; do not protect anything
//! that matters with this.

pub const TRITS: usize = 6; // 3^6 = 729 rings (-364..=364)
pub const MAX_RING: i32 = 364;
pub const INCREMENT: u64 = 0x9E3779B97F4A7C15;

/// Integer -> balanced ternary, least-significant trit first.
pub fn to_trits(mut n: i32) -> [i8; TRITS] {
    let mut t = [0i8; TRITS];
    for slot in t.iter_mut() {
        let mut r = n.rem_euclid(3);
        if r == 2 {
            r = -1; // digit 2 becomes -1 with a carry
        }
        *slot = r as i8;
        n = (n - r) / 3;
    }
    t
}

/// Balanced ternary (least-significant first) -> integer.
pub fn from_trits(t: &[i8; TRITS]) -> i32 {
    t.iter().rev().fold(0, |acc, &d| acc * 3 + d as i32)
}

/// SplitMix64 bit mixer.
pub const fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

/// Baked at compile time: one constant per (trit position, trit value).
const TRIT_TABLE: [[u64; 3]; TRITS] = {
    let mut t = [[0u64; 3]; TRITS];
    let mut i = 0;
    while i < TRITS {
        let mut j = 0;
        while j < 3 {
            t[i][j] = mix(0xCA2217u64.wrapping_add(((i * 3 + j) as u64).wrapping_mul(INCREMENT)));
            j += 1;
        }
        i += 1;
    }
    t
};

/// Baked CRC-16/CCITT table for the checksum.
const CRC_TABLE: [u16; 256] = {
    let mut t = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = (i as u16) << 8;
        let mut b = 0;
        while b < 8 {
            c = if c & 0x8000 != 0 { (c << 1) ^ 0x1021 } else { c << 1 };
            b += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

pub fn crc16(bytes: &[u8]) -> u16 {
    bytes
        .iter()
        .fold(0xFFFF, |c, &b| (c << 8) ^ CRC_TABLE[((c >> 8) as u8 ^ b) as usize])
}

pub struct Carny {
    seed: u64,
    state: u64,
}

impl Carny {
    /// Build a cipher for a ring. Rings outside -364..=364 don't exist, so
    /// they return `None` rather than saturating onto the edge ring.
    pub fn new_at_ring(key: u64, nonce: u64, ring: i32) -> Option<Self> {
        if !(-MAX_RING..=MAX_RING).contains(&ring) {
            return None;
        }
        let mut ring_mask = 0u64;
        for (pos, &t) in to_trits(ring).iter().enumerate() {
            ring_mask ^= TRIT_TABLE[pos][(t + 1) as usize];
        }
        let seed = mix(key ^ mix(nonce) ^ mix(ring_mask));
        Some(Carny { seed, state: seed })
    }

    fn next_mask(&mut self) -> u64 {
        self.state = self.state.wrapping_add(INCREMENT);
        mix(self.state)
    }

    /// Jump directly to keystream index `index` (0-indexed).
    pub fn seek(&mut self, index: u64) {
        self.state = self.seed.wrapping_add(index.wrapping_mul(INCREMENT));
    }

    /// Returns (ciphertext, encrypted checksum).
    pub fn seal(&mut self, plain: u64) -> (u64, u16) {
        let tag = crc16(&plain.to_le_bytes());
        let m = self.next_mask();
        (plain ^ m, tag ^ (m >> 48) as u16)
    }

    /// `Some(plain)` only if the checksum passes.
    pub fn open(&mut self, (c, t): (u64, u16)) -> Option<u64> {
        let m = self.next_mask();
        let plain = c ^ m;
        (crc16(&plain.to_le_bytes()) == t ^ (m >> 48) as u16).then_some(plain)
    }
}

/// Receiver: try the measured ring and its neighbors (jitter tolerance).
pub fn receive(key: u64, nonce: u64, measured: i32, msg: (u64, u16)) -> Option<u64> {
    [0, -1, 1].iter().find_map(|d| {
        Carny::new_at_ring(key, nonce, measured.saturating_add(*d))?.open(msg)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: u64 = 0xC0FFEE;
    const NONCE: u64 = 12345;

    #[test]
    fn trits_round_trip() {
        for n in -MAX_RING..=MAX_RING {
            assert_eq!(from_trits(&to_trits(n)), n);
        }
    }

    #[test]
    fn all_rings_have_distinct_trits() {
        let mut seen = std::collections::HashSet::new();
        for n in -MAX_RING..=MAX_RING {
            assert!(seen.insert(to_trits(n)), "duplicate trits for {n}");
        }
        assert_eq!(seen.len(), 729);
    }

    #[test]
    fn two_is_minus_one_with_carry() {
        assert_eq!(to_trits(2), [-1, 1, 0, 0, 0, 0]);
    }

    #[test]
    fn crc_known_vector() {
        // CRC-16/CCITT-FALSE check value for "123456789"
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }

    #[test]
    fn only_target_ring_opens() {
        let msg = Carny::new_at_ring(KEY, NONCE, 4).unwrap().seal(55555);
        for ring in -MAX_RING..=MAX_RING {
            let got = Carny::new_at_ring(KEY, NONCE, ring).unwrap().open(msg);
            if ring == 4 {
                assert_eq!(got, Some(55555));
            } else {
                assert_eq!(got, None, "ring {ring} should be dark");
            }
        }
    }

    #[test]
    fn out_of_range_rings_do_not_exist() {
        assert!(Carny::new_at_ring(KEY, NONCE, 365).is_none());
        assert!(Carny::new_at_ring(KEY, NONCE, -365).is_none());
        assert!(Carny::new_at_ring(KEY, NONCE, i32::MAX).is_none());
        assert!(Carny::new_at_ring(KEY, NONCE, i32::MIN).is_none());
    }

    #[test]
    fn edge_ring_is_not_a_saturation_hole() {
        let msg = Carny::new_at_ring(KEY, NONCE, 364).unwrap().seal(1);
        assert_eq!(receive(KEY, NONCE, 5000, msg), None);
        assert_eq!(receive(KEY, NONCE, 364, msg), Some(1));
    }

    #[test]
    fn receive_tolerates_one_ring_of_jitter() {
        let msg = Carny::new_at_ring(KEY, NONCE, 4).unwrap().seal(55555);
        assert_eq!(receive(KEY, NONCE, 3, msg), Some(55555));
        assert_eq!(receive(KEY, NONCE, 4, msg), Some(55555));
        assert_eq!(receive(KEY, NONCE, 5, msg), Some(55555));
        assert_eq!(receive(KEY, NONCE, 7, msg), None);
        assert_eq!(receive(KEY, NONCE, i32::MAX, msg), None);
    }

    #[test]
    fn seek_recovers_out_of_order_message() {
        let mut sender = Carny::new_at_ring(KEY, NONCE, 4).unwrap();
        let msgs = [11111u64, 22222, 33333, 44444, 55555];
        let cipher: Vec<_> = msgs.iter().map(|&m| sender.seal(m)).collect();

        let mut receiver = Carny::new_at_ring(KEY, NONCE, 4).unwrap();
        receiver.seek(3);
        assert_eq!(receiver.open(cipher[3]), Some(msgs[3]));
    }

    #[test]
    fn same_plaintext_gives_different_ciphertexts() {
        let mut c = Carny::new_at_ring(KEY, NONCE, 4).unwrap();
        let a = c.seal(55555);
        let b = c.seal(55555);
        assert_ne!(a, b);
    }
}
