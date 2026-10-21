const TRITS: usize = 6; // 3^6 = 729 rings (-364..=364)
const INCREMENT: u64 = 0x9E3779B97F4A7C15;

// Integer -> balanced ternary, least-significant trit first
fn to_trits(mut n: i32) -> [i8; TRITS] {
    let mut t = [0i8; TRITS];
    for slot in t.iter_mut() {
        let mut r = n.rem_euclid(3);
        if r == 2 { r = -1; }      // digit 2 becomes -1 with a carry
        *slot = r as i8;
        n = (n - r) / 3;
    }
    t
}

const fn mix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

// Baked at compile time: one constant per (trit position, trit value)
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

// Baked CRC-16/CCITT table for the checksum
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

fn crc16(bytes: &[u8]) -> u16 {
    bytes.iter().fold(0xFFFF, |c, &b| (c << 8) ^ CRC_TABLE[((c >> 8) as u8 ^ b) as usize])
}

struct Carny { seed: u64, state: u64 }

impl Carny {
    fn new_at_ring(key: u64, nonce: u64, ring: i32) -> Self {
        // Enforce boundary safety for raw inputs
        let bounded_ring = ring.clamp(-364, 364);
        let trits = to_trits(bounded_ring);
        let mut ring_mask = 0u64;
        for (pos, &t) in trits.iter().enumerate() {
            ring_mask ^= TRIT_TABLE[pos][(t + 1) as usize];
        }
        let seed = mix(key ^ mix(nonce) ^ mix(ring_mask));
        Carny { seed, state: seed }
    }

    fn next_mask(&mut self) -> u64 {
        self.state = self.state.wrapping_add(INCREMENT);
        mix(self.state)
    }

    // Returns (cipher, encrypted checksum)
    fn seal(&mut self, plain: u64) -> (u64, u16) {
        let tag = crc16(&plain.to_le_bytes());
        let m = self.next_mask();
        (plain ^ m, tag ^ (m >> 48) as u16)
    }

    // Some(plain) only if the checksum passes
    fn open(&mut self, (c, t): (u64, u16)) -> Option<u64> {
        let m = self.next_mask();
        let plain = c ^ m;
        (crc16(&plain.to_le_bytes()) == t ^ (m >> 48) as u16).then_some(plain)
    }
}

// Receiver: try the measured ring and its neighbors (the three lowest-trit cases)
fn receive(key: u64, nonce: u64, measured: i32, msg: (u64, u16)) -> Option<u64> {
    [0, -1, 1].iter().find_map(|d| Carny::new_at_ring(key, nonce, measured + d).open(msg))
}

fn main() {
    let (key, nonce) = (0xC0FFEE, 12345);
    let target_ring = 4;

    let msg = Carny::new_at_ring(key, nonce, target_ring).seal(55555);

    for ring in -2..=10 {
        let got = Carny::new_at_ring(key, nonce, ring).open(msg);
        println!("ring {:>3}: {:?}", ring, got);
    }

    // Validation checks
    assert_eq!(receive(key, nonce, 5, msg), Some(55555));
    assert_eq!(receive(key, nonce, 7, msg), None);
}
