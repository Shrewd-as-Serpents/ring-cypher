//! Tests of the design claims made about Carny.
//!
//! Run with: cargo test --release claims -- --nocapture --test-threads=1
//!
//! Some of these assert a *flaw* exists (named `flaw_*`); they pass when the
//! flaw is present, and will start failing if the design is later fixed.

use super::*;

const KEY: u64 = 0xC0FFEE;
const NONCE: u64 = 12345;

fn hd(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// The pre-mix ring mask, exactly as computed inside `new_at_ring`.
fn ring_mask(ring: i32) -> u64 {
    let mut m = 0u64;
    for (pos, &t) in to_trits(ring).iter().enumerate() {
        m ^= TRIT_TABLE[pos][(t + 1) as usize];
    }
    m
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(INCREMENT);
        mix(self.0)
    }
}

// ---------------------------------------------------------------------------
// Claim 1: ring changes cause radical, uncorrelated state divergence
// ---------------------------------------------------------------------------

#[test]
fn claim1_adjacent_rings_avalanche() {
    let mut rng = Rng(1);
    let (mut sum_seed, mut sum_mask, mut n) = (0u64, 0u64, 0u64);
    let (mut min_seed, mut max_seed) = (64u32, 0u32);

    for _ in 0..200 {
        let (key, nonce) = (rng.next(), rng.next());
        for r in -MAX_RING..MAX_RING {
            let mut a = Carny::new_at_ring(key, nonce, r).unwrap();
            let mut b = Carny::new_at_ring(key, nonce, r + 1).unwrap();
            let ds = hd(a.seed, b.seed);
            let dm = hd(a.next_mask(), b.next_mask());
            sum_seed += ds as u64;
            sum_mask += dm as u64;
            min_seed = min_seed.min(ds);
            max_seed = max_seed.max(ds);
            n += 1;
        }
    }
    let (ms, mm) = (sum_seed as f64 / n as f64, sum_mask as f64 / n as f64);
    println!(
        "claim1 avalanche over {n} adjacent-ring pairs: seed HD mean {ms:.2} (min {min_seed}, max {max_seed}), first-mask HD mean {mm:.2} (ideal 32)"
    );
    assert!((31.5..32.5).contains(&ms));
    assert!((31.5..32.5).contains(&mm));
    assert!(min_seed >= 8);
}

#[test]
fn claim1_ring_mask_is_xor_linear_before_mix() {
    // Rings 0, 1, 3, 4 have trits [0,0], [1,0], [0,1], [1,1] in the low two
    // positions and zeros elsewhere: a "rectangle" in trit space.
    assert_eq!(to_trits(0)[..2], [0, 0]);
    assert_eq!(to_trits(1)[..2], [1, 0]);
    assert_eq!(to_trits(3)[..2], [0, 1]);
    assert_eq!(to_trits(4)[..2], [1, 1]);

    let pre = ring_mask(0) ^ ring_mask(1) ^ ring_mask(3) ^ ring_mask(4);
    println!("claim1 pre-mix rectangle XOR = {pre:#018x} (0 means exactly linear)");
    assert_eq!(pre, 0, "table lookups combined with XOR are linear over GF(2)");

    // After the keyed mix wrapper the relation must be gone.
    let mut rng = Rng(7);
    let mut sum = 0u64;
    let trials = 20_000u64;
    for _ in 0..trials {
        let (key, nonce) = (rng.next(), rng.next());
        let s = |r| Carny::new_at_ring(key, nonce, r).unwrap().seed;
        sum += (s(0) ^ s(1) ^ s(3) ^ s(4)).count_ones() as u64;
    }
    let mean = sum as f64 / trials as f64;
    println!("claim1 post-mix rectangle XOR popcount mean = {mean:.2} (ideal 32)");
    assert!((31.5..32.5).contains(&mean));
}

#[test]
fn claim1_ring_space_is_tiny() {
    // "Completely preventing" tracking is about linearity, not secrecy: the
    // ring alone has only 729 values (~9.5 bits).
    let bits = (729f64).log2();
    println!("claim1 ring entropy = {bits:.2} bits");
    assert!(bits < 10.0);
}

// ---------------------------------------------------------------------------
// Claim 3: the CRC tag, masked with the top bits of the first mask, is a
// compact *authenticated* tag
// ---------------------------------------------------------------------------

#[test]
fn flaw_tag_mask_overlaps_cipher_mask() {
    // The tag is masked with (m >> 48), but those same 16 bits of m already
    // encrypt the top 16 bits of the plaintext. XORing them cancels the mask:
    //   (c >> 48) ^ t == (plain >> 48) ^ crc16(plain)    -- no key involved.
    let mut rng = Rng(3);
    for _ in 0..1000 {
        let (key, nonce, plain) = (rng.next(), rng.next(), rng.next());
        let ring = (rng.next() % 729) as i32 - MAX_RING;
        let (c, t) = Carny::new_at_ring(key, nonce, ring).unwrap().seal(plain);
        let leak = (c >> 48) as u16 ^ t;
        assert_eq!(leak, (plain >> 48) as u16 ^ crc16(&plain.to_le_bytes()));
    }

    // Practical consequence: a keyless guess-checker for plaintexts.
    let plain = 55555u64;
    let (c, t) = Carny::new_at_ring(KEY, NONCE, 4).unwrap().seal(plain);
    let leak = (c >> 48) as u16 ^ t;
    let hits = (0..(1u64 << 20))
        .filter(|p| (*p >> 48) as u16 ^ crc16(&p.to_le_bytes()) == leak)
        .count();
    println!(
        "flaw: keyless check of 2^20 candidate plaintexts leaves {hits} candidate(s) (expected ~17 incl. the true one)"
    );
    assert!(hits >= 1 && hits < 100);
}

#[test]
fn flaw_crc_tag_is_forgeable_without_key() {
    // CRC is affine over GF(2): crc(p ^ d) = crc(p) ^ crc(d) ^ crc(0).
    // So an attacker who knows nothing but the ciphertext can flip chosen
    // plaintext bits and fix the tag to match.
    let mut rng = Rng(11);
    let zero_crc = crc16(&[0u8; 8]);
    let mut forged_ok = 0;
    let trials = 1000;
    for _ in 0..trials {
        let (key, nonce, plain, d) = (rng.next(), rng.next(), rng.next(), rng.next());
        let ring = (rng.next() % 729) as i32 - MAX_RING;
        let (c, t) = Carny::new_at_ring(key, nonce, ring).unwrap().seal(plain);

        let forged = (c ^ d, t ^ crc16(&d.to_le_bytes()) ^ zero_crc);
        let got = Carny::new_at_ring(key, nonce, ring).unwrap().open(forged);
        if got == Some(plain ^ d) {
            forged_ok += 1;
        }
    }
    println!("flaw: {forged_ok}/{trials} keyless forgeries accepted by open()");
    assert_eq!(forged_ok, trials);
}

#[test]
fn claim3_false_accept_rate_matches_16_bits() {
    // How often does a *wrong* ring open a message by chance?
    let mut rng = Rng(99);
    let trials = 4_000_000u64;
    let mut accepted = 0u64;
    for _ in 0..trials {
        let (key, nonce, plain) = (rng.next(), rng.next(), rng.next());
        let target = (rng.next() % 729) as i32 - MAX_RING;
        let mut wrong = (rng.next() % 729) as i32 - MAX_RING;
        if wrong == target {
            wrong = if target == MAX_RING { -MAX_RING } else { target + 1 };
        }
        let msg = Carny::new_at_ring(key, nonce, target).unwrap().seal(plain);
        if Carny::new_at_ring(key, nonce, wrong).unwrap().open(msg).is_some() {
            accepted += 1;
        }
    }
    let expected = trials as f64 / 65536.0;
    println!(
        "claim3 false accepts: {accepted} in {trials} wrong-ring tries (expected ~{expected:.0}, rate {:.2e})",
        accepted as f64 / trials as f64
    );
    assert!(accepted > 25 && accepted < 110);
}
