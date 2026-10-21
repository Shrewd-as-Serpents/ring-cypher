use carny::{crc16, mix, Carny};
use std::hint::black_box;
use std::time::Instant;

fn per_op<F: FnMut(u64) -> u64>(label: &str, n: u64, mut f: F) {
    let start = Instant::now();
    let mut acc = 0u64;
    for i in 0..n {
        acc = acc.wrapping_add(f(black_box(i)));
    }
    black_box(acc);
    let ns = start.elapsed().as_nanos() as f64 / n as f64;
    println!("{label:<34} {ns:>7.2} ns/op");
}

fn main() {
    let n = 20_000_000;
    let (key, nonce) = (0xC0FFEEu64, 12345u64);

    per_op("mix (one SplitMix64 round)", n, |i| mix(i));
    per_op("crc16 over 8 bytes (table)", n, |i| crc16(&i.to_le_bytes()) as u64);
    per_op("to_trits alone (6 div/mod by 3)", n, |i| {
        carny::to_trits((i % 729) as i32 - 364).iter().map(|&t| t as u64).sum()
    });
    per_op("new_at_ring (trits+table+3 mix)", n, |i| {
        let ring = (i % 729) as i32 - 364;
        // Setup cost only: build the cipher, then touch it once so it isn't optimized away.
        Carny::new_at_ring(key, nonce, ring).map_or(0, |mut c| c.seal(0).0)
    });
    per_op("new_at_ring + seal + open", n, |i| {
        let ring = (i % 729) as i32 - 364;
        let msg = Carny::new_at_ring(key, nonce, ring).unwrap().seal(i);
        Carny::new_at_ring(key, nonce, ring).unwrap().open(msg).unwrap_or(0)
    });
    per_op("seal only (reused cipher, no setup)", n, {
        let mut c = Carny::new_at_ring(key, nonce, 4).unwrap();
        move |i| c.seal(i).0
    });
}
