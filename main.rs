use carny::{receive, Carny};

fn main() {
    let (key, nonce) = (0xC0FFEE, 12345);
    let target_ring = 4;

    let msg = Carny::new_at_ring(key, nonce, target_ring)
        .expect("target ring in range")
        .seal(55555);

    for ring in -2..=10 {
        let got = Carny::new_at_ring(key, nonce, ring).and_then(|mut c| c.open(msg));
        println!("ring {:>3}: {:?}", ring, got);
    }

    // Receiver measured 5, true ring 4: the +/-1 retry finds it.
    assert_eq!(receive(key, nonce, 5, msg), Some(55555));
    // Measured 7 is too far off for the retry: stays dark.
    assert_eq!(receive(key, nonce, 7, msg), None);
    println!("ok");
}
