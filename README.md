Balanced ternary ring stream cipher toy!

A message is sealed for a specific distance "ring" (a balanced-ternary
//! number). 
Receivers at any other ring derive a different keystream, so the
//! checksum fails and `open` returns `None`. The decay is the point.

SplitMix64 can’t be upgraded and its not secret. It’s built for speed and statistical randomness.

Every step is invertible, so one known plaintext/ciphertext pair gives you the mask, and running mix backwards gives you the state.

The state is just seed + i * INCREMENT, so once the state is known, every past and future mask is too.
64 bits of key and state is small enough to brute-force.

No cipher can fix: the ring comes from a physical measurement, and 729 values is only about 9.5 bits. 
It works as keyed context but never a secret, all real security has to come from the key.
