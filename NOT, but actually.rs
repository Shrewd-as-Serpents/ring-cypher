struct Carny {
    value: u64,
}

impl Carny {
    fn new(raw: u64, key: u64) -> Self {
        Carny { value: raw ^ key }
    }

    // Same operation both ways, so it's still an involution,
    // but now you need the key to undo it
    fn flip(&mut self, key: u64) {
        self.value ^= key;
    }
}
