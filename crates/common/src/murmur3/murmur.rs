/// The block mixer that a [`Digest`] delegates its rolling hash state to.
pub(crate) trait Bmixer {
    /// Mixes as many full blocks of `p` as fit and returns the offset of the bytes left over,
    /// leaving the tail to the caller rather than returning it as a subslice.
    fn bmix(&mut self, p: &[u8]) -> usize;

    fn size(&self) -> usize;

    /// The seed is read from the digest this mixer is embedded in.
    fn reset(&mut self, seed: u32);
}

///
/// The mixer is a separate field here rather than being embedded in the struct that owns it and
/// handed a pointer to its own container, which keeps the struct free of that self-reference. the `buf`, which backs the tail slice, is folded
/// into `tail`'s capacity — the tail is always its own copy at rest, so the reservation
/// plays the same role.
#[derive(Debug)]
pub(crate) struct Digest<M: Bmixer> {
    /// Digested input cumulative length.
    pub(crate) clen: usize,
    /// Up to one byte short of a full block: input that has not filled a block yet.
    pub(crate) tail: Vec<u8>,
    /// Seed for initializing the hash.
    pub(crate) seed: u32,
    pub(crate) mixer: M,
}

impl<M: Bmixer> Digest<M> {
    #[expect(clippy::unused_self, reason = "the block size is read off a digest, as the interface states")]
    pub(crate) const fn block_size(&self) -> usize {
        1
    }

    pub(crate) fn write(&mut self, p: &[u8]) -> usize {
        let n = p.len();
        self.clen += n;

        let mut p = p;
        if !self.tail.is_empty() {
            let size = self.mixer.size();
            let nfree = size - self.tail.len();
            if nfree < p.len() {
                let (head, rest) = p.split_at(nfree);
                let mut block = [0u8; 16];
                let (block_head, block_rest) = block.split_at_mut(self.tail.len());
                block_head.copy_from_slice(&self.tail);
                let (block_mid, _) = block_rest.split_at_mut(nfree);
                block_mid.copy_from_slice(head);
                let (filled, _) = block.split_at(size);
                let _ = self.mixer.bmix(filled);
                p = rest;
            } else {
                self.tail.extend_from_slice(p);
                let consumed = self.mixer.bmix(&self.tail);
                self.tail.drain(..consumed);
                return n;
            }
        }

        let consumed = self.mixer.bmix(p);
        self.tail.clear();
        let (_, left) = p.split_at(consumed);
        self.tail.extend_from_slice(left);

        n
    }

    pub(crate) fn reset(&mut self) {
        self.clen = 0;
        self.tail.clear();
        let seed = self.seed;
        self.mixer.reset(seed);
    }
}
