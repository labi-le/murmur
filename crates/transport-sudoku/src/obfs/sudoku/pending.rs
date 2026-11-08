#[derive(Debug, Default)]
pub(crate) struct PendingBuffer {
    data: Vec<u8>,
    off: usize,
}

pub(crate) fn new_pending_buffer(capacity: usize) -> PendingBuffer {
    PendingBuffer { data: Vec::with_capacity(capacity), off: 0 }
}

impl PendingBuffer {
    pub(crate) const fn available(&self) -> usize {
        self.data.len() - self.off
    }

    pub(crate) fn reset(&mut self) {
        self.data.clear();
        self.off = 0;
    }

    pub(crate) fn ensure_append_capacity(&mut self, extra: usize) {
        if extra == 0 {
            return;
        }
        if self.off == 0 {
            return;
        }
        if self.data.capacity() - self.data.len() >= extra {
            return;
        }

        let unread = self.data.len() - self.off;
        self.data.copy_within(self.off.., 0);
        self.data.truncate(unread);
        self.off = 0;
    }

    pub(crate) fn append_byte(&mut self, b: u8) {
        self.ensure_append_capacity(1);
        self.data.push(b);
    }
}

pub(crate) fn append_decoded_byte(dst: &mut [u8], n: usize, pending: &mut PendingBuffer, b: u8) -> usize {
    if let Some(slot) = dst.get_mut(n) {
        *slot = b;
        return n + 1;
    }
    pending.append_byte(b);
    n
}

pub(crate) fn drain_pending(dst: &mut [u8], pending: &mut PendingBuffer) -> (usize, bool) {
    if pending.available() == 0 {
        return (0, false);
    }

    let n = dst.len().min(pending.available());
    if let (Some(dest), Some(src)) = (dst.get_mut(..n), pending.data.get(pending.off..pending.off + n)) {
        dest.copy_from_slice(src);
    }
    pending.off += n;
    if pending.off == pending.data.len() {
        pending.reset();
    }
    (n, true)
}
