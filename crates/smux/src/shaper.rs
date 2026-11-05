//! The send loop reads only from the shaper, so this scheduler is reachable
//! (not dead code): every control frame — a stream open's SYN, a stream close's FIN, a write's
//! PSH, a keepalive's NOP, a window update's UPD — goes through it. The scheduler is a
//! per-stream min-heap ordered by `(class, seq)`, and it round-robins across those per-stream
//! heaps. A `BTreeMap<(Class, u64), _>` gives the same `(class, seq)` ordering as a heap
//! without hand-rolling one, and rotating a `VecDeque<u32>` of stream ids on each successful pop
//! reproduces the round-robin fairness.

use std::collections::{BTreeMap, HashMap, VecDeque};

use tokio::sync::oneshot;

use crate::frame::Frame;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Class {
    Ctrl = 0,
    Data = 1,
}

pub(crate) struct WriteRequest {
    pub class: Class,
    pub frame: Frame,
    pub seq: u64,
    pub result: oneshot::Sender<std::io::Result<usize>>,
}

#[derive(Default)]
pub(crate) struct ShaperQueue {
    streams: HashMap<u32, BTreeMap<(Class, u64), WriteRequest>>,
    order: VecDeque<u32>,
    count: usize,
}

impl ShaperQueue {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn push(&mut self, req: WriteRequest) {
        let sid = req.frame.sid;
        let key = (req.class, req.seq);
        let order = &mut self.order;
        let map = self.streams.entry(sid).or_insert_with(|| {
            order.push_back(sid);
            BTreeMap::new()
        });
        map.insert(key, req);
        self.count += 1;
    }

    pub(crate) fn pop(&mut self) -> Option<WriteRequest> {
        let rounds = self.order.len();
        for _ in 0..rounds {
            let sid = self.order.pop_front()?;
            let Some(map) = self.streams.get_mut(&sid) else {
                continue;
            };
            let Some((_, req)) = map.pop_first() else {
                self.streams.remove(&sid);
                continue;
            };
            self.count -= 1;
            if map.is_empty() {
                self.streams.remove(&sid);
            } else {
                self.order.push_back(sid);
            }
            return Some(req);
        }
        None
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.count == 0
    }
}
