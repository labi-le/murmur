use std::collections::VecDeque;

use super::strmatcher::Type;

pub(crate) const VALID_CHAR_COUNT: usize = 53;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MatchType {
    pub(crate) match_type: Type,
    pub(crate) exist: bool,
}

pub const TRIE_EDGE: bool = true;
pub const FAIL_EDGE: bool = false;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Edge {
    pub(crate) edge_type: bool,
    pub(crate) next_node: usize,
}

#[derive(Debug)]
pub struct ACAutomaton {
    pub(crate) trie: Vec<[Edge; VALID_CHAR_COUNT]>,
    pub(crate) fail: Vec<usize>,
    pub(crate) exists: Vec<MatchType>,
    pub(crate) count: usize,
}

const fn new_node() -> [Edge; VALID_CHAR_COUNT] {
    [Edge { edge_type: FAIL_EDGE, next_node: 0 }; VALID_CHAR_COUNT]
}

/// `char2Index`: the array is sized by its largest key `'~'`, so a byte above that range indexes
/// out of bounds.
#[expect(
    clippy::indexing_slicing,
    clippy::cast_possible_truncation,
    reason = "every write is a literal byte below the table's length, so the const evaluator \
              rejects an out-of-range one, and `i` stays under its literal loop bound"
)]
const CHAR2_INDEX: [u8; 127] = {
    let mut t = [0u8; 127];
    let mut i = 0;
    while i < 26 {
        t[b'A' as usize + i] = i as u8;
        t[b'a' as usize + i] = i as u8;
        i += 1;
    }
    t[b'!' as usize] = 26;
    t[b'$' as usize] = 27;
    t[b'&' as usize] = 28;
    t[b'\'' as usize] = 29;
    t[b'(' as usize] = 30;
    t[b')' as usize] = 31;
    t[b'*' as usize] = 32;
    t[b'+' as usize] = 33;
    t[b',' as usize] = 34;
    t[b';' as usize] = 35;
    t[b'=' as usize] = 36;
    t[b':' as usize] = 37;
    t[b'%' as usize] = 38;
    t[b'-' as usize] = 39;
    t[b'.' as usize] = 40;
    t[b'_' as usize] = 41;
    t[b'~' as usize] = 42;
    let mut i = 0;
    while i < 10 {
        t[b'0' as usize + i] = 43 + i as u8;
        i += 1;
    }
    t
};

#[expect(
    clippy::indexing_slicing,
    reason = "a byte above `~` is outside the table's 127 entries and must panic; a `get` fallback \
              would silently fold every such byte onto slot 0"
)]
const fn char2_index(c: u8) -> usize {
    CHAR2_INDEX[c as usize] as usize
}

#[must_use]
pub fn new_ac_automaton() -> ACAutomaton {
    let mut ac = ACAutomaton { trie: Vec::new(), fail: Vec::new(), exists: Vec::new(), count: 0 };
    ac.trie.push(new_node());
    ac.fail.push(0);
    ac.exists.push(MatchType { match_type: Type::Full, exist: false });
    ac
}

impl ACAutomaton {
    #[expect(
        clippy::indexing_slicing,
        reason = "`node` and `idx` come from the automaton's own edges and its 53-slot edge row, so \
                  both arrays are in bounds; a `get` fallback would silently drop an edge"
    )]
    pub fn add(&mut self, domain: &str, t: Type) {
        let bytes = domain.as_bytes();
        let mut node = 0usize;
        for &byte in bytes.iter().rev() {
            let idx = char2_index(byte);
            if self.trie[node][idx].next_node == 0 {
                self.count += 1;
                if self.trie.len() < self.count + 1 {
                    self.trie.push(new_node());
                    self.fail.push(0);
                    self.exists.push(MatchType { match_type: Type::Full, exist: false });
                }
                self.trie[node][idx] = Edge { edge_type: TRIE_EDGE, next_node: self.count };
            }
            node = self.trie[node][idx].next_node;
        }
        self.exists[node] = MatchType { match_type: t, exist: true };
        if t == Type::Domain {
            self.exists[node] = MatchType { match_type: Type::Full, exist: true };
            let idx = char2_index(b'.');
            if self.trie[node][idx].next_node == 0 {
                self.count += 1;
                if self.trie.len() < self.count + 1 {
                    self.trie.push(new_node());
                    self.fail.push(0);
                    self.exists.push(MatchType { match_type: Type::Full, exist: false });
                }
                self.trie[node][idx] = Edge { edge_type: TRIE_EDGE, next_node: self.count };
            }
            let node = self.trie[node][idx].next_node;
            self.exists[node] = MatchType { match_type: t, exist: true };
        }
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "`node`, `child` and `fail` are node ids `add` allocated in lockstep across the \
                  trie, and `i` walks the fixed edge row of the node being visited"
    )]
    pub fn build(&mut self) {
        let mut queue: VecDeque<Edge> = VecDeque::new();
        for edge in &self.trie[0] {
            if edge.next_node != 0 {
                queue.push_back(*edge);
            }
        }
        while let Some(front) = queue.pop_front() {
            let node = front.next_node;
            for i in 0..VALID_CHAR_COUNT {
                let child = self.trie[node][i].next_node;
                let fail = self.fail[node];
                if child != 0 {
                    self.fail[child] = self.trie[fail][i].next_node;
                    queue.push_back(self.trie[node][i]);
                } else {
                    let next_node = self.trie[fail][i].next_node;
                    self.trie[node][i] = Edge { edge_type: FAIL_EDGE, next_node };
                }
            }
        }
    }

    /// 1. the match string is all through trie edge. FULL MATCH or DOMAIN
    /// 2. the match string is through a fail edge. NOT FULL MATCH
    ///    - through a fail edge, but there exists a valid node. SUBSTR
    #[must_use]
    #[expect(
        clippy::indexing_slicing,
        reason = "`node` is a node id `add` allocated and `idx` comes from the char2Index table, so \
                  both rows are in bounds"
    )]
    pub fn match_(&self, s: &str) -> bool {
        let bytes = s.as_bytes();
        let mut node = 0usize;
        let mut full_match = true;
        for &byte in bytes.iter().rev() {
            let idx = char2_index(byte);
            full_match = full_match && self.trie[node][idx].edge_type;
            node = self.trie[node][idx].next_node;
            if self.exists[node].match_type == Type::Substr {
                return true;
            }
            if self.exists[node].match_type == Type::Domain && full_match {
                return true;
            }
        }
        full_match && self.exists[node].exist
    }
}
