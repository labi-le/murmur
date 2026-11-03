use anyhow::{anyhow, Result};
use std::collections::HashSet;

#[derive(Debug)]
pub(crate) struct ByteLayout {
    pub(crate) name: String,
    pub(crate) pad_marker: u8,
    pub(crate) padding_pool: Vec<u8>,

    pub(crate) hint_table: [bool; 256],
    pub(crate) encode_hint: [[u8; 16]; 4],
    pub(crate) encode_group: [u8; 64],
    pub(crate) decode_group: [u8; 256],
    pub(crate) group_valid: [bool; 256],
}

const fn empty_layout(name: String, pad_marker: u8, padding_pool: Vec<u8>) -> ByteLayout {
    ByteLayout {
        name,
        pad_marker,
        padding_pool,
        hint_table: [false; 256],
        encode_hint: [[0u8; 16]; 4],
        encode_group: [0u8; 64],
        decode_group: [0u8; 256],
        group_valid: [false; 256],
    }
}

/// Writes `value` at `index`, ignoring an out-of-range index; the callers mask
/// `index` into range first, so the ignored arm is unreachable.
fn set_at<T>(array: &mut [T], index: usize, value: T) {
    if let Some(slot) = array.get_mut(index) {
        *slot = value;
    }
}

impl ByteLayout {
    #[allow(dead_code, reason = "reachable only from packed.rs's #[cfg(test)] module, not from any production caller")]
    #[expect(
        clippy::indexing_slicing,
        reason = "a const fn cannot call slice::get (not const-stable); a u8 always indexes the 256-entry table"
    )]
    pub(crate) const fn is_hint(&self, b: u8) -> bool {
        self.hint_table[b as usize]
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "a const fn cannot call slice::get (not const-stable); the masks fix both indices inside their tables"
    )]
    pub(crate) const fn hint_byte(&self, val: u8, pos: u8) -> u8 {
        self.encode_hint[(val & 0x03) as usize][(pos & 0x0F) as usize]
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "a const fn cannot call slice::get (not const-stable); the mask fixes the index inside the 64-entry table"
    )]
    pub(crate) const fn group_byte(&self, group: u8) -> u8 {
        self.encode_group[(group & 0x3F) as usize]
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "a const fn cannot call slice::get (not const-stable); a u8 always indexes the 256-entry tables"
    )]
    pub(crate) const fn decode_packed_group(&self, b: u8) -> (u8, bool) {
        (self.decode_group[b as usize], self.group_valid[b as usize])
    }
}

/// Picks the byte layout for a single traffic direction.
/// ASCII always wins if requested. Custom patterns are ignored when ASCII is preferred.
pub(crate) fn resolve_layout(mode: &str, custom_pattern: &str) -> Result<ByteLayout> {
    match mode.to_lowercase().as_str() {
        "ascii" | "prefer_ascii" => return Ok(new_ascii_layout()),
        "entropy" | "prefer_entropy" | "" => {}
        _ => return Err(anyhow!("invalid ascii mode: {mode}")),
    }

    if !custom_pattern.trim().is_empty() {
        return new_custom_layout(custom_pattern);
    }
    Ok(new_entropy_layout())
}

fn new_ascii_layout() -> ByteLayout {
    let mut padding = Vec::with_capacity(32);
    for i in 0..32u8 {
        padding.push(0x20 + i);
    }

    let mut layout = empty_layout("ascii".to_owned(), 0x3F, padding);

    for val in 0..4u8 {
        for pos in 0..16u8 {
            let mut b = 0x40 | (val << 4) | pos;
            if b == 0x7F {
                b = b'\n';
            }
            if let Some(row) = layout.encode_hint.get_mut(usize::from(val)) {
                set_at(row, usize::from(pos), b);
            }
        }
    }
    for group in 0..64u8 {
        let mut b = 0x40 | group;
        if b == 0x7F {
            b = b'\n';
        }
        set_at(&mut layout.encode_group, usize::from(group), b);
    }
    for wire in 0u8..=255u8 {
        if (wire & 0x40) == 0x40 {
            let index = usize::from(wire);
            set_at(&mut layout.hint_table, index, true);
            set_at(&mut layout.decode_group, index, wire & 0x3F);
            set_at(&mut layout.group_valid, index, true);
        }
    }
    set_at(&mut layout.hint_table, usize::from(b'\n'), true);
    set_at(&mut layout.decode_group, usize::from(b'\n'), 0x3F);
    set_at(&mut layout.group_valid, usize::from(b'\n'), true);

    layout
}

fn new_entropy_layout() -> ByteLayout {
    let mut padding = Vec::with_capacity(16);
    for i in 0..8u8 {
        padding.push(0x80 + i);
        padding.push(0x10 + i);
    }

    let mut layout = empty_layout("entropy".to_owned(), 0x80, padding);

    for val in 0..4u8 {
        for pos in 0..16u8 {
            let b = (val << 5) | pos;
            if let Some(row) = layout.encode_hint.get_mut(usize::from(val)) {
                set_at(row, usize::from(pos), b);
            }
        }
    }
    for group in 0..64u8 {
        let v = group;
        set_at(&mut layout.encode_group, usize::from(group), ((v & 0x30) << 1) | (v & 0x0F));
    }
    for wire in 0u8..=255u8 {
        if (wire & 0x90) != 0 {
            continue;
        }
        let index = usize::from(wire);
        set_at(&mut layout.hint_table, index, true);
        set_at(&mut layout.decode_group, index, ((wire >> 1) & 0x30) | (wire & 0x0F));
        set_at(&mut layout.group_valid, index, true);
    }

    layout
}

fn new_custom_layout(pattern: &str) -> Result<ByteLayout> {
    let cleaned = pattern.trim().replace(' ', "").to_lowercase();
    if cleaned.len() != 8 {
        return Err(anyhow!("custom table must have 8 symbols, got {}", cleaned.len()));
    }

    let mut x_bits: Vec<u8> = Vec::new();
    let mut p_bits: Vec<u8> = Vec::new();
    let mut v_bits: Vec<u8> = Vec::new();
    for (bit, c) in (0..8u8).rev().zip(cleaned.chars()) {
        match c {
            'x' => x_bits.push(bit),
            'p' => p_bits.push(bit),
            'v' => v_bits.push(bit),
            _ => return Err(anyhow!("invalid char {c:?} in custom table")),
        }
    }

    if x_bits.len() != 2 || p_bits.len() != 2 || v_bits.len() != 4 {
        return Err(anyhow!("custom table must contain exactly 2 x, 2 p, 4 v"));
    }

    let mut x_mask = 0u8;
    for b in &x_bits {
        x_mask |= 1u8 << *b;
    }

    let encode_bits = |val: u8, pos: u8, drop_x: Option<usize>| -> u8 {
        let mut out = x_mask;
        if let Some(bit) = drop_x.and_then(|index| x_bits.get(index)) {
            out &= !(1u8 << *bit);
        }
        if (val & 0x02) != 0 {
            if let Some(bit) = p_bits.first() {
                out |= 1u8 << *bit;
            }
        }
        if (val & 0x01) != 0 {
            if let Some(bit) = p_bits.get(1) {
                out |= 1u8 << *bit;
            }
        }
        for (shift, bit) in (0..4u8).rev().zip(v_bits.iter()) {
            if (pos >> shift) & 0x01 == 1 {
                out |= 1u8 << *bit;
            }
        }
        out
    };

    let mut padding_set: HashSet<u8> = HashSet::new();
    let mut padding: Vec<u8> = Vec::new();
    for drop in 0..x_bits.len() {
        for val in 0..4u8 {
            for pos in 0..16u8 {
                let b = encode_bits(val, pos, Some(drop));
                if b.count_ones() >= 5 && padding_set.insert(b) {
                    padding.push(b);
                }
            }
        }
    }
    padding.sort_unstable();
    let Some(&pad_marker) = padding.first() else {
        return Err(anyhow!("custom table produced empty padding pool"));
    };

    let mut layout = empty_layout(format!("custom({cleaned})"), pad_marker, padding);

    for val in 0..4u8 {
        for pos in 0..16u8 {
            if let Some(row) = layout.encode_hint.get_mut(usize::from(val)) {
                set_at(row, usize::from(pos), encode_bits(val, pos, None));
            }
        }
    }
    for group in 0..64u8 {
        let val = (group >> 4) & 0x03;
        let pos = group & 0x0F;
        set_at(&mut layout.encode_group, usize::from(group), encode_bits(val, pos, None));
    }
    for wire in 0u8..=255u8 {
        if (wire & x_mask) != x_mask {
            continue;
        }
        let index = usize::from(wire);
        set_at(&mut layout.hint_table, index, true);

        let mut val = 0u8;
        let mut pos = 0u8;
        if let Some(bit) = p_bits.first() {
            if wire & (1u8 << *bit) != 0 {
                val |= 0x02;
            }
        }
        if let Some(bit) = p_bits.get(1) {
            if wire & (1u8 << *bit) != 0 {
                val |= 0x01;
            }
        }
        for (shift, bit) in (0..4u8).rev().zip(v_bits.iter()) {
            if wire & (1u8 << *bit) != 0 {
                pos |= 1 << shift;
            }
        }
        set_at(&mut layout.decode_group, index, (val << 4) | pos);
        set_at(&mut layout.group_valid, index, true);
    }

    Ok(layout)
}
