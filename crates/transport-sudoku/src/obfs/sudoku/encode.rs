use super::conn::PERM4;
use super::padding_prob::PROB_ONE;
use super::rand::SudokuRand;
use super::table::Table;

/// Picks the puzzle and hint permutation for wire byte `b`; `None` means the
/// table is malformed.
fn pick_puzzle_and_perm<'a>(table: &'a Table, rng: &mut SudokuRand, b: u8) -> Option<([u8; 4], &'a [u8; 4])> {
    let puzzles = table.encode_table.get(usize::from(b))?;
    let puzzle = *puzzles.get(rng.intn(puzzles.len()))?;
    let perm = PERM4.get(rng.intn(PERM4.len()))?;
    Some((puzzle, perm))
}

fn push_random_pad(out: &mut Vec<u8>, pads: &[u8], rng: &mut SudokuRand) {
    if let Some(&pad) = pads.get(rng.intn(pads.len())) {
        out.push(pad);
    }
}

fn push_puzzle_byte(out: &mut Vec<u8>, puzzle: [u8; 4], idx: u8) {
    if let Some(&byte) = puzzle.get(usize::from(idx)) {
        out.push(byte);
    }
}

pub(crate) fn encode_sudoku_payload(
    out: &mut Vec<u8>,
    table: &Table,
    rng: &mut SudokuRand,
    padding_threshold: u64,
    p: &[u8],
) {
    out.clear();
    if p.is_empty() {
        return;
    }
    if padding_threshold == 0 {
        encode_sudoku_payload_no_padding(out, table, rng, p);
        return;
    }

    let out_capacity = p.len() * 6 + 1;
    if out.capacity() < out_capacity {
        out.reserve(out_capacity);
    }

    let pads = &table.padding_pool;

    if padding_threshold >= PROB_ONE {
        for &b in p {
            push_random_pad(out, pads, rng);

            let Some((puzzle, perm)) = pick_puzzle_and_perm(table, rng, b) else {
                continue;
            };
            for &idx in perm {
                push_random_pad(out, pads, rng);
                push_puzzle_byte(out, puzzle, idx);
            }
        }

        push_random_pad(out, pads, rng);
        return;
    }

    for &b in p {
        if u64::from(rng.uint32()) < padding_threshold {
            push_random_pad(out, pads, rng);
        }

        let Some((puzzle, perm)) = pick_puzzle_and_perm(table, rng, b) else {
            continue;
        };
        for &idx in perm {
            if u64::from(rng.uint32()) < padding_threshold {
                push_random_pad(out, pads, rng);
            }
            push_puzzle_byte(out, puzzle, idx);
        }
    }

    if u64::from(rng.uint32()) < padding_threshold {
        push_random_pad(out, pads, rng);
    }
}

fn encode_sudoku_payload_no_padding(out: &mut Vec<u8>, table: &Table, rng: &mut SudokuRand, p: &[u8]) {
    let out_capacity = p.len() * 4;
    if out.capacity() < out_capacity {
        out.reserve(out_capacity);
    }

    for &b in p {
        let Some((puzzle, perm)) = pick_puzzle_and_perm(table, rng, b) else {
            continue;
        };
        for &idx in perm {
            push_puzzle_byte(out, puzzle, idx);
        }
    }
}
