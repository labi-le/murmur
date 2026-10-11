/// A 4x4 sudoku grid.
pub type Grid = [u8; 16];

/// All valid 4x4 sudoku grids.
#[must_use]
pub fn generate_all_grids() -> Vec<Grid> {
    fn backtrack(idx: usize, g: &mut Grid, grids: &mut Vec<Grid>) {
        if idx == 16 {
            grids.push(*g);
            return;
        }
        let row = idx / 4;
        let col = idx % 4;
        let (br, bc) = ((row / 2) * 2, (col / 2) * 2);
        for num in 1u8..=4 {
            let used_in_row = g.chunks_exact(4).nth(row).is_some_and(|cells| cells.contains(&num));
            let used_in_col = g.chunks_exact(4).any(|cells| cells.get(col) == Some(&num));
            let used_in_block = g
                .chunks_exact(4)
                .skip(br)
                .take(2)
                .any(|cells| cells.get(bc..bc + 2).is_some_and(|pair| pair.contains(&num)));
            if used_in_row || used_in_col || used_in_block {
                continue;
            }
            if let Some(cell) = g.get_mut(idx) {
                *cell = num;
            }
            backtrack(idx + 1, g, grids);
            if let Some(cell) = g.get_mut(idx) {
                *cell = 0;
            }
        }
    }

    let mut grids = Vec::new();
    let mut g: Grid = [0; 16];
    backtrack(0, &mut g, &mut grids);
    grids
}
