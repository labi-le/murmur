use anyhow::{Context, Result};
use std::sync::Arc;

use super::table::{new_table_with_custom, Table};

/// Manages multiple Sudoku tables (e.g. for per-connection rotation).
/// Intentionally decoupled from the tunnel/app layers.
#[derive(Debug, Clone, Default)]
pub struct TableSet {
    pub tables: Vec<Arc<Table>>,
}

/// Builds one or more tables from key/mode and a list of custom X/P/V patterns.
/// With no patterns it builds a single default table (customPattern="").
pub fn new_table_set(key: &str, mode: &str, patterns: &[String]) -> Result<TableSet> {
    if patterns.is_empty() {
        let table = new_table_with_custom(key, mode, "")?;
        return Ok(TableSet { tables: vec![table] });
    }

    let mut tables: Vec<Arc<Table>> = Vec::with_capacity(patterns.len());
    for (i, pattern) in patterns.iter().enumerate() {
        let table =
            new_table_with_custom(key, mode, pattern).with_context(|| format!("build table[{i}] ({pattern:?})"))?;
        tables.push(table);
    }
    Ok(TableSet { tables })
}

impl TableSet {
    #[must_use]
    pub fn candidates(&self) -> Vec<Arc<Table>> {
        self.tables.clone()
    }
}
