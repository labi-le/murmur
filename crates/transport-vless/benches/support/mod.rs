//! Fixtures and case registry shared by the `metrics_heap`/`metrics_cpu` targets. Cargo does not
//! auto-discover `benches/support/`, so each metrics target opts in with `mod support;`; the
//! Criterion `vless` target pulls in `fixture.rs` directly.

pub mod cases;
pub mod cli;
pub mod fixture;
pub mod metric_fixture;
