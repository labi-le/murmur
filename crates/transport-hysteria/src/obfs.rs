pub mod dummy;
#[expect(clippy::module_inception, reason = "the obfuscator namespace is named after its own module")]
pub mod obfs;
pub mod xplus;
