use super::obfs::Obfuscator;

#[derive(Debug, Clone, Copy, Default)]
pub struct DummyObfuscator {}

impl DummyObfuscator {
    #[must_use]
    pub const fn new() -> Self {
        Self {}
    }
}

impl Obfuscator for DummyObfuscator {
    fn deobfuscate(&self, input: &[u8], output: &mut [u8]) -> usize {
        let Some(out) = output.get_mut(..input.len()) else {
            return 0;
        };
        out.copy_from_slice(input);
        input.len()
    }

    fn obfuscate(&self, input: &[u8], output: &mut [u8]) -> usize {
        let n = output.len().min(input.len());
        let (Some(out), Some(src)) = (output.get_mut(..n), input.get(..n)) else {
            return 0;
        };
        out.copy_from_slice(src);
        n
    }
}
