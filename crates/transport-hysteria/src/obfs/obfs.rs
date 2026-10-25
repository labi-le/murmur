pub trait Obfuscator: Send + Sync {
    fn deobfuscate(&self, input: &[u8], output: &mut [u8]) -> usize;
    fn obfuscate(&self, input: &[u8], output: &mut [u8]) -> usize;
}
