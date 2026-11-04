#[derive(Clone, Debug, Default)]
pub struct Base {
    pub host: String,
    pub port: i32,
    pub key: Vec<u8>,
    pub iv_size: i32,
    pub param: String,
}
