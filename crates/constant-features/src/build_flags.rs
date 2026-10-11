//! The values come from the build environment at compile time, and are empty when the variable
//! was unset.

pub static ARM_VERSION: &str = match option_env!("MURMUR_ARM_VERSION") {
    Some(value) => value,
    None => "",
};
pub static MIPS_FLOAT: &str = match option_env!("MURMUR_MIPS_FLOAT") {
    Some(value) => value,
    None => "",
};
pub static AMD64_LEVEL: &str = match option_env!("MURMUR_AMD64_LEVEL") {
    Some(value) => value,
    None => "",
};
