#[expect(
    clippy::module_inception,
    reason = "the inner module keeps the file name of the package it implements; renaming either would hide which file backs it"
)]
pub mod auth;
