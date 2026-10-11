//! No platform probe: on Windows `socket2` sends the idle/interval as `SIO_KEEPALIVE_VALS`
//! (Windows 2000 and later), not as `TCP_KEEPIDLE`/`TCP_KEEPINTVL`, so a probe for those options
//! would skip a working setting on older builds. The only per-option `setsockopt` it issues is
//! `TCP_KEEPCNT`, which nothing in this crate configures.
