//! The level gate of the `*ln!` macros: a record the stdout level discards is never formatted,
//! while `emit` stays ungated so a subscriber still receives it (the `/logs` route thresholds per
//! request). The two halves cannot share a process with the unit tests, which read the process
//! level, and they need the subscription count to be this process's own.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::pedantic,
    clippy::nursery
)]

use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};

use murmur_log::{debugln, enabled, infoln, set_level, subscribe, un_subscribe, LogLevel};

static FORMATTED: AtomicUsize = AtomicUsize::new(0);

/// Increments `FORMATTED` when the macro actually formats its argument.
struct CountsFormatting;

impl fmt::Display for CountsFormatting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        FORMATTED.fetch_add(1, Ordering::SeqCst);
        f.write_str("counted")
    }
}

#[tokio::test]
async fn a_discarded_record_is_built_only_while_a_subscriber_can_see_it() {
    set_level(LogLevel::INFO);
    assert!(!enabled(LogLevel::DEBUG), "the default level discards debug records");
    assert!(enabled(LogLevel::INFO), "the default level keeps info records");

    let before = FORMATTED.load(Ordering::SeqCst);
    debugln!("{}", CountsFormatting);
    assert_eq!(FORMATTED.load(Ordering::SeqCst), before, "a discarded DEBUG record must not be formatted");

    infoln!("{}", CountsFormatting);
    assert_eq!(FORMATTED.load(Ordering::SeqCst), before + 1, "a record the level shows must be formatted");

    let subscription = subscribe().await.expect("subscribe");
    debugln!("{}", CountsFormatting);
    assert_eq!(
        FORMATTED.load(Ordering::SeqCst),
        before + 2,
        "a subscriber must still receive the DEBUG record the stdout level hides"
    );
    let event = subscription.recv().await.expect("the emitted record");
    assert_eq!(event.log_level, LogLevel::DEBUG);
    assert_eq!(event.payload, "counted");

    un_subscribe(subscription).await;
    debugln!("{}", CountsFormatting);
    assert_eq!(
        FORMATTED.load(Ordering::SeqCst),
        before + 2,
        "with no subscriber left, a discarded record must not be built again"
    );
}
