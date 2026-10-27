use portable_atomic::{AtomicI64, AtomicU64};
use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};

use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType, RuleWrapper as CRuleWrapper};

/// Outcome bit in its independent hit or miss state.
const OUTCOME_HIT: u32 = 1;
const OUTCOME_MISS: u32 = 2;
/// Raised when that outcome starts its first timestamp update.
const STAMPED: u32 = 4;
/// Per-outcome count interval between timestamp updates.
const STAMP_INTERVAL: u64 = 256;

/// The embedded rule becomes the `rule` field, which every method of [`Rule`] forwards to.
pub struct RuleWrapper {
    rule: Arc<dyn Rule>,
    disabled: AtomicBool,
    hit_count: AtomicU64,
    hit_at: AtomicTime,
    hit_state: AtomicU32,
    miss_count: AtomicU64,
    miss_at: AtomicTime,
    miss_state: AtomicU32,
}

impl std::fmt::Debug for RuleWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleWrapper")
            .field("rule_type", &self.rule.rule_type())
            .field("disabled", &self.disabled)
            .field("hit_count", &self.hit_count)
            .field("miss_count", &self.miss_count)
            .finish_non_exhaustive()
    }
}

impl RuleWrapper {
    pub fn hit(&self) {
        let before = self.hit_count.fetch_add(1, Ordering::SeqCst);
        Self::stamp(&self.hit_state, &self.hit_at, before, OUTCOME_HIT);
    }

    pub fn miss(&self) {
        let before = self.miss_count.fetch_add(1, Ordering::SeqCst);
        Self::stamp(&self.miss_state, &self.miss_at, before, OUTCOME_MISS);
    }

    /// Samples each outcome independently on its first occurrence and every STAMP_INTERVAL
    /// occurrences thereafter. Counters remain exact; timestamps retain nanosecond resolution.
    /// Hit/miss transitions do not reset either sampling schedule. Concurrent updates are not
    /// a coherent counter/timestamp snapshot, and STAMPED is published before the time store.
    fn stamp(state: &AtomicU32, at: &AtomicTime, before: u64, outcome: u32) {
        let required = outcome | STAMPED;
        // Every bit the read-modify-write below could add is already present, and this call is
        // not at a sampling boundary, so the RMW cannot change the state or take a timestamp.
        // The load stays SeqCst: it is a fast path for the same decision, not a weaker ordering.
        if !before.is_multiple_of(STAMP_INTERVAL) && state.load(Ordering::SeqCst) & required == required {
            return;
        }
        let previous = state.fetch_or(outcome, Ordering::SeqCst);
        let already_stamped = previous & required == required;
        if already_stamped && !before.is_multiple_of(STAMP_INTERVAL) {
            return;
        }
        state.fetch_or(STAMPED, Ordering::SeqCst);
        at.store(Utc::now());
    }
}

impl Rule for RuleWrapper {
    fn rule_type(&self) -> RuleType {
        self.rule.rule_type()
    }

    fn match_(&self, metadata: &mut Metadata, helper: &RuleMatchHelper) -> (bool, Cow<'_, str>) {
        if self.is_disabled() {
            return (false, Cow::Borrowed(""));
        }
        let (ok, adapter) = self.rule.match_(metadata, helper);
        if ok {
            self.hit();
        } else {
            self.miss();
        }
        (ok, adapter)
    }

    fn adapter(&self) -> String {
        self.rule.adapter()
    }

    fn payload(&self) -> String {
        self.rule.payload()
    }

    fn provider_names(&self) -> Vec<String> {
        self.rule.provider_names()
    }

    fn as_rule_wrapper(&self) -> Option<&dyn CRuleWrapper> {
        Some(self)
    }
}

impl CRuleWrapper for RuleWrapper {
    fn set_disabled(&self, v: bool) {
        self.disabled.store(v, Ordering::SeqCst);
    }

    fn is_disabled(&self) -> bool {
        self.disabled.load(Ordering::SeqCst)
    }

    fn hit_count(&self) -> u64 {
        self.hit_count.load(Ordering::SeqCst)
    }

    fn hit_at(&self) -> DateTime<Utc> {
        self.hit_at.load()
    }

    fn miss_count(&self) -> u64 {
        self.miss_count.load(Ordering::SeqCst)
    }

    fn miss_at(&self) -> DateTime<Utc> {
        self.miss_at.load()
    }

    fn unwrap(&self) -> Arc<dyn Rule> {
        Arc::clone(&self.rule)
    }
}

pub fn new_rule_wrapper(rule: Arc<dyn Rule>) -> Arc<dyn CRuleWrapper> {
    Arc::new(RuleWrapper {
        rule,
        disabled: AtomicBool::new(false),
        hit_count: AtomicU64::new(0),
        hit_at: AtomicTime::default(),
        hit_state: AtomicU32::new(0),
        miss_count: AtomicU64::new(0),
        miss_at: AtomicTime::default(),
        miss_state: AtomicU32::new(0),
    })
}

/// Stores the unix nanoseconds of a timestamp in an atomic `i64`.
#[derive(Default)]
pub(crate) struct AtomicTime {
    i: AtomicI64,
}

impl AtomicTime {
    pub(crate) fn load(&self) -> DateTime<Utc> {
        from_unix(0, self.i.load(Ordering::SeqCst))
    }

    pub(crate) fn store(&self, v: DateTime<Utc>) {
        self.i.store(unix_nano(&v), Ordering::SeqCst);
    }
}

fn from_unix(sec: i64, nsec: i64) -> DateTime<Utc> {
    let secs = sec + nsec.div_euclid(1_000_000_000);
    let sub_nanos = u32::try_from(nsec.rem_euclid(1_000_000_000)).unwrap_or_default();
    DateTime::from_timestamp(secs, sub_nanos).unwrap_or(DateTime::<Utc>::MIN_UTC)
}

/// The unix nanoseconds, undefined outside the representable range.
fn unix_nano(t: &DateTime<Utc>) -> i64 {
    t.timestamp_nanos_opt().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use murmur_rules_common::domain_suffix::DomainSuffix;

    use super::*;

    fn wrapper() -> RuleWrapper {
        let rule: Arc<dyn Rule> = Arc::new(DomainSuffix::new("example.com", "TEST"));
        RuleWrapper {
            rule,
            disabled: AtomicBool::new(false),
            hit_count: AtomicU64::new(0),
            hit_at: AtomicTime::default(),
            hit_state: AtomicU32::new(0),
            miss_count: AtomicU64::new(0),
            miss_at: AtomicTime::default(),
            miss_state: AtomicU32::new(0),
        }
    }

    #[test]
    fn a_stamped_outcome_skips_the_rmw_inside_its_interval_but_samples_the_boundary() {
        let state = AtomicU32::new(0);
        let at = AtomicTime::default();

        RuleWrapper::stamp(&state, &at, 0, OUTCOME_HIT);
        let first = at.load();
        assert_eq!(state.load(Ordering::SeqCst), OUTCOME_HIT | STAMPED);
        assert!(first.timestamp_nanos_opt().unwrap_or_default() > 0);

        std::thread::sleep(std::time::Duration::from_millis(2));
        for before in [1, 2, STAMP_INTERVAL - 1] {
            RuleWrapper::stamp(&state, &at, before, OUTCOME_HIT);
            assert_eq!(at.load(), first, "an in-interval call must not take a clock reading");
        }

        RuleWrapper::stamp(&state, &at, STAMP_INTERVAL, OUTCOME_HIT);
        assert_eq!(state.load(Ordering::SeqCst), OUTCOME_HIT | STAMPED);
        assert!(at.load() > first, "a sampling boundary refreshes the timestamp");
    }

    #[test]
    fn concurrent_hits_keep_exact_counts_and_publish_a_timestamp() {
        let wrapper = wrapper();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..1_000 {
                        wrapper.hit();
                    }
                });
            }
        });
        assert_eq!(wrapper.hit_count.load(Ordering::SeqCst), 8_000);
        assert_eq!(wrapper.miss_count.load(Ordering::SeqCst), 0);
        assert!(wrapper.hit_at.load().timestamp_nanos_opt().unwrap_or_default() > 0);
    }
}
