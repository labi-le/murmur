use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};

use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper, RuleType, RuleWrapper as CRuleWrapper};

/// which outcome the rule last produced
const OUTCOME_HIT: u32 = 1;
const OUTCOME_MISS: u32 = 2;
/// raised once the current streak of one outcome has taken a clock reading
const STAMPED: u32 = 4;
/// matches inside one streak between two clock readings; a power of two, so the modulo is a mask
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

    /// A wall-clock read is the bulk of what wrapping a rule costs, and the timestamp only feeds the
    /// controller's reporting fields, so the reading is taken on the first match of a streak and
    /// then once per STAMP_INTERVAL matches rather than on every match. Each counter still moves
    /// exactly once per match and the stored value keeps nanosecond resolution, so the wire form
    /// is unchanged; what this bounds is only how far the reported timestamp can lag the counter,
    /// by STAMP_INTERVAL matches of the same outcome.
    fn stamp(state: &AtomicU32, at: &AtomicTime, before: u64, outcome: u32) {
        let previous = state.fetch_or(outcome, Ordering::SeqCst);
        let already_stamped = previous & (outcome | STAMPED) == (outcome | STAMPED);
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
