use super::router::config_pb::Domain;

fn equal_fold(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right) || left.to_lowercase() == right.to_lowercase()
}

#[derive(Debug, Default)]
pub struct AttributeList {
    matcher: Vec<BooleanMatcher>,
}

impl AttributeList {
    #[must_use]
    pub fn match_(&self, domain: &Domain) -> bool {
        self.matcher.iter().all(|matcher| matcher.match_(domain))
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.matcher.is_empty()
    }
}

impl std::fmt::Display for AttributeList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let matcher: Vec<&str> = self.matcher.iter().map(BooleanMatcher::as_str).collect();
        write!(f, "{}", matcher.join(","))
    }
}

pub(crate) fn parse_attrs(attrs: &[String]) -> AttributeList {
    let mut al = AttributeList::default();
    for attr in attrs {
        let trimmed_attr = attr.trim().to_lowercase();
        if trimmed_attr.is_empty() {
            continue;
        }
        al.matcher.push(BooleanMatcher(trimmed_attr));
    }
    al
}

pub trait AttributeMatcher {
    fn match_(&self, domain: &Domain) -> bool;
}

#[derive(Debug, Clone)]
pub struct BooleanMatcher(String);

impl BooleanMatcher {
    fn as_str(&self) -> &str {
        &self.0
    }
}

impl AttributeMatcher for BooleanMatcher {
    fn match_(&self, domain: &Domain) -> bool {
        domain.attribute.iter().any(|attr| equal_fold(attr.get_key(), &self.0))
    }
}
