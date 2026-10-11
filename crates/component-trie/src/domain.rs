use std::borrow::Cow;

use anyhow::Result;

use super::node::Node;

pub(crate) const WILDCARD: &str = "*";
pub(crate) const DOT_WILDCARD: &str = "";
pub(crate) const COMPLEX_WILDCARD: &str = "+";
pub(crate) const DOMAIN_STEP: &str = ".";
pub(crate) const WILDCARD_CHAR: char = '*';
pub(crate) const COMPLEX_WILDCARD_CHAR: char = '+';
pub(crate) const DOMAIN_STEP_CHAR: char = '.';

/// The invalid-domain error, carrying the formatted context.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
#[error("invalid domain {domain:?}: {reason}")]
pub struct InvalidDomainError {
    pub domain: String,
    pub reason: String,
}

fn invalid_domain_error(domain: &str, reason: String) -> anyhow::Error {
    InvalidDomainError { domain: domain.to_owned(), reason }.into()
}

/// `ValidAndSplitDomain` lower-cases and validates a domain.
///
/// Returns the lowered domain ready to split into its dot-separated labels with
/// `.split(DOMAIN_STEP_CHAR)`. One allocation for the lowered domain, not one per label.
pub fn valid_and_split_domain(domain: &str) -> Result<String> {
    let original_domain = domain;
    if domain.is_empty() {
        return Err(invalid_domain_error(original_domain, "domain is empty".to_owned()));
    }

    if domain.ends_with(DOMAIN_STEP_CHAR) {
        return Err(invalid_domain_error(original_domain, "trailing dot is not allowed".to_owned()));
    }
    if domain.chars().next().is_some_and(char::is_whitespace) {
        return Err(invalid_domain_error(original_domain, "leading whitespace is not allowed".to_owned()));
    }
    if domain.chars().next_back().is_some_and(char::is_whitespace) {
        return Err(invalid_domain_error(original_domain, "trailing whitespace is not allowed".to_owned()));
    }

    let lowered = domain.to_lowercase();
    let parts: Vec<&str> = lowered.split(DOMAIN_STEP_CHAR).collect();
    if lowered.is_empty() {
        return Err(invalid_domain_error(original_domain, "domain is empty".to_owned()));
    }
    for (i, part) in parts.iter().skip(1).enumerate() {
        if part.is_empty() {
            return Err(invalid_domain_error(original_domain, format!("label {} is empty", i + 2)));
        }
    }

    for (i, part) in parts.iter().enumerate() {
        if part.contains(COMPLEX_WILDCARD_CHAR) {
            if *part != COMPLEX_WILDCARD {
                return Err(invalid_domain_error(
                    original_domain,
                    format!("{COMPLEX_WILDCARD:?} wildcard must occupy the entire label {}", i + 1),
                ));
            } else if i != 0 {
                return Err(invalid_domain_error(
                    original_domain,
                    format!("{COMPLEX_WILDCARD:?} wildcard is only allowed in the first label"),
                ));
            } else if parts.len() == 1 {
                return Err(invalid_domain_error(
                    original_domain,
                    format!("{COMPLEX_WILDCARD:?} wildcard must be followed by another label"),
                ));
            }
        }
        if part.contains(WILDCARD_CHAR) && *part != WILDCARD {
            return Err(invalid_domain_error(
                original_domain,
                format!("{WILDCARD:?} wildcard must occupy the entire label {}", i + 1),
            ));
        }
    }

    Ok(lowered)
}

fn search_labels(domain: &str) -> Option<Cow<'_, str>> {
    if domain.is_empty() {
        return None;
    }
    if domain.ends_with(DOMAIN_STEP_CHAR) {
        return None;
    }
    if domain.chars().next().is_some_and(char::is_whitespace) {
        return None;
    }
    if domain.chars().next_back().is_some_and(char::is_whitespace) {
        return None;
    }

    let lowered: Cow<'_, str> = if domain.bytes().any(|b| b.is_ascii_uppercase() || !b.is_ascii()) {
        Cow::Owned(domain.to_lowercase())
    } else {
        Cow::Borrowed(domain)
    };

    let single_label = !lowered.contains(DOMAIN_STEP_CHAR);
    for (i, part) in lowered.split(DOMAIN_STEP_CHAR).enumerate() {
        if part.is_empty() {
            return None;
        }
        if part.contains(COMPLEX_WILDCARD_CHAR) && (part != COMPLEX_WILDCARD || i != 0 || single_label) {
            return None;
        }
        if part.contains(WILDCARD_CHAR) && part != WILDCARD {
            return None;
        }
    }

    Some(lowered)
}

/// `DomainTrie` contains the main logic for adding and searching nodes for domain segments.
/// support wildcard domain (e.g *.google.com)
#[derive(Debug)]
pub struct DomainTrie<T> {
    root: Node<T>,
}

impl<T> DomainTrie<T> {
    #[must_use]
    pub fn new() -> Self {
        Self { root: Node::new() }
    }

    /// Search is the most important part of the Trie.
    /// Priority as: static part, wildcard domain, dot wildcard domain.
    pub fn search(&self, domain: &str) -> Option<&Node<T>> {
        let lowered = search_labels(domain)?;
        let node = Self::search_node(&self.root, lowered.rsplit(DOMAIN_STEP_CHAR))?;

        if node.is_empty() {
            return None;
        }

        Some(node)
    }

    fn search_node<'a, 'b, I>(node: &'a Node<T>, mut labels: I) -> Option<&'a Node<T>>
    where
        I: Iterator<Item = &'b str> + Clone,
    {
        let Some(label) = labels.next() else {
            return Some(node);
        };

        if let Some(child) = node.get_child(label) {
            if let Some(found) = Self::search_node(child, labels.clone()) {
                if !found.is_empty() {
                    return Some(found);
                }
            }
        }

        if let Some(child) = node.get_child(WILDCARD) {
            if let Some(found) = Self::search_node(child, labels) {
                if !found.is_empty() {
                    return Some(found);
                }
            }
        }

        node.get_child(DOT_WILDCARD)
    }

    pub fn optimize(&mut self) {
        self.root.optimize();
    }

    /// Foreach iterates over the stored domain patterns and their associated values
    /// in unspecified order. Returning false stops iteration.
    pub fn foreach<F>(&self, mut f: F)
    where
        F: FnMut(&str, &T) -> bool,
    {
        let Some(children) = self.root.get_children() else {
            return;
        };
        for (key, data) in children {
            recursion(&[key.to_owned()], data, &mut f);
            if !data.is_empty() && !f(key, data.data()) {
                return;
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        match self.root.get_children() {
            None => true,
            Some(children) => children.count() == 0,
        }
    }
}

impl<T: Clone> DomainTrie<T> {
    /// Insert adds a node to the trie.
    /// Support
    /// 1. www.example.com
    /// 2. *.example.com
    /// 3. subdomain.*.example.com
    /// 4. .example.com
    /// 5. +.example.com
    pub fn insert(&mut self, domain: &str, data: T) -> Result<()> {
        let lowered = valid_and_split_domain(domain)?;
        let mut parts: Vec<&str> = lowered.split(DOMAIN_STEP_CHAR).collect();

        if let Some((first, rest)) = parts.split_first_mut() {
            if *first == COMPLEX_WILDCARD {
                self.insert_parts(rest, data.clone());
                *first = DOT_WILDCARD;
            }
        }
        self.insert_parts(&parts, data);

        Ok(())
    }

    fn insert_parts(&mut self, parts: &[&str], data: T) {
        let mut node = &mut self.root;
        for part in parts.iter().rev() {
            node = node.get_or_new_child(part);
        }

        node.set_data(data);
    }
}

impl<T> Default for DomainTrie<T> {
    fn default() -> Self {
        Self::new()
    }
}

fn recursion<T, F>(items: &[String], node: &Node<T>, f: &mut F) -> bool
where
    F: FnMut(&str, &T) -> bool,
{
    let Some(children) = node.get_children() else {
        return true;
    };
    for (key, data) in children {
        let mut new_items = Vec::with_capacity(items.len() + 1);
        new_items.push(key.to_owned());
        new_items.extend(items.iter().cloned());
        if !data.is_empty() && !f(&join_domain(&new_items), data.data()) {
            return false;
        }
        if !recursion(&new_items, data, f) {
            return false;
        }
    }
    true
}

pub(crate) fn join_domain<S: AsRef<str>>(items: &[S]) -> String {
    let mut result = String::new();
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            result.push_str(DOMAIN_STEP);
        }
        result.push_str(item.as_ref());
    }
    result
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::domain_set::DomainSetBuilder;

    fn local_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
    }

    #[test]
    fn test_trie_basic() {
        let mut tree = DomainTrie::<IpAddr>::new();
        let domains = ["example.com", "google.com", "localhost"];

        for domain in domains {
            assert!(tree.insert(domain, local_ip()).is_ok());
        }

        let node = tree.search("example.com").expect("node");
        assert_eq!(*node.data(), local_ip());
        assert!(tree.insert("", local_ip()).is_err());
        assert!(tree.search("").is_none());
        assert!(tree.search("localhost").is_some());
        assert!(tree.search("www.google.com").is_none());
    }

    #[test]
    fn test_trie_search_uppercase_query_matches_lowercase_pattern() {
        let mut tree = DomainTrie::<IpAddr>::new();
        assert!(tree.insert("example.com", local_ip()).is_ok());

        assert!(tree.search("EXAMPLE.COM").is_some());
        assert!(tree.search("Example.Com").is_some());
    }

    #[test]
    fn test_trie_search_rejects_trailing_dot() {
        let mut tree = DomainTrie::<IpAddr>::new();
        assert!(tree.insert("example.com", local_ip()).is_ok());

        assert!(tree.search("example.com.").is_none());
    }

    #[test]
    fn test_trie_search_non_ascii_hosts() {
        let mut tree = DomainTrie::<IpAddr>::new();
        assert!(tree.insert("例え.jp", local_ip()).is_ok());
        assert!(tree.insert("*.пример.рф", local_ip()).is_ok());
        assert!(tree.insert("ǅ.com", local_ip()).is_ok());
        assert!(tree.insert("i.tr", local_ip()).is_ok());

        assert!(tree.search("例え.jp").is_some());
        assert!(tree.search("例え.JP").is_some());
        assert!(tree.search("sub.ПРИМЕР.рф").is_some());
        assert!(tree.search("пример.рф").is_none());
        assert!(tree.search("ǅ.com").is_some());
    }

    #[test]
    fn test_trie_wildcard() {
        let mut tree = DomainTrie::<IpAddr>::new();
        let domains = [
            "*.example.com",
            "sub.*.example.com",
            "*.dev",
            ".org",
            ".example.net",
            ".apple.*",
            "+.foo.com",
            "+.stun.*.*",
            "+.stun.*.*.*",
            "+.stun.*.*.*.*",
            "stun.l.google.com",
        ];

        for domain in domains {
            assert!(tree.insert(domain, local_ip()).is_ok(), "{domain}");
        }

        assert!(tree.search("sub.example.com").is_some());
        assert!(tree.search("sub.foo.example.com").is_some());
        assert!(tree.search("test.org").is_some());
        assert!(tree.search("test.example.net").is_some());
        assert!(tree.search("test.apple.com").is_some());
        assert!(tree.search("test.foo.com").is_some());
        assert!(tree.search("foo.com").is_some());
        assert!(tree.search("global.stun.website.com").is_some());
        assert!(tree.search("foo.sub.example.com").is_none());
        assert!(tree.search("foo.example.dev").is_none());
        assert!(tree.search("example.com").is_none());
    }

    #[test]
    fn test_trie_priority() {
        let mut tree = DomainTrie::<i32>::new();
        let domains = [".dev", "example.dev", "*.example.dev", "test.example.dev"];

        for (index, domain) in domains.iter().enumerate() {
            assert!(tree.insert(domain, index as i32 + 1).is_ok());
        }

        let assert_fn = |domain: &str, data: i32| {
            let node = tree.search(domain).expect(domain);
            assert_eq!(*node.data(), data);
        };

        assert_fn("test.dev", 1);
        assert_fn("foo.bar.dev", 1);
        assert_fn("example.dev", 2);
        assert_fn("foo.example.dev", 3);
        assert_fn("test.example.dev", 4);
    }

    #[test]
    fn test_trie_boundary() {
        let mut tree = DomainTrie::<IpAddr>::new();
        assert!(tree.insert("*.dev", local_ip()).is_ok());

        assert!(tree.insert(".", local_ip()).is_err());
        assert!(tree.insert("..dev", local_ip()).is_err());
        assert!(tree.search("dev").is_none());
    }

    #[test]
    fn test_trie_wildcard_boundary() {
        let mut tree = DomainTrie::<IpAddr>::new();
        assert!(tree.insert("+.*", local_ip()).is_ok());
        assert!(tree.insert("stun.*.*.*", local_ip()).is_ok());

        assert!(tree.search("example.com").is_some());
    }

    #[test]
    fn test_trie_invalid_wildcard_placement() {
        let valid = ["+.example.com", "*.example.com", "+.*", "stun.*.*.*", "*", "a.*", "*.a"];
        for domain in valid {
            let mut tree = DomainTrie::<IpAddr>::new();
            assert!(tree.insert(domain, local_ip()).is_ok(), "should accept {domain:?}");
        }

        let invalid = [
            ("stun.+", "\"+\" wildcard is only allowed in the first label"),
            ("a.+.b", "\"+\" wildcard is only allowed in the first label"),
            ("a.+", "\"+\" wildcard is only allowed in the first label"),
            ("+", "\"+\" wildcard must be followed by another label"),
            ("+.+.com", "\"+\" wildcard is only allowed in the first label"),
            ("a+b.com", "\"+\" wildcard must occupy the entire label 1"),
            ("a*b.com", "\"*\" wildcard must occupy the entire label 1"),
            ("*a.com", "\"*\" wildcard must occupy the entire label 1"),
            ("a*.com", "\"*\" wildcard must occupy the entire label 1"),
        ];
        for (domain, reason) in invalid {
            let mut tree = DomainTrie::<IpAddr>::new();
            let err = tree.insert(domain, local_ip()).expect_err("should reject invalid domain");
            assert!(err.downcast_ref::<InvalidDomainError>().is_some(), "should reject {domain:?}");
            assert!(err.to_string().contains(reason), "should explain why {domain:?} was rejected: {err}");
        }

        let queries = ["example.com", "a.example.com", "com", "x.com", "za.com", "anything.at.all"];
        for domain in valid {
            let mut tree = DomainTrie::<IpAddr>::new();
            assert!(tree.insert(domain, local_ip()).is_ok());
            let set_from_trie = tree.new_domain_set();
            let mut builder = DomainSetBuilder::default();
            assert!(builder.insert(domain).is_ok());
            let set_from_builder = builder.build();
            assert_eq!(set_from_trie, set_from_builder);
            for query in queries {
                let search_hit = tree.search(query).is_some();
                let trie_set_hit = set_from_trie.as_ref().is_some_and(|set| set.has(query));
                let builder_set_hit = set_from_builder.as_ref().is_some_and(|set| set.has(query));
                assert_eq!(search_hit, trie_set_hit, "pattern {domain:?} query {query:?}");
                assert_eq!(search_hit, builder_set_hit, "pattern {domain:?} query {query:?}");
            }
        }
    }

    #[test]
    fn test_trie_valid_and_split_domain() {
        assert_eq!(valid_and_split_domain("GOOGLE.COM").expect("valid"), "google.com");
        assert_eq!(valid_and_split_domain("Mijia Cloud").expect("valid"), "mijia cloud");

        let invalid = [
            ("", "domain is empty"),
            ("example.com.", "trailing dot is not allowed"),
            (" example.com", "leading whitespace is not allowed"),
            ("example.com ", "trailing whitespace is not allowed"),
            ("A..COM", "label 2 is empty"),
        ];
        for (domain, reason) in invalid {
            let err = valid_and_split_domain(domain).expect_err("should reject");
            assert!(err.downcast_ref::<InvalidDomainError>().is_some());
            let message = err.to_string();
            assert!(message.contains(reason), "{message}");
            assert!(message.contains(&format!("{domain:?}")), "{message}");
        }
    }

    #[test]
    fn test_trie_foreach() {
        let mut tree = DomainTrie::<i32>::new();
        let domain_list = [
            "google.com",
            "stun.*.*.*",
            "test.*.google.com",
            "+.baidu.com",
            "*.baidu.com",
            "*.*.baidu.com",
            "baidu.com",
            ".example.org",
        ];
        for (index, domain) in domain_list.iter().enumerate() {
            assert!(tree.insert(domain, index as i32).is_ok());
        }
        let mut rebuilt = DomainTrie::<i32>::new();
        let mut values: HashMap<String, i32> = HashMap::new();
        tree.foreach(|domain, data| {
            assert!(!values.contains_key(domain));
            values.insert(domain.to_owned(), *data);
            assert!(rebuilt.insert(domain, *data).is_ok());
            true
        });
        let expected: HashMap<String, i32> = [
            ("google.com", 0),
            ("stun.*.*.*", 1),
            ("test.*.google.com", 2),
            (".baidu.com", 3),
            ("*.baidu.com", 4),
            ("*.*.baidu.com", 5),
            ("baidu.com", 6),
            (".example.org", 7),
        ]
        .into_iter()
        .map(|(domain, value)| (domain.to_owned(), value))
        .collect();
        assert_eq!(values, expected);
        for tree in [&tree, &rebuilt] {
            for (domain, expected) in
                [("google.com", 0), ("baidu.com", 6), ("a.b.c.baidu.com", 3), ("www.example.org", 7)]
            {
                let node = tree.search(domain).expect(domain);
                assert_eq!(*node.data(), expected, "{domain}");
            }
            assert!(tree.search("example.org").is_none());
        }
    }

    /// The traversal contract, re-derived from the inserted strings alone: a `+` expands
    /// into the exact pattern and the leading-dot pattern, everything else is visited as
    /// itself, all labels lowered.
    fn expected_visits(inserted: &[&str]) -> Vec<String> {
        let mut expected = Vec::new();
        for domain in inserted {
            let lowered = domain.to_lowercase();
            let mut parts: Vec<&str> = lowered.split(DOMAIN_STEP_CHAR).collect();
            if parts.first() == Some(&COMPLEX_WILDCARD) {
                expected.push(parts[1..].join(DOMAIN_STEP));
                parts[0] = DOT_WILDCARD;
            }
            expected.push(parts.join(DOMAIN_STEP));
        }
        expected.sort();
        expected.dedup();
        expected
    }

    #[test]
    fn foreach_visits_every_stored_pattern_exactly_once() {
        let inserted = [
            "www.example.com",
            "*.example.com",
            "subdomain.*.example.com",
            ".example.com",
            "+.example.com",
            "+.a.example.com",
            "a.example.com",
            "*.*.example.com",
            "example.com",
            "EXAMPLE.COM",
            "测试.cn",
            "i\u{307}.tr",
            "ασ.gr",
            "ας",
        ];
        let mut tree = DomainTrie::<i32>::new();
        for (index, domain) in inserted.iter().enumerate() {
            assert!(tree.insert(domain, index as i32).is_ok(), "{domain}");
        }

        let mut visits: Vec<String> = Vec::new();
        tree.foreach(|domain, _| {
            assert!(!visits.iter().any(|seen| seen == domain), "visited {domain} twice");
            visits.push(domain.to_owned());
            true
        });

        let expected = expected_visits(&inserted);
        visits.sort();
        assert_eq!(visits, expected);
    }

    #[test]
    fn returning_false_from_a_subtree_does_not_stop_the_outer_iteration() {
        // Recursion's result is discarded, so a `false` returned inside a subtree only unwinds
        // that subtree. It is deliberately not promoted to a whole-traversal stop: this test
        // exists so that changing it is a conscious decision.
        let mut tree = DomainTrie::<i32>::new();
        assert!(tree.insert("a.example.com", 0).is_ok());
        assert!(tree.insert("com", 1).is_ok());

        let mut seen: Vec<String> = Vec::new();
        tree.foreach(|domain, _| {
            seen.push(domain.to_owned());
            false
        });
        assert_eq!(seen, vec!["a.example.com".to_owned(), "com".to_owned()]);

        let mut tree = DomainTrie::<i32>::new();
        assert!(tree.insert("a.example.com", 0).is_ok());
        assert!(tree.insert("b.example.org", 1).is_ok());

        let mut seen: HashSet<String> = HashSet::new();
        tree.foreach(|domain, _| {
            seen.insert(domain.to_owned());
            false
        });
        assert_eq!(seen, HashSet::from(["a.example.com".to_owned(), "b.example.org".to_owned()]));
    }

    #[test]
    fn test_trie_optimize() {
        let mut tree = DomainTrie::<i32>::new();
        let domains = ["google.com", "stub.google.com", "*.google.com", ".example.org", "test.*.google.com"];
        for (index, domain) in domains.iter().enumerate() {
            assert!(tree.insert(domain, index as i32).is_ok());
        }
        tree.optimize();

        assert_eq!(*tree.search("google.com").expect("node").data(), 0);
        assert_eq!(*tree.search("stub.google.com").expect("node").data(), 1);
        assert_eq!(*tree.search("foo.google.com").expect("node").data(), 2);
        assert_eq!(*tree.search("test.foo.google.com").expect("node").data(), 4);
        assert_eq!(*tree.search("www.example.org").expect("node").data(), 3);
        assert!(tree.search("example.com").is_none());
    }
}
