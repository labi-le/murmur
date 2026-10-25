use std::sync::Arc;

use murmur_component_trie::domain::DomainTrie;
use murmur_constant::matcher::DomainMatcher;

use super::resolver::DnsClient;

pub(crate) trait DnsPolicy: Send + Sync {
    fn match_(&self, domain: &str) -> Vec<Arc<dyn DnsClient>>;
}

pub(crate) struct DomainTriePolicy(pub DomainTrie<Vec<Arc<dyn DnsClient>>>);

impl DnsPolicy for DomainTriePolicy {
    fn match_(&self, domain: &str) -> Vec<Arc<dyn DnsClient>> {
        match self.0.search(domain) {
            Some(record) => record.data().clone(),
            None => Vec::new(),
        }
    }
}

pub(crate) struct DomainMatcherPolicy {
    pub matcher: Arc<dyn DomainMatcher>,
    pub dns_clients: Vec<Arc<dyn DnsClient>>,
}

impl DnsPolicy for DomainMatcherPolicy {
    fn match_(&self, domain: &str) -> Vec<Arc<dyn DnsClient>> {
        if self.matcher.match_domain(domain) {
            return self.dns_clients.clone();
        }
        Vec::new()
    }
}
