use std::collections::HashMap;
use std::fmt;

use anyhow::Result;

/// the `ErrorOverMaxValue`, a sentinel compared by message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorOverMaxValue;

impl fmt::Display for ErrorOverMaxValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the value don't over max value")
    }
}

impl std::error::Error for ErrorOverMaxValue {}

#[derive(Debug)]
pub struct IpCidrNode {
    pub mark: bool,
    child: HashMap<u32, Self>,
    max_value: u32,
}

impl IpCidrNode {
    #[must_use]
    pub fn new_ip_cidr_node(mark: bool, max_value: u32) -> Self {
        Self { mark, child: HashMap::new(), max_value }
    }

    pub(crate) fn add_child(&mut self, value: u32) -> Result<()> {
        if value > self.max_value {
            return Err(ErrorOverMaxValue.into());
        }

        self.child.insert(value, Self::new_ip_cidr_node(false, self.max_value));
        Ok(())
    }

    pub(crate) fn has_child(&self, value: u32) -> bool {
        self.get_child(value).is_some()
    }

    pub(crate) fn get_child(&self, value: u32) -> Option<&Self> {
        if value <= self.max_value {
            return self.child.get(&value);
        }

        None
    }

    pub(crate) fn get_child_mut(&mut self, value: u32) -> Option<&mut Self> {
        if value <= self.max_value {
            return self.child.get_mut(&value);
        }

        None
    }
}

/// Deletes the leading child keys, re-reading the length as it shrinks.
pub(crate) fn clean_child(node: &mut IpCidrNode) {
    let mut i: u32 = 0;
    while usize::try_from(i).unwrap_or(usize::MAX) < node.child.len() {
        node.child.remove(&i);
        i += 1;
    }
}
