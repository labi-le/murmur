use std::collections::HashMap;

/// The children of a node, in storage order.
pub(crate) type ChildIter<'a, T> = Box<dyn Iterator<Item = (&'a str, &'a Node<T>)> + 'a>;

/// Node is the trie's node
#[derive(Debug)]
pub struct Node<T> {
    child_map: Option<HashMap<String, Box<Self>>>,
    child: Option<Box<Self>>,
    child_str: String,
    inited: bool,
    data: Option<T>,
}

impl<T> Node<T> {
    #[must_use]
    pub const fn new() -> Self {
        Self { child_map: None, child: None, child_str: String::new(), inited: false, data: None }
    }

    pub(crate) fn get_child(&self, s: &str) -> Option<&Self> {
        match &self.child_map {
            Some(child_map) => child_map.get(s).map(|child| &**child),
            None => match &self.child {
                Some(child) if self.child_str == s => Some(child),
                _ => None,
            },
        }
    }

    pub(crate) fn add_child(&mut self, s: String, child: Box<Self>) {
        if self.child_map.is_none() {
            if self.child.is_none() {
                self.child_str = s;
                self.child = Some(child);
                return;
            }
            let mut child_map = HashMap::new();
            if let Some(child) = self.child.take() {
                child_map.insert(std::mem::take(&mut self.child_str), child);
            }
            self.child_map = Some(child_map);
        }
        if let Some(child_map) = self.child_map.as_mut() {
            child_map.insert(s, child);
        }
    }

    pub(crate) fn get_or_new_child(&mut self, s: &str) -> &mut Self {
        if self.get_child(s).is_none() {
            self.add_child(s.to_owned(), Box::new(Self::new()));
        }
        if let Some(child) = self.child_map.as_mut().and_then(|map| map.get_mut(s)) {
            return child;
        }
        self.child.get_or_insert_with(|| Box::new(Self::new()))
    }

    pub(crate) fn optimize(&mut self) {
        if !self.child_str.is_empty() {
            self.child_str = str_clone(&self.child_str);
        }
        if let Some(child) = self.child.as_mut() {
            child.optimize();
        }
        let Some(mut child_map) = self.child_map.take() else {
            return;
        };
        match child_map.len() {
            0 => return,
            1 => {
                if let Some((key, child)) = child_map.drain().next() {
                    self.child_str = key;
                    self.child = Some(child);
                }
                self.optimize();
                return;
            }
            _ => {}
        }
        let mut children = HashMap::with_capacity(child_map.len());
        for (key, mut child) in child_map.drain() {
            child.optimize();
            children.insert(str_clone(&key), child);
        }
        self.child_map = Some(children);
    }

    pub(crate) const fn is_empty(&self) -> bool {
        !self.inited
    }

    pub(crate) fn set_data(&mut self, data: T) {
        self.data = Some(data);
        self.inited = true;
    }

    pub(crate) fn get_children(&self) -> Option<ChildIter<'_, T>> {
        if let Some(child_map) = &self.child_map {
            return Some(Box::new(child_map.iter().map(|(key, child)| (key.as_str(), &**child))));
        }
        if let Some(child) = &self.child {
            return Some(Box::new(std::iter::once((self.child_str.as_str(), &**child))));
        }
        None
    }

    #[expect(clippy::expect_used, reason = "callers read `data` only after `is_empty` reports the node was inited")]
    pub const fn data(&self) -> &T {
        self.data.as_ref().expect("data is only read from a node that was inited")
    }
}

impl<T> Default for Node<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// The four interned cases all copy the same bytes here.
pub(crate) fn str_clone(key: &str) -> String {
    key.to_owned()
}
