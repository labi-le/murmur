use super::sing::UpstreamNode;

/// Finds the first node in the wrapper chain that downcasts to `T` (optionally filtered by
/// `accept`).
///
/// No value in the tree currently exists solely to expose a raw net conn, but the walk keeps its
/// hook for the value that adds one.
pub fn find_upstream<'a, T: 'static>(
    value: &'a dyn UpstreamNode,
    accept: Option<&dyn Fn(&T) -> bool>,
) -> Option<&'a T> {
    let mut current = Some(value);
    while let Some(node) = current {
        if let Some(candidate) = node.as_any().downcast_ref::<T>() {
            if accept.is_none_or(|accept| accept(candidate)) {
                return Some(candidate);
            }
        }
        current = node.upstream_node().or_else(|| node.net_conn_node());
    }
    None
}
