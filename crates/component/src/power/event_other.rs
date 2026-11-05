#[cfg(not(target_os = "windows"))]
use super::event::Type;

#[cfg(not(target_os = "windows"))]
pub fn new_event_listener<F>(_cb: F) -> anyhow::Result<Box<dyn Fn() + Send + Sync>>
where
    F: Fn(Type) + Send + Sync + 'static,
{
    Err(anyhow::anyhow!("not support on this platform"))
}
