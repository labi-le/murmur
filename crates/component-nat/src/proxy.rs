use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;

use murmur_common::atomic::value::TypedValue;
use murmur_constant::adapters::{WriteBack, WriteBackProxy as WriteBackProxyTrait};

#[derive(Default)]
pub(crate) struct WriteBackProxy {
    wb: TypedValue<Option<Arc<dyn WriteBack>>>,
}

#[async_trait]
impl WriteBack for WriteBackProxy {
    async fn write_back(&self, b: &[u8], addr: Option<SocketAddr>) -> anyhow::Result<usize> {
        let wb = self.wb.load().ok_or_else(|| anyhow::anyhow!("write back proxy is nil"))?;
        wb.write_back(b, addr).await
    }
}

impl WriteBackProxyTrait for WriteBackProxy {
    fn update_write_back(&self, wb: Arc<dyn WriteBack>) {
        self.wb.store(Some(wb));
    }
}

pub fn new_write_back_proxy(wb: Arc<dyn WriteBack>) -> Arc<dyn WriteBackProxyTrait> {
    let w = WriteBackProxy::default();
    w.update_write_back(wb);
    Arc::new(w)
}
