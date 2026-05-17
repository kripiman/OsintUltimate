use tokio_util::sync::CancellationToken;
use tracing::{info, warn};
use std::sync::Arc;
use futures::future::BoxFuture;

pub type CleanupHook = Box<dyn FnOnce() -> BoxFuture<'static, ()> + Send>;

pub struct ShutdownManager {
    token: CancellationToken,
    proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>,
    hooks: tokio::sync::Mutex<Vec<CleanupHook>>,
}

impl ShutdownManager {
    pub fn new(token: CancellationToken, proxy_manager: Option<Arc<crate::utils::proxy::ProxyManager>>) -> Self {
        Self { 
            token, 
            proxy_manager,
            hooks: tokio::sync::Mutex::new(Vec::new()),
        }
    }

    pub async fn add_hook<F>(&self, hook: F) 
    where 
        F: FnOnce() -> BoxFuture<'static, ()> + Send + 'static 
    {
        let mut hooks = self.hooks.lock().await;
        hooks.push(Box::new(hook));
    }

    pub async fn wait_for_signal(self: Arc<Self>) {
        tokio::signal::ctrl_c().await.ok();
        info!("🛑 SHUTDOWN: Ctrl-C received. Initiating graceful cleanup...");
        self.initiate().await;
    }

    pub async fn initiate(&self) {
        info!("🔔 SHUTDOWN: Signaling all components to stop...");
        self.token.cancel();
        
        if let Some(ref pm) = self.proxy_manager {
            warn!("🔌 SHUTDOWN: Killing all egress proxies to prevent detection leaks...");
            pm.kill_egress();
        }

        let mut hooks = self.hooks.lock().await;
        while let Some(hook) = hooks.pop() {
            hook().await;
        }
        
        info!("🛡️ SHUTDOWN: Cleanup complete. Terminal status reached.");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
