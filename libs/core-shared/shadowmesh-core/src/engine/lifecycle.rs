use anyhow::Result;
use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    Initialize,
    Start,
    PostStart,
    Started,
    Shutdown,
}

#[async_trait]
pub trait Service: Send + Sync {
    fn name(&self) -> &str;
    async fn stage_change(&self, stage: Stage) -> Result<()>;
}

pub struct LifecycleManager {
    services: Vec<Box<dyn Service>>,
}

impl Default for LifecycleManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LifecycleManager {
    pub fn new() -> Self {
        Self { services: Vec::new() }
    }

    pub fn register(&mut self, service: Box<dyn Service>) {
        self.services.push(service);
    }

    pub async fn transition_to(&self, stage: Stage) -> Result<()> {
        tracing::info!("Transitioning to stage: {:?}", stage);
        for service in &self.services {
            service.stage_change(stage).await?;
        }
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        tracing::info!("Shutting down services...");
        for service in self.services.iter().rev() {
            tracing::info!("Shutting down service: {}", service.name());
            if let Err(e) = service.stage_change(Stage::Shutdown).await {
                tracing::error!("Failed to shutdown service {}: {:?}", service.name(), e);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;
    use std::sync::Arc;

    struct TestService {
        name: String,
        stages: Arc<Mutex<Vec<(String, Stage)>>>,
    }

    #[async_trait]
    impl Service for TestService {
        fn name(&self) -> &str {
            &self.name
        }
        async fn stage_change(&self, stage: Stage) -> Result<()> {
            self.stages.lock().push((self.name.clone(), stage));
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_lifecycle_shutdown_order() {
        let stages = Arc::new(Mutex::new(Vec::new()));
        let mut manager = LifecycleManager::new();

        manager.register(Box::new(TestService { name: "s1".to_string(), stages: stages.clone() }));
        manager.register(Box::new(TestService { name: "s2".to_string(), stages: stages.clone() }));

        manager.shutdown().await.unwrap();

        let s = stages.lock();
        assert_eq!(s.len(), 2);
        assert_eq!(s[0], ("s2".to_string(), Stage::Shutdown));
        assert_eq!(s[1], ("s1".to_string(), Stage::Shutdown));
    }
}
