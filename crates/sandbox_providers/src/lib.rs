pub use sandcastle_sandbox_providers_core::*;

use std::sync::Arc;

use sandcastle_sandbox_provider_daytona::DaytonaProvider;
use sandcastle_sandbox_provider_docker::DockerProvider;
use sandcastle_sandbox_provider_k8s::K8sProvider;
use sandcastle_sandbox_provider_local::LocalProvider;

pub async fn load(enabled: &[String]) -> Vec<Arc<dyn Provider>> {
    let mut providers: Vec<Arc<dyn Provider>> = Vec::new();

    if enabled.contains(&"local".to_string()) {
        let local = LocalProvider::from_env();
        local.start_cleanup_task();
        providers.push(local);
        tracing::info!("local sandbox provider registered");
    }

    if enabled.contains(&"docker".to_string()) {
        match DockerProvider::from_env() {
            Ok(docker) => {
                docker.cleanup_stale_containers().await;
                docker.start_cleanup_task();
                providers.push(docker);
                tracing::info!("docker sandbox provider registered");
            }
            Err(e) => tracing::warn!("docker provider unavailable: {e}"),
        }
    }

    if enabled.contains(&"k8s".to_string()) {
        match K8sProvider::from_env().await {
            Ok(k8s) => {
                k8s.cleanup_stale_pods().await;
                k8s.start_cleanup_task();
                providers.push(k8s);
                tracing::info!("k8s sandbox provider registered");
            }
            Err(e) => tracing::warn!("k8s sandbox provider unavailable: {e}"),
        }
    }

    if enabled.contains(&"daytona".to_string()) {
        match DaytonaProvider::from_env() {
            Ok(daytona) => {
                providers.push(daytona);
                tracing::info!("daytona sandbox provider registered");
            }
            Err(e) => tracing::warn!("daytona provider unavailable: {e}"),
        }
    }

    providers
}
