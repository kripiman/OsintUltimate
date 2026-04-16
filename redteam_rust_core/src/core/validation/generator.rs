use anyhow::{Result, Context};
use crate::models::{Finding, TargetHost};
use crate::models::findings::PocDefinition;
use crate::core::validation::PocValidator;

use crate::utils::executor::ExecutorMode;

impl<M: ExecutorMode> PocValidator<M> {
    pub(crate) async fn generate_poc(&self, finding: &Finding, target: &TargetHost, attack_context: Option<&str>) -> Result<PocDefinition> {
        let analysis = self.router.analyze_with_level(finding, target, attack_context, crate::core::ai::RouteLevel::Premium, crate::core::ai::CavemanLevel::default()).await?;
        if let Some(poc) = analysis.poc {
            Ok(poc)
        } else {
            let text = analysis.summary; 
            let poc_json: PocDefinition = serde_json::from_str(crate::utils::common::extract_json(&text))
                .context("IA payload recovery failed.")?;
            Ok(poc_json)
        }
    }
}
