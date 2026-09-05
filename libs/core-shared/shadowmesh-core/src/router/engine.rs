use crate::engine::context::ConnectionContext;
use crate::router::rule::{Action, RoutingRule};
use anyhow::Result;

pub struct RoutingPipeline {
    rules: Vec<RoutingRule>,
}

impl RoutingPipeline {
    pub fn new(rules: Vec<RoutingRule>) -> Self {
        Self { rules }
    }

    pub async fn route(&self, context: &mut ConnectionContext) -> Result<Action> {
        // Step 3: Environment Enrichment (Scaffold)
        self.enrich_metadata(context).await?;

        // Step 4: Rule Matching Loop
        for rule in &self.rules {
            if rule.condition.matches(&context.metadata) {
                context.rule_match_history.push(rule.tag.clone());

                match &rule.action {
                    Action::Sniff => {
                        // Perform sniffing and continue/restart loop
                        continue;
                    }
                    Action::Resolve => {
                        // Perform DNS resolution and continue
                        continue;
                    }
                    terminating_action => {
                        return Ok(terminating_action.clone());
                    }
                }
            }
        }

        // Default Action if no rule matches
        Ok(Action::Bypass)
    }

    async fn enrich_metadata(&self, _context: &mut ConnectionContext) -> Result<()> {
        // Logic for reverse DNS, process identification, etc.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::metadata::{ConnectionMetadata, Endpoint};
    use crate::router::rule::{Action, Condition, RoutingRule};

    #[tokio::test]
    async fn test_basic_routing() {
        let rules = vec![
            RoutingRule {
                tag: "block-ads".into(),
                condition: Condition::Domain("ads.example.com".into()),
                action: Action::Reject,
            },
            RoutingRule {
                tag: "proxy-google".into(),
                condition: Condition::DomainSuffix(".google.com".into()),
                action: Action::Route("proxy".into()),
            },
        ];

        let pipeline = RoutingPipeline::new(rules);

        let dest1 = Endpoint::new_domain("ads.example.com".into(), 443);
        let meta = ConnectionMetadata::new(dest1);
        let mut ctx = ConnectionContext::new(meta);
        assert!(matches!(pipeline.route(&mut ctx).await.unwrap(), Action::Reject));

        let dest2 = Endpoint::new_domain("www.google.com".into(), 443);
        let meta2 = ConnectionMetadata::new(dest2);
        let mut ctx2 = ConnectionContext::new(meta2);
        let result = pipeline.route(&mut ctx2).await.unwrap();
        if let Action::Route(tag) = result {
            assert_eq!(tag, "proxy");
        } else {
            panic!("Expected Route action");
        }
    }
}
