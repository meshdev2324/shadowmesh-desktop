use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub enum DeepLinkAction {
    Activate { token: String },
    Connect { node_id: String },
    Unknown,
}

pub fn parse_deeplink(url_str: &str) -> DeepLinkAction {
    let Ok(url) = Url::parse(url_str) else {
        return DeepLinkAction::Unknown;
    };

    if url.scheme() != "shadowmesh" {
        return DeepLinkAction::Unknown;
    }

    match url.host_str() {
        Some("activate") => {
            let token = url
                .query_pairs()
                .find(|(k, _)| k == "token")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();

            if token.is_empty() {
                DeepLinkAction::Unknown
            } else {
                DeepLinkAction::Activate { token }
            }
        }
        Some("connect") => {
            let node_id = url
                .query_pairs()
                .find(|(k, _)| k == "node_id")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();

            if node_id.is_empty() {
                DeepLinkAction::Unknown
            } else {
                DeepLinkAction::Connect { node_id }
            }
        }
        _ => DeepLinkAction::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_activation_link() {
        let url = "shadowmesh://activate?token=ABCDE12345FGHIJKLMNOPQRST";
        let action = parse_deeplink(url);
        assert_eq!(
            action,
            DeepLinkAction::Activate { token: "ABCDE12345FGHIJKLMNOPQRST".to_string() }
        );
    }

    #[test]
    fn test_parse_connect_link() {
        let url = "shadowmesh://connect?node_id=us-east-1";
        let action = parse_deeplink(url);
        assert_eq!(action, DeepLinkAction::Connect { node_id: "us-east-1".to_string() });
    }

    #[test]
    fn test_parse_invalid_link() {
        let url = "shadowmesh://invalid";
        let action = parse_deeplink(url);
        assert_eq!(action, DeepLinkAction::Unknown);
    }
}
