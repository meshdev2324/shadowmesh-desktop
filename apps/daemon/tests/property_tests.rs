use proptest::prelude::*;
use shadowmesh_daemon::types::{VpnAction, VpnCommand};
use std::borrow::Cow;

// Helper to generate Cow<'static, str>
fn any_cow_str() -> impl Strategy<Value = Cow<'static, str>> {
    any::<String>().prop_map(Cow::Owned)
}

prop_compose! {
    fn any_vpn_action() (
        action_idx in 0..15u32,
        code in any_cow_str(),
        node_id in any_cow_str(),
        mode in proptest::option::of(any_cow_str()),
        minutes in any::<u32>(),
        enabled in any::<bool>(),
        label in any_cow_str(),
        key in any_cow_str(),
        value in any_cow_str(),
    ) -> VpnAction<'static> {
        match action_idx {
            0 => VpnAction::GetVersion,
            1 => VpnAction::Ping,
            2 => VpnAction::Activate { code },
            3 => VpnAction::Connect { node_id, mode },
            4 => VpnAction::Pause { minutes },
            5 => VpnAction::SetKillSwitch { enabled },
            6 => VpnAction::SetAutoConnect { enabled },
            7 => VpnAction::SetDeviceLabel { label },
            8 => VpnAction::SecureToken { op: shadowmesh_daemon::types::SecureTokenOp::Set { key: key.clone(), value } },
            9 => VpnAction::SecureToken { op: shadowmesh_daemon::types::SecureTokenOp::Get { key } },
            10 => VpnAction::QrAuth { op: shadowmesh_daemon::types::QrAuthOp::Generate },
            11 => VpnAction::PanicWipe,
            12 => VpnAction::Camouflage { enabled },
            13 => VpnAction::SmartFallback { enabled },
            14 => VpnAction::ListNodes,
            _ => VpnAction::Status,
        }
    }
}

proptest! {
    #[test]
    fn test_ipc_serialization_roundtrip(
        action in any_vpn_action(),
        token in any_cow_str(),
    ) {
        let cmd = VpnCommand {
            action: action.clone(),
            token,
        };

        // Serialize
        let json = serde_json::to_string(&cmd).unwrap();

        // Deserialize (Zero-Copy)
        let deserialized: VpnCommand = serde_json::from_str(&json).unwrap();

        assert_eq!(cmd.action, deserialized.action);
        assert_eq!(cmd.token, deserialized.token);
    }

    #[test]
    fn test_ipc_parser_robustness(s in "\\PC*") {
        // The parser should never panic on arbitrary input
        let _: Result<VpnCommand, _> = serde_json::from_str(&s);
    }
}
