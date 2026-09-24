pub mod direct;
pub mod group;
pub mod registry;
pub mod shadowsocks;
pub mod trojan;
pub mod tuic;
pub mod vmess;
pub mod wireguard;

pub use direct::DirectOutbound;
pub use group::{OutboundGroup, SelectionStrategy};
pub use registry::OutboundRegistry;
pub use shadowsocks::ShadowsocksOutbound;
pub use trojan::TrojanOutbound;
pub use tuic::TuicOutbound;
pub use vmess::{VlessOutbound, VmessOutbound};
pub use wireguard::WireguardOutbound;
