pub mod actor;
pub mod context;
pub mod dispatcher;
pub mod events;
pub mod lifecycle;
pub mod metadata;
pub mod observability;
pub mod process;
pub mod registry;
pub mod system;

pub use actor::{EngineActor, EngineHandle};
pub use observability::setup_observability;
pub use system::ShadowMeshSystem;
