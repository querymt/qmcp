//! Native MCP-to-ACP bridge for a running QueryMT server.

mod commands;
mod output;
mod workspace;

pub use qmacp::policy;

pub mod local_oauth;
pub mod oauth;
pub mod server;
pub mod transport;

pub use server::{BridgeConfig, QmcpServer};
