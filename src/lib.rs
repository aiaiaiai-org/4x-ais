// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0

//! aiaiaiai AIS: the one sign-in origin for every product
//! (`docs/service-design.md`).

pub mod config;
pub mod crypto;
pub mod family;
pub mod issuer;
pub mod limiter;
pub mod page;
pub mod pass;
pub mod password;
pub mod product_token;
pub mod relay;
pub mod store;

pub use issuer::router;

#[cfg(test)]
mod host_env_tests;
#[cfg(test)]
mod tests;
