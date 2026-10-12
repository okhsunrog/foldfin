//! Optional traffic adapters. OS route/DNS ownership belongs to the caller.
#[cfg(feature = "client")]
pub mod socks;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod tun;
