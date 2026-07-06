//! Manifest based modern-event providers
//!
//! List of every supported provider, generated from xml manifests and manually implemented ones.
//!
//! Typically created by calling [into_contained_event](ModernEvent::into_contained_event) on a [ModernEvent].
use super::*;

/// Windows-Kernel-Network provider
///
/// Can't be parsed from a manifest, because Ipv6 addresses are
/// encoded as type binary with a implicit size (which the parser can't infer).
mod win_kernel_network;
pub use win_kernel_network::*;

#[cfg(feature = "proc-win-etw-manifest")]
proc_win_etw_manifest::include_manifests!("./manifest/enabled");
