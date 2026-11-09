//! GingerVM's independent virtualization foundation.
//!
//! The broker, scripted guest harness, and restricted static ARM ELF runner are
//! host-side compatibility prototypes; they are not a kernel syscall
//! interceptor and do not boot a complete Android system image.

mod arm;
pub mod broker;
pub mod elf;
pub mod guest;
pub mod profile;
pub mod rootfs;
pub mod syscall;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
