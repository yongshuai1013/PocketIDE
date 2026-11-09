//! GingerVM's independent virtualization foundation.
//!
//! The broker, scripted guest harness, and restricted ARM ELF runner (including
//! limited self-relocating ET_DYN, rootfs-confined DT_NEEDED loading, selected
//! ARM REL relocations, and PT_INTERP entry handoff) are host-side compatibility
//! prototypes; they are not a Bionic linker, kernel syscall interceptor, or
//! complete Android system image boot path.

mod arm;
pub mod broker;
pub mod elf;
pub mod guest;
pub mod profile;
pub mod rootfs;
pub mod syscall;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Execute the packaged Android 2.3.7 init test rootfs for the Android JNI shell.
///
/// This intentionally reuses the same host-side ARM interpreter as the CLI; it
/// is not a guest-kernel boot API. `output` is a caller-owned UTF-8 NUL buffer.
///
/// # Safety
/// `rootfs_path` must point to a live NUL-terminated UTF-8 string, and `output`
/// must point to a writable buffer of `output_capacity` bytes for this call.
#[no_mangle]
pub unsafe extern "C" fn gingervm_android_run_init(
    rootfs_path: *const std::ffi::c_char,
    output: *mut std::ffi::c_char,
    output_capacity: usize,
) -> i32 {
    // SAFETY: the ABI contract is identical to this function's documented contract.
    unsafe { android_init_ffi(rootfs_path, output, output_capacity, false) }
}

/// Run AOSP init with one explicitly simulated guest-local property socket event.
///
/// # Safety
/// `rootfs_path` must point to a live NUL-terminated UTF-8 string, and `output`
/// must point to a writable buffer of `output_capacity` bytes for this call.
#[no_mangle]
pub unsafe extern "C" fn gingervm_android_run_init_simulated(
    rootfs_path: *const std::ffi::c_char,
    output: *mut std::ffi::c_char,
    output_capacity: usize,
) -> i32 {
    // SAFETY: the ABI contract is identical to this function's documented contract.
    unsafe { android_init_ffi(rootfs_path, output, output_capacity, true) }
}

unsafe fn android_init_ffi(
    rootfs_path: *const std::ffi::c_char,
    output: *mut std::ffi::c_char,
    output_capacity: usize,
    simulate_property_event: bool,
) -> i32 {
    if output.is_null() || output_capacity == 0 {
        return -1;
    }
    let result = if rootfs_path.is_null() {
        Err("missing rootfs path".to_owned())
    } else {
        // SAFETY: the JNI bridge passes a live, NUL-terminated UTF-8 path for
        // the duration of this call.
        match unsafe { std::ffi::CStr::from_ptr(rootfs_path) }.to_str() {
            Ok(path) => android_init_report(path, simulate_property_event),
            Err(error) => Err(format!("rootfs path is not UTF-8: {error}")),
        }
    };
    let (message, result_code) = match result {
        Ok(report) => (report, 0),
        Err(error) => (format!("GingerVM init test failed: {error}"), -3),
    };
    let bytes = message.as_bytes();
    let count = bytes.len().min(output_capacity - 1);
    // SAFETY: the caller supplied an output buffer of `output_capacity` bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), output.cast::<u8>(), count);
        *output.add(count) = 0;
    }
    if count < bytes.len() {
        -2
    } else {
        result_code
    }
}

pub fn android_init_report(
    rootfs_path: &str,
    simulate_property_event: bool,
) -> Result<String, String> {
    use crate::broker::{
        BrokerValue, GuestSyscall, SyscallBroker, VirtualIdentity, SIMULATED_PROPERTY_NAME,
        SIMULATED_PROPERTY_VALUE,
    };
    use crate::elf::{run_elf_with_args, ElfStopReason, DEFAULT_MAX_STEPS};
    use crate::rootfs::RootFs;
    use std::path::Path;

    let path = Path::new(rootfs_path);
    if !path.join("system/build.prop").is_file() {
        return Err("rootfs is missing the Android /system/build.prop image".to_owned());
    }
    let image = std::fs::read(path.join("init")).map_err(|error| error.to_string())?;
    let root = RootFs::open(path).map_err(|error| error.to_string())?;
    root.initialize_layout()
        .map_err(|error| error.to_string())?;
    let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
    if simulate_property_event {
        broker.inject_simulated_property_event();
    }
    let report = run_elf_with_args(
        &image,
        &mut broker,
        DEFAULT_MAX_STEPS,
        &["init".to_owned()],
        &[],
    )
    .map_err(|error| error.to_string())?;

    let mut mount_attempts = 0usize;
    let mut mount_successes = 0usize;
    for event in &report.events {
        if matches!(&event.syscall, GuestSyscall::Mount { .. }) {
            mount_attempts += 1;
            if matches!(&event.result, Ok(BrokerValue::Unit)) {
                mount_successes += 1;
            }
        }
    }
    let stop = match report.stop_reason {
        ElfStopReason::WaitingForEvents => {
            "WaitingForEvents (init is waiting for virtual fd events; no guest exit code)"
                .to_owned()
        }
        ElfStopReason::GuestExited => format!("GuestExited (exit code {})", report.exit_code),
    };
    let event_report = if simulate_property_event {
        let handled = simulated_property_event_was_handled(&report.events);
        if handled {
            format!(
                "SIMULATED EVENT: one guest-local property-service SETPROP request ({SIMULATED_PROPERTY_NAME}={SIMULATED_PROPERTY_VALUE}) from a virtual shell peer (uid 2000).\nGuest response: AOSP init accepted the virtual connection, read its 128-byte message, and returned to its normal event wait. No hardware/uevent was generated.\n\n"
            )
        } else {
            "SIMULATED EVENT: property-service SETPROP was armed, but the guest response could not be verified; see the syscall count and stop state below. No hardware/uevent was generated.\n\n".to_owned()
        }
    } else {
        String::new()
    };
    Ok(format!(
        "{event_report}Guest init: {stop}\nARM guest instructions: {}\nGuest syscall trace entries: {}\nBrokered syscall events: {}\nVirtual mount results: {mount_successes}/{mount_attempts} successful\n\nThis is a GingerVM ARM interpreter test, not a complete Android boot.",
        report.instructions_executed,
        report.syscall_trace.len(),
        report.events.len(),
    ))
}

fn simulated_property_event_was_handled(events: &[crate::elf::ElfSyscallEvent]) -> bool {
    use crate::broker::{
        BrokerValue, GuestSyscall, SIMULATED_PROPERTY_NAME, SIMULATED_PROPERTY_VALUE,
    };
    let accepted = events.iter().any(|event| {
        matches!(
            (&event.syscall, &event.result),
            (
                GuestSyscall::Accept { .. },
                Ok(BrokerValue::FileDescriptor(_))
            )
        )
    });
    let credentials_verified = events.iter().any(|event| {
        matches!(
            (&event.syscall, &event.result),
            (GuestSyscall::PeerCredentials { .. }, Ok(BrokerValue::Bytes(bytes)))
                if bytes.len() == 12
                    && i32::from_le_bytes(bytes[0..4].try_into().unwrap()) == 4242
                    && i32::from_le_bytes(bytes[4..8].try_into().unwrap()) == 2000
                    && i32::from_le_bytes(bytes[8..12].try_into().unwrap()) == 2000
        )
    });
    let message_consumed = events.iter().any(|event| {
        let GuestSyscall::Read { count, .. } = &event.syscall else {
            return false;
        };
        let Ok(BrokerValue::Bytes(bytes)) = &event.result else {
            return false;
        };
        *count >= 128
            && bytes.len() == 128
            && u32::from_le_bytes(bytes[0..4].try_into().unwrap()) == 1
            && bytes[4..36].split(|byte| *byte == 0).next()
                == Some(SIMULATED_PROPERTY_NAME.as_bytes())
            && bytes[36..128].split(|byte| *byte == 0).next()
                == Some(SIMULATED_PROPERTY_VALUE.as_bytes())
    });
    accepted && credentials_verified && message_consumed
}
