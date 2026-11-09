use std::env;
use std::error::Error;
use std::fs;
use std::process::ExitCode;

use gingervm_core::broker::{
    BrokerError, BrokerValue, GuestSyscall, OpenFlags, SyscallBroker, VirtualIdentity,
};
use gingervm_core::elf::{run_elf, DEFAULT_MAX_STEPS};
use gingervm_core::guest::GuestProgram;
use gingervm_core::profile::GINGERBREAD_2_3_7;
use gingervm_core::rootfs::RootFs;
use gingervm_core::syscall::route_syscall;
use gingervm_core::VERSION;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("gingervm: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("version") => println!("GingerVM {VERSION}"),
        Some("profile") => println!("{}", GINGERBREAD_2_3_7.summary()),
        Some("doctor") => {
            println!("GingerVM {VERSION}");
            println!("Host: {} / {}", env::consts::OS, env::consts::ARCH);
            println!("Guest: {}", GINGERBREAD_2_3_7.summary());
            println!("Host-side static ARM/Thumb ELF interpreter: enabled (restricted instruction subset)");
            println!("Android SDK/NDK is required for an APK or linked Android .so; this CLI does not need it.");
        }
        Some("init") => {
            let root = args
                .next()
                .ok_or("usage: gingervm init <rootfs-directory>")?;
            if args.next().is_some() {
                return Err("usage: gingervm init <rootfs-directory>".into());
            }
            let root = RootFs::open(root)?;
            root.initialize_layout()?;
            println!(
                "Initialized guest rootfs layout at {}",
                root.root().display()
            );
        }
        Some("map") => {
            let root_path = args
                .next()
                .ok_or("usage: gingervm map <rootfs-directory> <absolute-guest-path>")?;
            let guest_path = args
                .next()
                .ok_or("usage: gingervm map <rootfs-directory> <absolute-guest-path>")?;
            if args.next().is_some() {
                return Err("usage: gingervm map <rootfs-directory> <absolute-guest-path>".into());
            }
            let root = RootFs::open(root_path)?;
            println!("{}", root.map_absolute(&guest_path)?.display());
        }
        Some("route") => {
            let name = args.next().ok_or("usage: gingervm route <syscall-name>")?;
            if args.next().is_some() {
                return Err("usage: gingervm route <syscall-name>".into());
            }
            println!("{name}: {}", route_syscall(&name));
        }
        Some("probe") => {
            let root_path = args
                .next()
                .ok_or("usage: gingervm probe <rootfs-directory>")?;
            if args.next().is_some() {
                return Err("usage: gingervm probe <rootfs-directory>".into());
            }
            run_probe(root_path)?;
        }
        Some("run-elf") => {
            let root_path = args
                .next()
                .ok_or("usage: gingervm run-elf <rootfs-directory> <static-arm-elf>")?;
            let elf_path = args
                .next()
                .ok_or("usage: gingervm run-elf <rootfs-directory> <static-arm-elf>")?;
            if args.next().is_some() {
                return Err("usage: gingervm run-elf <rootfs-directory> <static-arm-elf>".into());
            }
            run_elf_file(root_path, elf_path)?;
        }
        _ => {
            print_usage();
            return Err("unknown or missing command".into());
        }
    }
    Ok(())
}

fn run_probe(root_path: String) -> Result<(), Box<dyn Error>> {
    let root = RootFs::open(root_path)?;
    root.initialize_layout()?;
    let guest_path = format!("/tmp/.gingervm-probe-{}.txt", std::process::id());
    let cleanup_path = root.map_absolute(&guest_path)?;
    let payload = b"GingerVM broker round-trip: OK\n".to_vec();

    let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
    let program = GuestProgram::new(
        "cli-file-and-identity-probe",
        vec![
            GuestSyscall::Open {
                path: guest_path.clone(),
                flags: OpenFlags::WRITE_CREATE_TRUNCATE,
            },
            GuestSyscall::Write {
                fd: 3,
                bytes: payload.clone(),
            },
            GuestSyscall::Close { fd: 3 },
            GuestSyscall::Open {
                path: guest_path,
                flags: OpenFlags::READ_ONLY,
            },
            GuestSyscall::Read { fd: 3, count: 128 },
            GuestSyscall::Close { fd: 3 },
            GuestSyscall::GetUid,
            GuestSyscall::GetGid,
            GuestSyscall::GetPid,
        ],
    );
    let execution = program.run(&mut broker);
    let cleanup_result = if cleanup_path.exists() {
        fs::remove_file(cleanup_path)
    } else {
        Ok(())
    };
    let report = execution?;
    cleanup_result?;

    let readback = report
        .events
        .iter()
        .find_map(|event| match &event.result {
            BrokerValue::Bytes(bytes) => Some(bytes.as_slice()),
            _ => None,
        })
        .ok_or("probe did not receive a read result")?;
    if readback != payload {
        return Err("guest-to-broker file round-trip did not match".into());
    }

    let denied = broker.dispatch(&GuestSyscall::Control {
        name: "mount".to_owned(),
    });
    if !matches!(denied, Err(BrokerError::Denied(name)) if name == "mount") {
        return Err("mount control call was not denied".into());
    }
    println!("Guest probe: scripted syscall ABI harness (not ARM instruction execution)");
    println!("Completed {} brokered syscalls", report.events.len());
    println!("Rootfs file write/read round-trip: OK");
    println!("Virtual identity: uid=1000 gid=1000 pid=1");
    println!("Host-control syscall mount: denied");
    Ok(())
}

fn run_elf_file(root_path: String, elf_path: String) -> Result<(), Box<dyn Error>> {
    let image = fs::read(&elf_path)?;
    let root = RootFs::open(root_path)?;
    root.initialize_layout()?;
    let mut broker = SyscallBroker::new(root, VirtualIdentity::default());
    let report = run_elf(&image, &mut broker, DEFAULT_MAX_STEPS)?;

    println!("Guest ELF: {elf_path}");
    println!("Instruction set: {}", report.instruction_set);
    println!("Instructions executed: {}", report.instructions_executed);
    println!("Brokered syscall events: {}", report.events.len());
    for event in &report.events {
        match &event.result {
            Ok(BrokerValue::FileDescriptor(fd)) => {
                println!("  {} -> guest fd {fd}", event.syscall.name());
            }
            Ok(BrokerValue::Bytes(bytes)) => {
                println!("  {} -> {} bytes", event.syscall.name(), bytes.len());
            }
            Ok(BrokerValue::Count(count)) => {
                println!("  {} -> {count}", event.syscall.name());
            }
            Ok(BrokerValue::Identity(identity)) => {
                println!("  {} -> {identity}", event.syscall.name());
            }
            Ok(BrokerValue::Unit) => println!("  {} -> OK", event.syscall.name()),
            Err(errno) => println!("  {} -> errno {errno}", event.syscall.name()),
        }
    }
    println!("Guest exit code: {}", report.exit_code);
    Ok(())
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  gingervm version");
    eprintln!("  gingervm doctor");
    eprintln!("  gingervm profile");
    eprintln!("  gingervm init <rootfs-directory>");
    eprintln!("  gingervm map <rootfs-directory> <absolute-guest-path>");
    eprintln!("  gingervm route <syscall-name>");
    eprintln!("  gingervm probe <rootfs-directory>");
    eprintln!("  gingervm run-elf <rootfs-directory> <static-arm-elf>");
}
