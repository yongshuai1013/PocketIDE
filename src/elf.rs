use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::fmt;
use std::fs;

use crate::arm::{
    decode_single_transfer_register_offset, execute_data_processing, execute_multiply,
    Flags as ArmFlags,
};
use crate::broker::{
    BrokerError, BrokerValue, GuestSyscall, OpenFlags, SyscallBroker, VirtualIdentity,
    MAX_TRANSFER_BYTES,
};
use crate::rootfs::{RootFs, RootFsError};

const ELF_HEADER_SIZE: usize = 52;
const ELF_PROGRAM_HEADER_SIZE: usize = 32;
const ELFCLASS32: u8 = 1;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_ARM: u16 = 40;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const DT_NULL: u32 = 0;
const DT_NEEDED: u32 = 1;
const DT_HASH: u32 = 4;
const DT_STRTAB: u32 = 5;
const DT_SYMTAB: u32 = 6;
const DT_PLTRELSZ: u32 = 2;
const DT_RELA: u32 = 7;
const DT_RELASZ: u32 = 8;
const DT_REL: u32 = 17;
const DT_RELSZ: u32 = 18;
const DT_RELENT: u32 = 19;
const DT_PLTREL: u32 = 20;
const DT_JMPREL: u32 = 23;
const DT_STRSZ: u32 = 10;
const DT_SYMENT: u32 = 11;
const R_ARM_NONE: u32 = 0;
const R_ARM_ABS32: u32 = 2;
const R_ARM_REL32: u32 = 3;
const R_ARM_COPY: u32 = 20;
const R_ARM_GLOB_DAT: u32 = 21;
const R_ARM_JUMP_SLOT: u32 = 22;
const R_ARM_RELATIVE: u32 = 23;
// Linux's ARM-private syscall range: __ARM_NR_BASE + 5.
const ARM_NR_SET_TLS: u32 = 0x000f_0005;
const KUSER_HELPER_PAGE_BASE: u32 = 0xffff_0000;
const KUSER_GET_TLS: u32 = 0xffff_0fe0;
const DT_PLTREL_REL: u32 = DT_REL;
const PAGE_SIZE: u32 = 4096;
const MAX_IMAGE_BYTES: usize = 32 * 1024 * 1024;
const MAX_MAPPING_BYTES: usize = 64 * 1024 * 1024;
const MAX_GUEST_MEMORY_BYTES: usize = 128 * 1024 * 1024;
const MMAP_BASE: u32 = 0x4000_0000;
const MMAP_LIMIT: u32 = 0x7000_0000;
const DYN_IMAGE_BASE: u32 = 0x1000_0000;
const DYN_INTERPRETER_BASE: u32 = 0x2000_0000;
const DYN_LIBRARY_BASE: u32 = 0x3000_0000;
const DYN_LIBRARY_STRIDE: u32 = 0x0100_0000;
const MAX_LIBRARY_COUNT: usize = 16;
const MAX_NEEDED_LIBRARIES: usize = 64;
const MAX_DYNAMIC_SYMBOLS: usize = 262_144;
const MAX_DYNAMIC_STRING_BYTES: usize = 4096;
const STACK_BASE: u32 = 0x7ff0_0000;
const STACK_SIZE: usize = 128 * 1024;
const RLIMIT_STACK: u32 = 3;
const MAX_PATH_BYTES: usize = 4096;
const LEGACY_SIGACTION_SIZE: usize = 16;
const GINGERBREAD_SIGNAL_COUNT: usize = 31;
const AT_NULL: u32 = 0;
const AT_PHDR: u32 = 3;
const AT_PHENT: u32 = 4;
const AT_PHNUM: u32 = 5;
const AT_PAGESZ: u32 = 6;
#[derive(Debug, Clone, Copy, Default)]
struct LegacySignalAction {
    handler: u32,
    mask: u32,
    flags: u32,
    restorer: u32,
}

impl LegacySignalAction {
    fn from_abi_bytes(bytes: &[u8]) -> Self {
        Self {
            handler: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            mask: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            flags: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            restorer: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        }
    }

    fn to_abi_bytes(self) -> [u8; LEGACY_SIGACTION_SIZE] {
        let mut bytes = [0; LEGACY_SIGACTION_SIZE];
        bytes[0..4].copy_from_slice(&self.handler.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.mask.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.flags.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.restorer.to_le_bytes());
        bytes
    }
}

const AT_BASE: u32 = 7;
const AT_FLAGS: u32 = 8;
const AT_ENTRY: u32 = 9;
const AT_UID: u32 = 11;
const AT_EUID: u32 = 12;
const AT_GID: u32 = 13;
const AT_EGID: u32 = 14;
const AT_PLATFORM: u32 = 15;
const AT_HWCAP: u32 = 16;
const AT_CLKTCK: u32 = 17;
const AT_SECURE: u32 = 23;
const AT_RANDOM: u32 = 25;
const AT_EXECFN: u32 = 31;
const STAT64_SIZE: usize = 96;

/// Default instruction budget for a guest image. This prevents an accidental
/// infinite loop from hanging the host-side test runner.
pub const DEFAULT_MAX_STEPS: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionSet {
    Arm,
    Thumb,
}

impl fmt::Display for InstructionSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arm => f.write_str("ARM"),
            Self::Thumb => f.write_str("Thumb"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSyscallEvent {
    /// CPU instruction count when the guest entered the syscall.
    pub step: u64,
    pub pc: u32,
    pub syscall: GuestSyscall,
    /// On failure this is a positive Linux errno; the guest receives -errno in r0.
    pub result: Result<BrokerValue, i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfExecutionReport {
    pub entry: u32,
    pub instruction_set: InstructionSet,
    pub instructions_executed: u64,
    /// Meaningful only when `stop_reason` is `GuestExited`; idle runs use zero here.
    pub exit_code: i32,
    /// Distinguishes a process exit from a headless wait for unavailable events.
    pub stop_reason: ElfStopReason,
    pub events: Vec<ElfSyscallEvent>,
    pub syscall_trace: Vec<ElfSyscallTrace>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfStopReason {
    GuestExited,
    WaitingForEvents,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfSyscallTrace {
    pub step: u64,
    pub pc: u32,
    pub number: u32,
    pub args: [u32; 6],
    /// Raw ARM EABI return register, including negative errno values.
    pub result: u32,
    /// True when execution stopped at an indefinitely blocking guest syscall.
    pub blocked: bool,
}

#[derive(Debug)]
pub enum ElfError {
    Invalid(&'static str),
    Unsupported(&'static str),
    Bounds(&'static str),
    InterpreterLoad(String),
    LibraryLoad(String),
    UnresolvedSymbol(String),
    HostIo(String),
    MemoryAccess {
        address: u32,
        access: &'static str,
    },
    CpuMemoryFault {
        address: u32,
        access: &'static str,
        pc: u32,
        instruction: Option<u32>,
        instruction_set: InstructionSet,
        registers: [u32; 16],
        cpsr_nzcv: u8,
        instructions: u64,
        trace: String,
    },
    InvalidInstruction {
        pc: u32,
        instruction: u32,
        thumb: bool,
    },
    StepLimit {
        limit: u64,
    },
    Broker {
        pc: u32,
        source: BrokerError,
    },
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid ARM ELF: {message}"),
            Self::Unsupported(message) => write!(f, "unsupported ARM ELF feature: {message}"),
            Self::Bounds(message) => write!(f, "ARM ELF out of bounds: {message}"),
            Self::InterpreterLoad(message) => {
                write!(f, "failed to load guest ELF interpreter: {message}")
            }
            Self::LibraryLoad(message) => {
                write!(f, "failed to load guest shared library: {message}")
            }
            Self::UnresolvedSymbol(name) => {
                write!(f, "unresolved guest dynamic symbol: {name}")
            }
            Self::HostIo(message) => write!(f, "guest process initialization failed: {message}"),
            Self::MemoryAccess { address, access } => {
                write!(f, "guest memory {access} fault at 0x{address:08x}")
            }
            Self::CpuMemoryFault {
                address,
                access,
                pc,
                instruction,
                instruction_set,
                registers,
                cpsr_nzcv,
                instructions,
                trace,
            } => {
                write!(
                    f,
                    "guest memory {access} fault at 0x{address:08x} while executing {instruction_set} step {instructions} at pc=0x{pc:08x}"
                )?;
                match instruction {
                    Some(word) if *instruction_set == InstructionSet::Thumb => {
                        write!(f, "; instruction=0x{word:04x}")?;
                    }
                    Some(word) => write!(f, "; instruction=0x{word:08x}")?,
                    None => write!(f, "; instruction bytes unavailable")?,
                }
                write!(f, "; registers (pre-instruction, architectural PC):")?;
                for (index, value) in registers.iter().enumerate() {
                    if index % 4 == 0 {
                        write!(f, "\n  ")?;
                    } else {
                        write!(f, " ")?;
                    }
                    write!(f, "r{index}=0x{value:08x}")?;
                }
                write!(
                    f,
                    "\n  CPSR.NZCV={}{}{}{}\nrecent guest instruction trace (oldest first):\n{trace}",
                    if cpsr_nzcv & 8 != 0 { '1' } else { '0' },
                    if cpsr_nzcv & 4 != 0 { '1' } else { '0' },
                    if cpsr_nzcv & 2 != 0 { '1' } else { '0' },
                    if cpsr_nzcv & 1 != 0 { '1' } else { '0' },
                )
            }
            Self::InvalidInstruction {
                pc,
                instruction,
                thumb,
            } => write!(
                f,
                "unsupported {} instruction 0x{:04x} at 0x{pc:08x}",
                if *thumb { "Thumb" } else { "ARM" },
                instruction
            ),
            Self::StepLimit { limit } => {
                write!(f, "guest exceeded the instruction limit ({limit})")
            }
            Self::Broker { pc, source } => {
                write!(
                    f,
                    "broker failed while handling guest instruction at 0x{pc:08x}: {source}"
                )
            }
        }
    }
}

impl Error for ElfError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Broker { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct Segment {
    start: u32,
    bytes: Vec<u8>,
    flags: u32,
    /// A private file mapping faults beyond the page containing EOF.
    fault_after: Option<u64>,
}

impl Segment {
    fn end(&self) -> u64 {
        self.start as u64 + self.bytes.len() as u64
    }
}

#[derive(Debug)]
struct GuestMemory {
    segments: Vec<Segment>,
}

impl GuestMemory {
    fn new(segments: Vec<Segment>) -> Self {
        Self { segments }
    }

    fn read(&self, address: u32, length: usize) -> Result<Vec<u8>, ElfError> {
        self.read_with_permission(address, length, PF_R)
    }

    fn write(&mut self, address: u32, bytes: &[u8]) -> Result<(), ElfError> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.check_access(address, bytes.len(), PF_W)?;
        let end = address as u64 + bytes.len() as u64;
        let mut current = address as u64;
        let mut source_offset = 0;
        while current < end {
            let index = self
                .segments
                .iter()
                .position(|segment| {
                    current >= segment.start as u64
                        && current < segment.end()
                        && segment.fault_after.is_none_or(|limit| current < limit)
                })
                .ok_or(ElfError::MemoryAccess {
                    address: current as u32,
                    access: "write",
                })?;
            let segment = &mut self.segments[index];
            let count = (end
                .min(segment.end())
                .min(segment.fault_after.unwrap_or(u64::MAX))
                - current) as usize;
            let offset = (current - segment.start as u64) as usize;
            segment.bytes[offset..offset + count]
                .copy_from_slice(&bytes[source_offset..source_offset + count]);
            current += count as u64;
            source_offset += count;
        }
        Ok(())
    }

    fn check_write(&self, address: u32, length: usize) -> Result<(), ElfError> {
        self.check_access(address, length, PF_W)
    }

    fn fetch(&self, address: u32, length: usize) -> Result<Vec<u8>, ElfError> {
        self.read_with_permission(address, length, PF_X)
    }

    fn read_with_permission(
        &self,
        address: u32,
        length: usize,
        permission: u32,
    ) -> Result<Vec<u8>, ElfError> {
        if length == 0 {
            return Ok(Vec::new());
        }
        let end = checked_memory_end(address, length, permission_name(permission))?;
        let mut bytes = Vec::with_capacity(length);
        let mut current = address as u64;
        while current < end {
            let segment = self
                .segments
                .iter()
                .find(|segment| {
                    current >= segment.start as u64
                        && current < segment.end()
                        && segment.fault_after.is_none_or(|limit| current < limit)
                        && segment.flags & permission == permission
                })
                .ok_or(ElfError::MemoryAccess {
                    address: current as u32,
                    access: permission_name(permission),
                })?;
            let count = (end
                .min(segment.end())
                .min(segment.fault_after.unwrap_or(u64::MAX))
                - current) as usize;
            let offset = (current - segment.start as u64) as usize;
            bytes.extend_from_slice(&segment.bytes[offset..offset + count]);
            current += count as u64;
        }
        Ok(bytes)
    }

    fn check_access(&self, address: u32, length: usize, permission: u32) -> Result<(), ElfError> {
        if length == 0 {
            return Ok(());
        }
        let end = checked_memory_end(address, length, permission_name(permission))?;
        let mut current = address as u64;
        while current < end {
            let segment = self
                .segments
                .iter()
                .find(|segment| {
                    current >= segment.start as u64
                        && current < segment.end()
                        && segment.fault_after.is_none_or(|limit| current < limit)
                        && segment.flags & permission == permission
                })
                .ok_or(ElfError::MemoryAccess {
                    address: current as u32,
                    access: permission_name(permission),
                })?;
            current = end
                .min(segment.end())
                .min(segment.fault_after.unwrap_or(u64::MAX));
        }
        Ok(())
    }

    fn is_page_range_mapped(&self, address: u32, length: usize) -> bool {
        if length == 0 {
            return true;
        }
        if address & (PAGE_SIZE - 1) != 0 || !length.is_multiple_of(PAGE_SIZE as usize) {
            return false;
        }
        let Ok(end) = checked_memory_end(address, length, "access") else {
            return false;
        };
        let page_size = PAGE_SIZE as u64;
        let mut current = address as u64;
        let mut segment_index = 0;
        while segment_index < self.segments.len() && self.segments[segment_index].end() <= current {
            segment_index += 1;
        }
        while current < end {
            let page_end = current + page_size;
            let mut index = segment_index;
            let mut page_is_mapped = false;
            while index < self.segments.len() && (self.segments[index].start as u64) < page_end {
                if self.segments[index].end() > current {
                    page_is_mapped = true;
                    break;
                }
                index += 1;
            }
            if !page_is_mapped {
                return false;
            }
            current = page_end;
            while segment_index < self.segments.len()
                && self.segments[segment_index].end() <= current
            {
                segment_index += 1;
            }
        }
        true
    }

    fn overlaps(&self, start: u32, length: usize) -> bool {
        self.overlaps_except(start, length, None)
    }

    fn overlaps_except(&self, start: u32, length: usize, excluded_start: Option<u32>) -> bool {
        if length == 0 {
            return false;
        }
        let end = start as u64 + length as u64;
        self.segments.iter().any(|segment| {
            Some(segment.start) != excluded_start
                && (start as u64) < segment.end()
                && (segment.start as u64) < end
        })
    }

    fn allocated_bytes(&self) -> usize {
        self.segments
            .iter()
            .map(|segment| segment.bytes.len())
            .sum()
    }

    fn mapped_bytes_in_range(&self, start: u32, length: usize) -> usize {
        let start = start as u64;
        let end = start + length as u64;
        self.segments
            .iter()
            .map(|segment| {
                let overlap_start = start.max(segment.start as u64);
                let overlap_end = end.min(segment.end());
                overlap_end.saturating_sub(overlap_start) as usize
            })
            .sum()
    }

    fn find_free_mapping(&self, hint: u32, length: usize) -> Option<u32> {
        let length = length as u64;
        let hint_is_candidate = hint >= MMAP_BASE
            && hint & (PAGE_SIZE - 1) == 0
            && hint as u64 + length <= KUSER_HELPER_PAGE_BASE as u64
            && !self.overlaps(hint, length as usize);
        let end_limit = if hint_is_candidate {
            KUSER_HELPER_PAGE_BASE as u64
        } else {
            MMAP_LIMIT as u64
        };
        let mut candidate = if hint_is_candidate { hint } else { MMAP_BASE } as u64;
        for segment in &self.segments {
            let candidate_end = candidate + length;
            if candidate_end > end_limit {
                return None;
            }
            if segment.end() <= candidate {
                continue;
            }
            if segment.start as u64 >= candidate_end {
                break;
            }
            candidate = align_up_u64(segment.end(), PAGE_SIZE as u64)?;
        }
        if candidate + length <= end_limit {
            Some(candidate as u32)
        } else {
            None
        }
    }

    fn map_zeroed(&mut self, start: u32, length: usize, flags: u32) -> Result<(), ElfError> {
        let end = checked_memory_end(start, length, "map")?;
        if length == 0 || self.overlaps(start, length) || end > u32::MAX as u64 + 1 {
            return Err(ElfError::Invalid("invalid or overlapping guest mapping"));
        }
        self.segments.push(Segment {
            start,
            bytes: vec![0; length],
            flags,
            fault_after: None,
        });
        self.segments.sort_by_key(|segment| segment.start);
        Ok(())
    }

    fn map_file_bytes(
        &mut self,
        start: u32,
        length: usize,
        data: &[u8],
        flags: u32,
    ) -> Result<(), ElfError> {
        let end = checked_memory_end(start, length, "map")?;
        if length == 0 || data.len() > length || self.overlaps(start, length) {
            return Err(ElfError::Invalid("invalid or overlapping file mapping"));
        }
        let mut bytes = vec![0; length];
        bytes[..data.len()].copy_from_slice(data);
        let fault_after = if data.len() < length {
            let accessible = page_rounded_length(data.len())
                .unwrap_or(length)
                .min(length);
            Some(start as u64 + accessible as u64)
        } else {
            None
        };
        self.segments.push(Segment {
            start,
            bytes,
            flags,
            fault_after,
        });
        self.segments.sort_by_key(|segment| segment.start);
        debug_assert!(end <= u32::MAX as u64 + 1);
        Ok(())
    }

    fn unmap(&mut self, start: u32, length: usize) {
        let end = start as u64 + length as u64;
        let mut kept = Vec::with_capacity(self.segments.len() + 1);
        for segment in self.segments.drain(..) {
            let segment_start = segment.start as u64;
            let segment_end = segment.end();
            if segment_end <= start as u64 || segment_start >= end {
                kept.push(segment);
                continue;
            }
            if segment_start < start as u64 {
                let left_len = (start as u64 - segment_start) as usize;
                kept.push(Segment {
                    start: segment.start,
                    bytes: segment.bytes[..left_len].to_vec(),
                    flags: segment.flags,
                    fault_after: segment.fault_after,
                });
            }
            if segment_end > end {
                let right_offset = (end - segment_start) as usize;
                kept.push(Segment {
                    start: end as u32,
                    bytes: segment.bytes[right_offset..].to_vec(),
                    flags: segment.flags,
                    fault_after: segment.fault_after,
                });
            }
        }
        self.segments = kept;
        self.segments.sort_by_key(|segment| segment.start);
    }

    fn protect(&mut self, start: u32, length: usize, flags: u32) -> Result<(), ElfError> {
        if !self.is_page_range_mapped(start, length) {
            return Err(ElfError::Invalid(
                "mprotect range includes an unmapped address",
            ));
        }
        let end = start as u64 + length as u64;
        self.split_at(start as u64);
        self.split_at(end);
        for segment in &mut self.segments {
            if segment.start >= start && segment.end() <= end {
                segment.flags = flags;
            }
        }
        self.merge_adjacent();
        Ok(())
    }

    fn split_at(&mut self, boundary: u64) {
        let Some(index) = self
            .segments
            .iter()
            .position(|segment| boundary > segment.start as u64 && boundary < segment.end())
        else {
            return;
        };
        let right_offset = (boundary - self.segments[index].start as u64) as usize;
        let right_bytes = self.segments[index].bytes.split_off(right_offset);
        let right = Segment {
            start: boundary as u32,
            bytes: right_bytes,
            flags: self.segments[index].flags,
            fault_after: self.segments[index].fault_after,
        };
        self.segments.insert(index + 1, right);
    }

    fn merge_adjacent(&mut self) {
        let mut index = 0;
        while index + 1 < self.segments.len() {
            let adjacent = self.segments[index].end() == self.segments[index + 1].start as u64;
            if adjacent
                && self.segments[index].flags == self.segments[index + 1].flags
                && self.segments[index].fault_after == self.segments[index + 1].fault_after
            {
                let next = self.segments.remove(index + 1);
                self.segments[index].bytes.extend_from_slice(&next.bytes);
            } else {
                index += 1;
            }
        }
    }
}

fn checked_memory_end(address: u32, length: usize, access: &'static str) -> Result<u64, ElfError> {
    let Some(end) = (address as u64).checked_add(length as u64) else {
        return Err(ElfError::MemoryAccess { address, access });
    };
    if end > u32::MAX as u64 + 1 {
        return Err(ElfError::MemoryAccess { address, access });
    }
    Ok(end)
}

fn page_rounded_length(length: usize) -> Option<usize> {
    if length == 0 {
        return Some(0);
    }
    let page_size = PAGE_SIZE as usize;
    length
        .checked_add(page_size - 1)
        .map(|length| length & !(page_size - 1))
}

fn align_up_u64(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
}

fn permission_name(permission: u32) -> &'static str {
    match permission {
        PF_R => "read",
        PF_W => "write",
        PF_X => "execute",
        _ => "access",
    }
}

struct LoadedImage {
    memory: GuestMemory,
    entry: u32,
    elf_entry: u32,
    instruction_set: InstructionSet,
    stack_pointer: u32,
    brk_base: u32,
    load_bias: u32,
    interpreter_path: Option<String>,
    phdr_address: Option<u32>,
    phent: u32,
    phnum: u32,
    dynamic: Option<DynamicInfo>,
}

#[derive(Debug, Clone)]
struct DynamicInfo {
    needed: Vec<String>,
    rel: Option<(u32, usize)>,
    plt_rel: Option<(u32, usize)>,
    symtab: Option<u32>,
    syment: Option<u32>,
    strtab: Option<u32>,
    strsz: Option<u32>,
    symbol_count: Option<usize>,
}

#[derive(Clone, Copy)]
struct ResolvedSymbol {
    value: u32,
    binding: u8,
    size: u32,
    image_index: usize,
}

struct DynamicSymbol {
    name: String,
    value: u32,
    size: u32,
    binding: u8,
    visibility: u8,
    section_index: u16,
}

#[derive(Clone, Copy)]
struct InitialStackInfo {
    phdr_address: u32,
    phent: u32,
    phnum: u32,
    interpreter_base: u32,
    program_entry: u32,
    identity: VirtualIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DependencyLoading {
    HostCompatibility,
    GuestInterpreter,
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, ElfError> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or(ElfError::Bounds("truncated 16-bit field"))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, ElfError> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or(ElfError::Bounds("truncated 32-bit field"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn load_elf(
    bytes: &[u8],
    rootfs: &RootFs,
    identity: VirtualIdentity,
    argv: &[String],
    env: &[String],
    dependency_loading: DependencyLoading,
) -> Result<LoadedImage, ElfError> {
    let mut loaded = load_elf_image(bytes, DYN_IMAGE_BASE, true, true, true)?;
    let program_entry = loaded.elf_entry;
    let interpreter_path = loaded.interpreter_path.take();
    let mut interpreter_base = 0;

    if dependency_loading == DependencyLoading::GuestInterpreter && interpreter_path.is_none() {
        return Err(ElfError::Unsupported(
            "guest-interpreter mode requires a PT_INTERP executable",
        ));
    }

    if let Some(path) = interpreter_path {
        if loaded.phdr_address.is_none() {
            return Err(ElfError::Unsupported(
                "PT_INTERP executable does not map its program headers",
            ));
        }
        let mut images = vec![loaded];
        if dependency_loading == DependencyLoading::HostCompatibility {
            let libraries = load_needed_libraries(&images[0], rootfs)?;
            images.extend(libraries);
            apply_symbol_relocations(&mut images)?;
        }

        let mut main = images.remove(0);
        let mut segments = std::mem::take(&mut main.memory.segments);
        for mut image in images {
            segments.append(&mut image.memory.segments);
        }
        segments.sort_by_key(|segment| segment.start);
        let mapped_bytes: usize = segments.iter().map(|segment| segment.bytes.len()).sum();
        if mapped_bytes > MAX_GUEST_MEMORY_BYTES {
            return Err(ElfError::Unsupported(
                "main and dependency images exceed the guest memory limit",
            ));
        }
        main.memory = GuestMemory::new(segments);

        let host_path = rootfs
            .map_absolute(&path)
            .map_err(|error| ElfError::InterpreterLoad(format!("{path}: {error}")))?;
        let interpreter_bytes = fs::read(&host_path)
            .map_err(|error| ElfError::InterpreterLoad(format!("{path}: {error}")))?;
        let interpreter =
            load_elf_image(&interpreter_bytes, DYN_INTERPRETER_BASE, false, false, true)?;
        interpreter_base = interpreter.load_bias;

        let mut segments = main.memory.segments;
        for segment in interpreter.memory.segments {
            if segments.iter().any(|existing| {
                (segment.start as u64) < existing.end() && (existing.start as u64) < segment.end()
            }) {
                return Err(ElfError::Invalid(
                    "PT_INTERP image overlaps the main guest image",
                ));
            }
            segments.push(segment);
        }
        segments.sort_by_key(|segment| segment.start);
        let mapped_bytes: usize = segments.iter().map(|segment| segment.bytes.len()).sum();
        if mapped_bytes > MAX_GUEST_MEMORY_BYTES {
            return Err(ElfError::Unsupported(
                "main, dependencies, and interpreter exceed the guest memory limit",
            ));
        }
        main.memory = GuestMemory::new(segments);
        main.entry = interpreter.entry;
        main.instruction_set = interpreter.instruction_set;
        loaded = main;
    }

    // ARM Linux exposes this read-only helper page to every process, not just
    // dynamically linked programs. Gingerbread's static Bionic libc uses the
    // same __kuser_get_tls entry during startup.
    if loaded
        .memory
        .overlaps(KUSER_HELPER_PAGE_BASE, PAGE_SIZE as usize)
    {
        return Err(ElfError::Unsupported(
            "guest image overlaps the ARM Linux helper page",
        ));
    }
    if loaded
        .memory
        .allocated_bytes()
        .saturating_add(PAGE_SIZE as usize)
        > MAX_GUEST_MEMORY_BYTES
    {
        return Err(ElfError::Unsupported(
            "guest image and ARM Linux helper page exceed the guest memory limit",
        ));
    }
    let mut helper_page = vec![0; PAGE_SIZE as usize];
    let get_tls_offset = (KUSER_GET_TLS - KUSER_HELPER_PAGE_BASE) as usize;
    helper_page[get_tls_offset..get_tls_offset + 4].copy_from_slice(&0xee1d_0f70_u32.to_le_bytes()); // mrc p15, 0, r0, c13, c0, 3
    helper_page[get_tls_offset + 4..get_tls_offset + 8]
        .copy_from_slice(&0xe12f_ff1e_u32.to_le_bytes()); // bx lr
    loaded.memory.segments.push(Segment {
        start: KUSER_HELPER_PAGE_BASE,
        bytes: helper_page,
        flags: PF_R | PF_X,
        fault_after: None,
    });
    loaded.memory.segments.sort_by_key(|segment| segment.start);

    let (stack_pointer, stack_bytes) = build_initial_stack(
        InitialStackInfo {
            phdr_address: loaded.phdr_address.unwrap_or(0),
            phent: loaded.phent,
            phnum: loaded.phnum,
            interpreter_base,
            program_entry,
            identity,
        },
        argv,
        env,
    )?;
    if loaded.memory.overlaps(STACK_BASE, STACK_SIZE) {
        return Err(ElfError::Unsupported(
            "guest image overlaps the reserved stack region",
        ));
    }
    loaded.memory.segments.push(Segment {
        start: STACK_BASE,
        bytes: stack_bytes,
        flags: PF_R | PF_W,
        fault_after: None,
    });
    loaded.memory.segments.sort_by_key(|segment| segment.start);
    loaded.stack_pointer = stack_pointer;
    Ok(loaded)
}

fn load_elf_image(
    bytes: &[u8],
    dynamic_base: u32,
    allow_interpreter: bool,
    apply_self_relocations: bool,
    require_entry: bool,
) -> Result<LoadedImage, ElfError> {
    if bytes.len() < ELF_HEADER_SIZE {
        return Err(ElfError::Bounds("file is shorter than the ELF32 header"));
    }
    if bytes.get(0..4) != Some(b"\x7fELF") {
        return Err(ElfError::Invalid("bad ELF magic"));
    }
    if bytes[4] != ELFCLASS32 {
        return Err(ElfError::Unsupported(
            "only 32-bit ELF images are supported",
        ));
    }
    if bytes[5] != ELFDATA2LSB {
        return Err(ElfError::Unsupported(
            "only little-endian ELF images are supported",
        ));
    }
    if bytes[6] != 1 || u32_at(bytes, 20)? != 1 {
        return Err(ElfError::Invalid("unsupported ELF version"));
    }
    let elf_type = u16_at(bytes, 16)?;
    if !matches!(elf_type, ET_EXEC | ET_DYN) {
        return Err(ElfError::Unsupported(
            "only ARM ET_EXEC and ET_DYN images are supported",
        ));
    }
    if u16_at(bytes, 18)? != EM_ARM {
        return Err(ElfError::Unsupported("ELF machine is not 32-bit ARM"));
    }
    let header_size = u16_at(bytes, 40)? as usize;
    if header_size < ELF_HEADER_SIZE || header_size > bytes.len() {
        return Err(ElfError::Invalid("invalid ELF32 header size"));
    }
    let raw_entry = u32_at(bytes, 24)?;
    let phoff = u32_at(bytes, 28)? as usize;
    let phentsize = u16_at(bytes, 42)? as usize;
    let phnum = u16_at(bytes, 44)? as usize;
    if phentsize < ELF_PROGRAM_HEADER_SIZE || phnum == 0 {
        return Err(ElfError::Invalid(
            "missing or truncated program header table",
        ));
    }
    let table_size = phentsize
        .checked_mul(phnum)
        .ok_or(ElfError::Bounds("program header table size overflow"))?;
    let table_end = phoff
        .checked_add(table_size)
        .ok_or(ElfError::Bounds("program header table offset overflow"))?;
    if table_end > bytes.len() {
        return Err(ElfError::Bounds("program header table exceeds file size"));
    }

    let mut minimum_page = None;
    let mut interpreter_segment = None;
    let mut dynamic_segment = None;
    for index in 0..phnum {
        let offset = phoff + index * phentsize;
        match u32_at(bytes, offset)? {
            PT_TLS => {
                return Err(ElfError::Unsupported(
                    "native PT_TLS is unsupported; Gingerbread Bionic uses emulated TLS",
                ));
            }
            PT_INTERP => {
                if interpreter_segment.is_some() {
                    return Err(ElfError::Invalid("multiple PT_INTERP segments"));
                }
                if !allow_interpreter {
                    return Err(ElfError::Unsupported(
                        "nested PT_INTERP segments are not supported",
                    ));
                }
                let file_offset = u32_at(bytes, offset + 4)? as usize;
                let file_size = u32_at(bytes, offset + 16)? as usize;
                let file_end = file_offset
                    .checked_add(file_size)
                    .ok_or(ElfError::Bounds("PT_INTERP file range overflow"))?;
                if !(2..=MAX_PATH_BYTES).contains(&file_size) || file_end > bytes.len() {
                    return Err(ElfError::Bounds("invalid PT_INTERP file range"));
                }
                interpreter_segment = Some((file_offset, file_size));
            }
            PT_DYNAMIC => {
                if dynamic_segment.is_some() {
                    return Err(ElfError::Invalid("multiple PT_DYNAMIC segments"));
                }
                let file_offset = u32_at(bytes, offset + 4)? as usize;
                let virtual_address = u32_at(bytes, offset + 8)?;
                let file_size = u32_at(bytes, offset + 16)? as usize;
                let memory_size = u32_at(bytes, offset + 20)? as usize;
                let file_end = file_offset
                    .checked_add(file_size)
                    .ok_or(ElfError::Bounds("PT_DYNAMIC file range overflow"))?;
                if file_size > memory_size || file_end > bytes.len() {
                    return Err(ElfError::Bounds(
                        "PT_DYNAMIC exceeds its file or memory range",
                    ));
                }
                dynamic_segment = Some((file_offset, file_size, virtual_address, memory_size));
            }
            PT_LOAD => {
                let virtual_address = u32_at(bytes, offset + 8)?;
                let memory_size = u32_at(bytes, offset + 20)?;
                if memory_size != 0 {
                    let page = virtual_address & !(PAGE_SIZE - 1);
                    minimum_page =
                        Some(minimum_page.map_or(page, |current: u32| current.min(page)));
                }
            }
            _ => {}
        }
    }
    let load_bias = if elf_type == ET_DYN {
        let minimum_page =
            minimum_page.ok_or(ElfError::Invalid("ELF has no loadable PT_LOAD segment"))?;
        dynamic_base
            .checked_sub(minimum_page)
            .ok_or(ElfError::Unsupported(
                "ET_DYN image virtual addresses exceed the supported load window",
            ))?
    } else {
        0
    };

    let mut segments = Vec::new();
    let mut mapped_bytes = 0usize;
    for index in 0..phnum {
        let offset = phoff + index * phentsize;
        if u32_at(bytes, offset)? != PT_LOAD {
            continue;
        }
        let file_offset = u32_at(bytes, offset + 4)? as usize;
        let raw_virtual_address = u32_at(bytes, offset + 8)?;
        let file_size = u32_at(bytes, offset + 16)? as usize;
        let memory_size = u32_at(bytes, offset + 20)? as usize;
        let flags = u32_at(bytes, offset + 24)?;
        if memory_size < file_size {
            return Err(ElfError::Invalid(
                "PT_LOAD memory size is smaller than file size",
            ));
        }
        if memory_size == 0 {
            continue;
        }
        let file_end = file_offset
            .checked_add(file_size)
            .ok_or(ElfError::Bounds("PT_LOAD file range overflow"))?;
        if file_end > bytes.len() {
            return Err(ElfError::Bounds("PT_LOAD segment exceeds file size"));
        }
        let virtual_address = raw_virtual_address
            .checked_add(load_bias)
            .ok_or(ElfError::Bounds("relocated PT_LOAD address overflow"))?;
        let virtual_end = virtual_address as u64 + memory_size as u64;
        if virtual_end > u32::MAX as u64 + 1 {
            return Err(ElfError::Bounds("PT_LOAD virtual address range overflow"));
        }
        mapped_bytes = mapped_bytes
            .checked_add(memory_size)
            .ok_or(ElfError::Bounds("mapped image size overflow"))?;
        if mapped_bytes > MAX_IMAGE_BYTES {
            return Err(ElfError::Unsupported(
                "guest image exceeds the 32 MiB mapping limit",
            ));
        }
        let mut data = vec![0; memory_size];
        data[..file_size].copy_from_slice(&bytes[file_offset..file_end]);
        segments.push(Segment {
            start: virtual_address,
            bytes: data,
            flags,
            fault_after: None,
        });
    }
    if segments.is_empty() {
        return Err(ElfError::Invalid("ELF has no loadable PT_LOAD segment"));
    }
    segments.sort_by_key(|segment| segment.start);
    for pair in segments.windows(2) {
        if pair[0].end() > pair[1].start as u64 {
            return Err(ElfError::Invalid("overlapping PT_LOAD segments"));
        }
    }

    let interpreter_path = if let Some((file_offset, file_size)) = interpreter_segment {
        let raw_path = &bytes[file_offset..file_offset + file_size];
        if raw_path.last() != Some(&0) || raw_path[..file_size - 1].contains(&0) {
            return Err(ElfError::Invalid(
                "PT_INTERP path is not a single NUL-terminated string",
            ));
        }
        let path = std::str::from_utf8(&raw_path[..file_size - 1])
            .map_err(|_| ElfError::Invalid("PT_INTERP path is not valid UTF-8"))?;
        if !path.starts_with('/') {
            return Err(ElfError::Invalid("PT_INTERP path is not absolute"));
        }
        Some(path.to_owned())
    } else {
        None
    };

    let dynamic_info =
        if let Some((file_offset, file_size, virtual_address, memory_size)) = dynamic_segment {
            if memory_size < file_size {
                return Err(ElfError::Invalid(
                    "PT_DYNAMIC memory size is smaller than its file size",
                ));
            }
            let dynamic_address = virtual_address
                .checked_add(load_bias)
                .ok_or(ElfError::Bounds("relocated PT_DYNAMIC address overflow"))?;
            // Require the dynamic table to be part of the loaded image, rather than
            // trusting an unrelated file range supplied by a malformed header.
            read_image_bytes(&segments, dynamic_address, file_size)?;
            if interpreter_path.is_none() && apply_self_relocations {
                apply_dynamic_relocations(
                    bytes,
                    (file_offset, file_size, virtual_address, memory_size),
                    load_bias,
                    &mut segments,
                )?;
                None
            } else {
                Some(parse_dynamic_info(
                    &segments,
                    dynamic_address,
                    file_size,
                    load_bias,
                )?)
            }
        } else {
            None
        };

    let entry = (raw_entry & !1)
        .checked_add(load_bias)
        .ok_or(ElfError::Bounds("relocated ELF entry overflow"))?;
    let elf_entry = raw_entry
        .checked_add(load_bias)
        .ok_or(ElfError::Bounds("relocated ELF e_entry overflow"))?;
    let thumb = raw_entry & 1 != 0;
    if require_entry && ((!thumb && entry & 3 != 0) || (thumb && entry & 1 != 0)) {
        return Err(ElfError::Invalid(
            "entry point has invalid instruction alignment",
        ));
    }
    if require_entry
        && !segments.iter().any(|segment| {
            entry >= segment.start && (entry as u64) < segment.end() && segment.flags & PF_X != 0
        })
    {
        return Err(ElfError::Invalid(
            "entry point is not in an executable PT_LOAD segment",
        ));
    }

    let image_end = segments
        .iter()
        .map(Segment::end)
        .max()
        .ok_or(ElfError::Invalid("ELF has no loadable PT_LOAD segment"))?;
    if elf_type == ET_DYN && image_end > MMAP_BASE as u64 {
        return Err(ElfError::Unsupported(
            "ET_DYN image exceeds the supported address window",
        ));
    }
    let brk_base = align_up_u64(image_end, PAGE_SIZE as u64)
        .filter(|address| *address <= MMAP_BASE as u64)
        .unwrap_or(MMAP_BASE as u64) as u32;

    let phdr_address =
        find_program_headers_address(bytes, phoff, table_end, phentsize, phnum, load_bias)?;
    if let Some(address) = phdr_address {
        read_image_bytes(&segments, address, table_size)?;
    }

    Ok(LoadedImage {
        memory: GuestMemory::new(segments),
        entry,
        elf_entry,
        instruction_set: if thumb {
            InstructionSet::Thumb
        } else {
            InstructionSet::Arm
        },
        stack_pointer: 0,
        brk_base,
        load_bias,
        interpreter_path,
        phdr_address,
        phent: phentsize as u32,
        phnum: phnum as u32,
        dynamic: dynamic_info,
    })
}

fn find_program_headers_address(
    bytes: &[u8],
    phoff: usize,
    table_end: usize,
    phentsize: usize,
    phnum: usize,
    load_bias: u32,
) -> Result<Option<u32>, ElfError> {
    let mut explicit = None;
    let mut covering_load = None;
    for index in 0..phnum {
        let offset = phoff + index * phentsize;
        match u32_at(bytes, offset)? {
            PT_PHDR => {
                let address = u32_at(bytes, offset + 8)?
                    .checked_add(load_bias)
                    .ok_or(ElfError::Bounds("relocated PT_PHDR address overflow"))?;
                explicit = Some(address);
            }
            PT_LOAD => {
                let file_offset = u32_at(bytes, offset + 4)? as usize;
                let virtual_address = u32_at(bytes, offset + 8)?;
                let file_size = u32_at(bytes, offset + 16)? as usize;
                let file_end = file_offset
                    .checked_add(file_size)
                    .ok_or(ElfError::Bounds("PT_LOAD file range overflow"))?;
                if phoff >= file_offset && table_end <= file_end {
                    let relative = phoff - file_offset;
                    let address = virtual_address
                        .checked_add(relative as u32)
                        .and_then(|address| address.checked_add(load_bias))
                        .ok_or(ElfError::Bounds("program header address overflow"))?;
                    covering_load = Some(address);
                    break;
                }
            }
            _ => {}
        }
    }
    let address = explicit.or(covering_load);
    if let Some(address) = address {
        // The caller verifies that the table bytes are present in PT_LOAD.
        Ok(Some(address))
    } else {
        Ok(None)
    }
}

fn parse_dynamic_info(
    segments: &[Segment],
    address: u32,
    size: usize,
    load_bias: u32,
) -> Result<DynamicInfo, ElfError> {
    if !size.is_multiple_of(8) || size > MAX_IMAGE_BYTES {
        return Err(ElfError::Invalid(
            "PT_DYNAMIC size is not a valid whole number of entries",
        ));
    }
    let bytes = read_image_bytes(segments, address, size)?;
    let mut needed_offsets = Vec::new();
    let mut rel_address = None;
    let mut rel_size = None;
    let mut rel_entry_size = None;
    let mut plt_rel_address = None;
    let mut plt_rel_size = None;
    let mut plt_rel_type = None;
    let mut rela_address = None;
    let mut rela_size = None;
    let mut symtab = None;
    let mut syment = None;
    let mut strtab = None;
    let mut strsz = None;
    let mut hash = None;
    let mut terminated = false;

    for entry in bytes.chunks_exact(8) {
        let tag = u32::from_le_bytes(entry[..4].try_into().unwrap());
        let value = u32::from_le_bytes(entry[4..].try_into().unwrap());
        if tag == DT_NULL {
            terminated = true;
            break;
        }
        match tag {
            DT_NEEDED => {
                if needed_offsets.len() == MAX_NEEDED_LIBRARIES {
                    return Err(ElfError::Unsupported(
                        "too many DT_NEEDED shared-library entries",
                    ));
                }
                needed_offsets.push(value);
            }
            DT_REL => set_dynamic_value(&mut rel_address, value, "duplicate DT_REL")?,
            DT_RELSZ => set_dynamic_value(&mut rel_size, value, "duplicate DT_RELSZ")?,
            DT_RELENT => set_dynamic_value(&mut rel_entry_size, value, "duplicate DT_RELENT")?,
            DT_JMPREL => set_dynamic_value(&mut plt_rel_address, value, "duplicate DT_JMPREL")?,
            DT_PLTRELSZ => set_dynamic_value(&mut plt_rel_size, value, "duplicate DT_PLTRELSZ")?,
            DT_PLTREL => set_dynamic_value(&mut plt_rel_type, value, "duplicate DT_PLTREL")?,
            DT_RELA => set_dynamic_value(&mut rela_address, value, "duplicate DT_RELA")?,
            DT_RELASZ => set_dynamic_value(&mut rela_size, value, "duplicate DT_RELASZ")?,
            DT_SYMTAB => set_dynamic_value(&mut symtab, value, "duplicate DT_SYMTAB")?,
            DT_SYMENT => set_dynamic_value(&mut syment, value, "duplicate DT_SYMENT")?,
            DT_STRTAB => set_dynamic_value(&mut strtab, value, "duplicate DT_STRTAB")?,
            DT_STRSZ => set_dynamic_value(&mut strsz, value, "duplicate DT_STRSZ")?,
            DT_HASH => set_dynamic_value(&mut hash, value, "duplicate DT_HASH")?,
            9 if value != 0 => {
                return Err(ElfError::Unsupported(
                    "ARM RELA relocation tables are not implemented",
                ));
            }
            0x6000_000f | 0x6000_0010 if value != 0 => {
                return Err(ElfError::Unsupported(
                    "Android packed relocations are not implemented",
                ));
            }
            _ => {}
        }
    }
    if !terminated {
        return Err(ElfError::Invalid("PT_DYNAMIC has no DT_NULL terminator"));
    }
    if rela_size.unwrap_or(0) != 0 || rela_address.unwrap_or(0) != 0 {
        return Err(ElfError::Unsupported(
            "ARM RELA relocation tables are not implemented",
        ));
    }

    let rel_size = rel_size.unwrap_or(0) as usize;
    let rel = if rel_size == 0 {
        None
    } else {
        let entry_size = rel_entry_size.ok_or(ElfError::Invalid("DT_REL is missing DT_RELENT"))?;
        if entry_size != 8 || !rel_size.is_multiple_of(entry_size as usize) {
            return Err(ElfError::Unsupported("invalid ARM DT_REL table"));
        }
        Some((
            rel_address.ok_or(ElfError::Invalid("DT_RELSZ is present without DT_REL"))?,
            rel_size,
        ))
    };
    let plt_size = plt_rel_size.unwrap_or(0) as usize;
    let plt_rel = if plt_size == 0 {
        None
    } else {
        if plt_rel_type != Some(DT_PLTREL_REL) {
            return Err(ElfError::Unsupported(
                "ARM PLT relocation table is not DT_REL",
            ));
        }
        if !plt_size.is_multiple_of(8) {
            return Err(ElfError::Unsupported("invalid ARM PLT relocation table"));
        }
        Some((
            plt_rel_address.ok_or(ElfError::Invalid(
                "DT_PLTRELSZ is present without DT_JMPREL",
            ))?,
            plt_size,
        ))
    };
    if rel
        .as_ref()
        .is_some_and(|(_, length)| *length > MAX_IMAGE_BYTES)
        || plt_rel
            .as_ref()
            .is_some_and(|(_, length)| *length > MAX_IMAGE_BYTES)
    {
        return Err(ElfError::Unsupported("oversized ARM relocation table"));
    }

    let symbol_count = if let Some(hash_address) = hash {
        let hash_address = hash_address
            .checked_add(load_bias)
            .ok_or(ElfError::Bounds("relocated DT_HASH address overflow"))?;
        let header = read_image_bytes(segments, hash_address, 8)?;
        let buckets = u32::from_le_bytes(header[..4].try_into().unwrap()) as usize;
        let count = u32::from_le_bytes(header[4..].try_into().unwrap()) as usize;
        if count > MAX_DYNAMIC_SYMBOLS || buckets > MAX_DYNAMIC_SYMBOLS {
            return Err(ElfError::Unsupported("oversized SysV dynamic symbol hash"));
        }
        let words = 2_usize
            .checked_add(buckets)
            .and_then(|value| value.checked_add(count))
            .ok_or(ElfError::Bounds("DT_HASH table size overflow"))?;
        let table_size = words
            .checked_mul(4)
            .ok_or(ElfError::Bounds("DT_HASH table size overflow"))?;
        read_image_bytes(segments, hash_address, table_size)?;
        Some(count)
    } else {
        None
    };

    let mut needed = Vec::with_capacity(needed_offsets.len());
    if !needed_offsets.is_empty() {
        let raw_strtab = strtab.ok_or(ElfError::Invalid("DT_NEEDED is missing DT_STRTAB"))?;
        let table_size = strsz.ok_or(ElfError::Invalid("DT_NEEDED is missing DT_STRSZ"))?;
        let table_address = raw_strtab
            .checked_add(load_bias)
            .ok_or(ElfError::Bounds("relocated DT_STRTAB address overflow"))?;
        for offset in needed_offsets {
            let name = read_dynamic_string(segments, table_address, table_size, offset)?;
            if name.is_empty() {
                return Err(ElfError::Invalid(
                    "DT_NEEDED contains an empty library name",
                ));
            }
            needed.push(name);
        }
    }

    Ok(DynamicInfo {
        needed,
        rel,
        plt_rel,
        symtab,
        syment,
        strtab,
        strsz,
        symbol_count,
    })
}

fn read_dynamic_string(
    segments: &[Segment],
    table_address: u32,
    table_size: u32,
    offset: u32,
) -> Result<String, ElfError> {
    if offset >= table_size {
        return Err(ElfError::Bounds("dynamic string offset exceeds DT_STRSZ"));
    }
    let max_length = (table_size - offset).min(MAX_DYNAMIC_STRING_BYTES as u32) as usize;
    let start = table_address
        .checked_add(offset)
        .ok_or(ElfError::Bounds("dynamic string address overflow"))?;
    let mut bytes = Vec::new();
    for index in 0..max_length {
        let address = start
            .checked_add(index as u32)
            .ok_or(ElfError::Bounds("dynamic string address overflow"))?;
        let byte = read_image_bytes(segments, address, 1)?[0];
        if byte == 0 {
            return String::from_utf8(bytes)
                .map_err(|_| ElfError::Invalid("dynamic string is not valid UTF-8"));
        }
        bytes.push(byte);
    }
    Err(ElfError::Invalid(
        "dynamic string is not NUL-terminated within its limit",
    ))
}

fn load_needed_libraries(
    main: &LoadedImage,
    rootfs: &RootFs,
) -> Result<Vec<LoadedImage>, ElfError> {
    let mut pending: VecDeque<String> = main
        .dynamic
        .as_ref()
        .map(|dynamic| dynamic.needed.clone())
        .unwrap_or_default()
        .into();
    let mut images = Vec::new();
    let mut loaded_paths = Vec::<String>::new();
    let mut next_slot = 0_usize;
    while let Some(name) = pending.pop_front() {
        let host_path = resolve_library_path(rootfs, &name)?;
        let identity = host_path.to_string_lossy().into_owned();
        if loaded_paths.contains(&identity) {
            continue;
        }
        if images.len() >= MAX_LIBRARY_COUNT {
            return Err(ElfError::Unsupported(
                "shared-library count exceeds the supported mapping window",
            ));
        }
        let bytes = fs::read(&host_path)
            .map_err(|error| ElfError::LibraryLoad(format!("{name}: {error}")))?;
        if u16_at(&bytes, 16)? != ET_DYN {
            return Err(ElfError::Unsupported(
                "DT_NEEDED shared-library objects must be ET_DYN",
            ));
        }
        let mut loaded_image = None;
        while next_slot < MAX_LIBRARY_COUNT {
            let base = DYN_LIBRARY_BASE
                .checked_add((next_slot as u32) * DYN_LIBRARY_STRIDE)
                .ok_or(ElfError::Bounds("shared-library load address overflow"))?;
            next_slot += 1;
            if base >= MMAP_BASE {
                break;
            }
            let candidate = load_elf_image(&bytes, base, false, false, false)?;
            let overlaps =
                std::iter::once(main)
                    .chain(images.iter())
                    .any(|existing: &LoadedImage| {
                        candidate.memory.segments.iter().any(|segment| {
                            existing.memory.segments.iter().any(|other| {
                                (segment.start as u64) < other.end()
                                    && (other.start as u64) < segment.end()
                            })
                        })
                    });
            if !overlaps {
                let mapped_bytes = main
                    .memory
                    .allocated_bytes()
                    .checked_add(
                        images
                            .iter()
                            .map(|image: &LoadedImage| image.memory.allocated_bytes())
                            .sum::<usize>(),
                    )
                    .and_then(|value| value.checked_add(candidate.memory.allocated_bytes()))
                    .ok_or(ElfError::Bounds("guest dependency memory size overflow"))?;
                if mapped_bytes > MAX_GUEST_MEMORY_BYTES {
                    return Err(ElfError::Unsupported(
                        "main and dependency images exceed the guest memory limit",
                    ));
                }
                loaded_image = Some(candidate);
                break;
            }
        }
        let loaded_image = loaded_image.ok_or(ElfError::Unsupported(
            "no non-overlapping address range remains for a shared library",
        ))?;
        loaded_paths.push(identity);
        if let Some(dynamic) = &loaded_image.dynamic {
            pending.extend(dynamic.needed.iter().cloned());
        }
        images.push(loaded_image);
    }
    Ok(images)
}

fn resolve_library_path(rootfs: &RootFs, name: &str) -> Result<std::path::PathBuf, ElfError> {
    if name.starts_with('/') {
        return rootfs
            .map_absolute(name)
            .map_err(|error| ElfError::LibraryLoad(format!("{name}: {error}")));
    }
    if name.contains('/') || name == "." || name == ".." || name.as_bytes().contains(&0) {
        return Err(ElfError::Unsupported(
            "relative DT_NEEDED names must be plain shared-library filenames",
        ));
    }
    let mut last_not_found = None;
    for directory in ["/system/lib", "/vendor/lib", "/lib"] {
        let guest_path = format!("{directory}/{name}");
        let host_path = rootfs
            .map_absolute(&guest_path)
            .map_err(|error| ElfError::LibraryLoad(format!("{guest_path}: {error}")))?;
        match fs::metadata(&host_path) {
            Ok(metadata) if metadata.is_file() => return Ok(host_path),
            Ok(_) => {
                return Err(ElfError::LibraryLoad(format!(
                    "{guest_path} is not a regular file"
                )))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                last_not_found = Some(error)
            }
            Err(error) => return Err(ElfError::LibraryLoad(format!("{guest_path}: {error}"))),
        }
    }
    Err(ElfError::LibraryLoad(format!(
        "{name} was not found in /system/lib, /vendor/lib, or /lib{}",
        last_not_found
            .map(|error| format!(": {error}"))
            .unwrap_or_default()
    )))
}

fn build_initial_stack(
    info: InitialStackInfo,
    argv: &[String],
    env: &[String],
) -> Result<(u32, Vec<u8>), ElfError> {
    let mut stack = vec![0_u8; STACK_SIZE];
    let mut cursor = STACK_SIZE;
    let platform_address = place_stack_bytes(&mut stack, &mut cursor, b"v7l\0")?;
    let argv_addresses = place_stack_strings(&mut stack, &mut cursor, argv)?;
    let env_addresses = place_stack_strings(&mut stack, &mut cursor, env)?;

    let mut random = [0_u8; 16];
    std::io::Read::read_exact(
        &mut fs::File::open("/dev/urandom").map_err(|error| {
            ElfError::HostIo(format!("host random source /dev/urandom: {error}"))
        })?,
        &mut random,
    )
    .map_err(|error| ElfError::HostIo(format!("host random source /dev/urandom: {error}")))?;

    cursor &= !15;
    let random_address = place_stack_bytes(&mut stack, &mut cursor, &random)?;
    let argc = u32::try_from(argv_addresses.len())
        .map_err(|_| ElfError::Bounds("guest argument count exceeds 32-bit ABI"))?;
    let mut words = Vec::with_capacity(1 + argv_addresses.len() + env_addresses.len() + 40);
    words.push(argc);
    words.extend_from_slice(&argv_addresses);
    words.push(0); // argv terminator
    words.extend_from_slice(&env_addresses);
    words.push(0); // envp terminator
    for (kind, value) in [
        (AT_PHDR, info.phdr_address),
        (AT_PHENT, info.phent),
        (AT_PHNUM, info.phnum),
        (AT_PAGESZ, PAGE_SIZE),
        (AT_BASE, info.interpreter_base),
        (AT_FLAGS, 0),
        (AT_ENTRY, info.program_entry),
        (AT_UID, info.identity.uid),
        (AT_EUID, info.identity.uid),
        (AT_GID, info.identity.gid),
        (AT_EGID, info.identity.gid),
        (AT_HWCAP, 0),
        (AT_CLKTCK, 100),
        (AT_SECURE, 0),
        (AT_RANDOM, random_address),
        (AT_PLATFORM, platform_address),
        (AT_EXECFN, argv_addresses.first().copied().unwrap_or(0)),
        (AT_NULL, 0),
    ] {
        words.push(kind);
        words.push(value);
    }
    let words_size = words
        .len()
        .checked_mul(4)
        .ok_or(ElfError::Bounds("initial guest stack size overflow"))?;
    let stack_offset = cursor
        .checked_sub(words_size)
        .ok_or(ElfError::Bounds("guest argv/env exceed the stack limit"))?
        & !7;
    let stack_pointer = STACK_BASE + stack_offset as u32;
    for (index, word) in words.into_iter().enumerate() {
        let offset = stack_offset + index * 4;
        stack[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
    }
    Ok((stack_pointer, stack))
}

fn place_stack_bytes(stack: &mut [u8], cursor: &mut usize, bytes: &[u8]) -> Result<u32, ElfError> {
    *cursor = (*cursor)
        .checked_sub(bytes.len())
        .ok_or(ElfError::Bounds("guest argv/env exceed the stack limit"))?;
    stack[*cursor..*cursor + bytes.len()].copy_from_slice(bytes);
    Ok(STACK_BASE + *cursor as u32)
}

fn place_stack_strings(
    stack: &mut [u8],
    cursor: &mut usize,
    strings: &[String],
) -> Result<Vec<u32>, ElfError> {
    let mut addresses = Vec::with_capacity(strings.len());
    for string in strings.iter().rev() {
        if string.as_bytes().contains(&0) {
            return Err(ElfError::Invalid(
                "guest argv/env string contains a NUL byte",
            ));
        }
        let mut bytes = string.as_bytes().to_vec();
        bytes.push(0);
        addresses.push(place_stack_bytes(stack, cursor, &bytes)?);
    }
    addresses.reverse();
    Ok(addresses)
}

fn apply_dynamic_relocations(
    bytes: &[u8],
    dynamic: (usize, usize, u32, usize),
    load_bias: u32,
    segments: &mut [Segment],
) -> Result<(), ElfError> {
    let (file_offset, file_size, _, _) = dynamic;
    if file_size % 8 != 0 {
        return Err(ElfError::Invalid(
            "PT_DYNAMIC size is not a whole number of entries",
        ));
    }
    let dynamic_bytes = bytes
        .get(file_offset..file_offset + file_size)
        .ok_or(ElfError::Bounds("PT_DYNAMIC exceeds file size"))?;
    let mut rel_address = None;
    let mut rel_size = None;
    let mut rel_entry_size = None;
    let mut rela_size = 0_u32;
    let mut plt_rel_size = 0_u32;
    let mut terminated = false;
    for entry in dynamic_bytes.chunks_exact(8) {
        let tag = u32::from_le_bytes(entry[..4].try_into().unwrap());
        let value = u32::from_le_bytes(entry[4..].try_into().unwrap());
        if tag == DT_NULL {
            terminated = true;
            break;
        }
        match tag {
            DT_NEEDED => {
                return Err(ElfError::Unsupported(
                    "DT_NEEDED shared-library dependencies require an ELF interpreter",
                ));
            }
            DT_REL => set_dynamic_value(&mut rel_address, value, "duplicate DT_REL")?,
            DT_RELSZ => set_dynamic_value(&mut rel_size, value, "duplicate DT_RELSZ")?,
            DT_RELENT => set_dynamic_value(&mut rel_entry_size, value, "duplicate DT_RELENT")?,
            DT_RELASZ => rela_size = value,
            DT_PLTRELSZ => plt_rel_size = value,
            DT_RELA | DT_JMPREL => {
                if value != 0 {
                    return Err(ElfError::Unsupported(
                        "RELA or PLT relocations require symbol resolution",
                    ));
                }
            }
            0x6000_000f | 0x6000_0010 if value != 0 => {
                return Err(ElfError::Unsupported(
                    "Android packed relocations are not implemented",
                ));
            }
            _ => {}
        }
    }
    if !terminated {
        return Err(ElfError::Invalid("PT_DYNAMIC has no DT_NULL terminator"));
    }
    if rela_size != 0 || plt_rel_size != 0 {
        return Err(ElfError::Unsupported(
            "RELA or PLT relocations require symbol resolution",
        ));
    }
    let rel_size = rel_size.unwrap_or(0) as usize;
    if rel_size == 0 {
        return Ok(());
    }
    let rel_entry_size =
        rel_entry_size.ok_or(ElfError::Invalid("DT_REL is missing DT_RELENT"))? as usize;
    if rel_entry_size != 8 || !rel_size.is_multiple_of(rel_entry_size) || rel_size > MAX_IMAGE_BYTES
    {
        return Err(ElfError::Unsupported(
            "invalid or oversized ARM DT_REL table",
        ));
    }
    let rel_address = rel_address.ok_or(ElfError::Invalid("DT_RELSZ is present without DT_REL"))?;
    let rel_address = rel_address
        .checked_add(load_bias)
        .ok_or(ElfError::Bounds("relocated DT_REL address overflow"))?;
    let relocations = read_image_bytes(segments, rel_address, rel_size)?;
    for relocation in relocations.chunks_exact(8) {
        let offset = u32::from_le_bytes(relocation[..4].try_into().unwrap());
        let info = u32::from_le_bytes(relocation[4..].try_into().unwrap());
        let relocation_type = info & 0xff;
        let symbol = info >> 8;
        match relocation_type {
            R_ARM_NONE => {}
            R_ARM_RELATIVE if symbol == 0 => {
                let target = offset
                    .checked_add(load_bias)
                    .ok_or(ElfError::Bounds("relocated ARM relocation target overflow"))?;
                let addend = read_image_u32(segments, target)?;
                write_image_u32(segments, target, addend.wrapping_add(load_bias))?;
            }
            R_ARM_RELATIVE => {
                return Err(ElfError::Unsupported(
                    "R_ARM_RELATIVE relocation has a non-zero symbol index",
                ));
            }
            _ => {
                return Err(ElfError::Unsupported(
                    "ARM relocation type requires symbol resolution",
                ));
            }
        }
    }
    Ok(())
}

fn insert_resolved_symbol(
    exports: &mut HashMap<String, ResolvedSymbol>,
    name: String,
    symbol: ResolvedSymbol,
) {
    match exports.entry(name) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(symbol);
        }
        std::collections::hash_map::Entry::Occupied(mut entry)
            if entry.get().binding == 2 && symbol.binding == 1 =>
        {
            entry.insert(symbol);
        }
        std::collections::hash_map::Entry::Occupied(_) => {}
    }
}

fn apply_symbol_relocations(images: &mut [LoadedImage]) -> Result<(), ElfError> {
    let mut exports = HashMap::<String, ResolvedSymbol>::new();
    let mut copy_sources = HashMap::<String, ResolvedSymbol>::new();
    for (image_index, image) in images.iter().enumerate() {
        let Some(dynamic) = &image.dynamic else {
            continue;
        };
        let Some(symbol_count) = dynamic.symbol_count else {
            continue;
        };
        for index in 0..symbol_count {
            let symbol = read_dynamic_symbol(image, index)?;
            if symbol.section_index == 0
                || !matches!(symbol.binding, 1 | 2)
                || !matches!(symbol.visibility, 0 | 3)
                || symbol.name.is_empty()
            {
                continue;
            }
            let value = if symbol.section_index == 0xfff1 {
                symbol.value
            } else {
                symbol
                    .value
                    .checked_add(image.load_bias)
                    .ok_or(ElfError::Bounds("dynamic symbol address overflow"))?
            };
            let resolved = ResolvedSymbol {
                value,
                binding: symbol.binding,
                size: symbol.size,
                image_index,
            };
            insert_resolved_symbol(&mut exports, symbol.name.clone(), resolved);
            if image_index != 0 {
                insert_resolved_symbol(&mut copy_sources, symbol.name, resolved);
            }
        }
    }

    for image_index in 0..images.len() {
        let relocations = collect_dynamic_relocations(&images[image_index])?;
        for (target, kind, symbol_index) in relocations {
            if kind == R_ARM_NONE {
                continue;
            }
            if kind == R_ARM_COPY {
                if image_index != 0 {
                    return Err(ElfError::Unsupported(
                        "R_ARM_COPY relocation is only supported in the main executable",
                    ));
                }
                if symbol_index == 0 {
                    return Err(ElfError::Unsupported(
                        "R_ARM_COPY relocation has a zero dynamic symbol index",
                    ));
                }
                let destination = read_dynamic_symbol(&images[image_index], symbol_index as usize)?;
                let source = copy_sources
                    .get(&destination.name)
                    .copied()
                    .ok_or_else(|| ElfError::UnresolvedSymbol(destination.name.clone()))?;
                let copy_size = source.size as usize;
                if copy_size > MAX_IMAGE_BYTES {
                    return Err(ElfError::Unsupported(
                        "R_ARM_COPY symbol exceeds the supported image size",
                    ));
                }
                if copy_size > destination.size as usize {
                    return Err(ElfError::Unsupported(
                        "R_ARM_COPY source is larger than the executable symbol",
                    ));
                }
                let source_bytes = read_image_bytes(
                    &images[source.image_index].memory.segments,
                    source.value,
                    copy_size,
                )?;
                write_image_bytes(
                    &mut images[image_index].memory.segments,
                    target,
                    &source_bytes,
                )?;
                continue;
            }

            let addend = if matches!(kind, R_ARM_RELATIVE | R_ARM_ABS32 | R_ARM_REL32) {
                read_image_u32(&images[image_index].memory.segments, target)?
            } else {
                0
            };
            let symbol = if symbol_index == 0 {
                None
            } else {
                Some(read_dynamic_symbol(
                    &images[image_index],
                    symbol_index as usize,
                )?)
            };
            let symbol_value = match symbol {
                None => 0,
                Some(symbol) if symbol.binding == 0 && symbol.section_index != 0 => {
                    if symbol.section_index == 0xfff1 {
                        symbol.value
                    } else {
                        symbol
                            .value
                            .checked_add(images[image_index].load_bias)
                            .ok_or(ElfError::Bounds("local dynamic symbol address overflow"))?
                    }
                }
                Some(symbol) => match exports.get(&symbol.name) {
                    Some(resolved) => resolved.value,
                    None if symbol.section_index == 0 && symbol.binding == 2 => 0,
                    None if symbol.section_index == 0 => {
                        return Err(ElfError::UnresolvedSymbol(symbol.name));
                    }
                    None if symbol.section_index == 0xfff1 => symbol.value,
                    None => symbol
                        .value
                        .checked_add(images[image_index].load_bias)
                        .ok_or(ElfError::Bounds("dynamic symbol address overflow"))?,
                },
            };
            let value = match kind {
                R_ARM_RELATIVE if symbol_index == 0 => {
                    images[image_index].load_bias.wrapping_add(addend)
                }
                R_ARM_RELATIVE => {
                    return Err(ElfError::Unsupported(
                        "R_ARM_RELATIVE relocation has a non-zero symbol index",
                    ));
                }
                R_ARM_ABS32 => symbol_value.wrapping_add(addend),
                R_ARM_REL32 => symbol_value.wrapping_add(addend).wrapping_sub(target),
                R_ARM_GLOB_DAT | R_ARM_JUMP_SLOT if symbol_index != 0 => symbol_value,
                R_ARM_GLOB_DAT | R_ARM_JUMP_SLOT => {
                    return Err(ElfError::Unsupported(
                        "symbol relocation has a zero dynamic symbol index",
                    ));
                }
                _ => {
                    return Err(ElfError::Unsupported(
                        "ARM relocation type is not implemented by the host loader",
                    ));
                }
            };
            write_image_u32(&mut images[image_index].memory.segments, target, value)?;
        }
    }
    Ok(())
}

fn collect_dynamic_relocations(image: &LoadedImage) -> Result<Vec<(u32, u32, u32)>, ElfError> {
    let Some(dynamic) = &image.dynamic else {
        return Ok(Vec::new());
    };
    let mut relocations = Vec::new();
    for (raw_address, size) in [dynamic.rel, dynamic.plt_rel].into_iter().flatten() {
        if size == 0 {
            continue;
        }
        let address = raw_address
            .checked_add(image.load_bias)
            .ok_or(ElfError::Bounds(
                "relocated ARM relocation table address overflow",
            ))?;
        let bytes = read_image_bytes(&image.memory.segments, address, size)?;
        for relocation in bytes.chunks_exact(8) {
            let offset = u32::from_le_bytes(relocation[..4].try_into().unwrap());
            let info = u32::from_le_bytes(relocation[4..].try_into().unwrap());
            let target = offset
                .checked_add(image.load_bias)
                .ok_or(ElfError::Bounds("relocated ARM relocation target overflow"))?;
            relocations.push((target, info & 0xff, info >> 8));
        }
    }
    Ok(relocations)
}

fn read_dynamic_symbol(image: &LoadedImage, index: usize) -> Result<DynamicSymbol, ElfError> {
    let dynamic = image
        .dynamic
        .as_ref()
        .ok_or(ElfError::Invalid("symbol relocation has no PT_DYNAMIC"))?;
    let count = dynamic.symbol_count.ok_or(ElfError::Unsupported(
        "symbol relocations require a bounded SysV DT_HASH table",
    ))?;
    if index >= count {
        return Err(ElfError::Bounds(
            "dynamic symbol index exceeds DT_HASH count",
        ));
    }
    if dynamic.syment != Some(16) {
        return Err(ElfError::Unsupported("ARM DT_SYMENT is not 16 bytes"));
    }
    let table = dynamic
        .symtab
        .ok_or(ElfError::Invalid("symbol relocation is missing DT_SYMTAB"))?
        .checked_add(image.load_bias)
        .ok_or(ElfError::Bounds("relocated DT_SYMTAB address overflow"))?;
    let offset = index
        .checked_mul(16)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(ElfError::Bounds("dynamic symbol table offset overflow"))?;
    let address = table
        .checked_add(offset)
        .ok_or(ElfError::Bounds("dynamic symbol address overflow"))?;
    let bytes = read_image_bytes(&image.memory.segments, address, 16)?;
    let name_offset = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let value = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let size = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let binding = bytes[12] >> 4;
    let visibility = bytes[13] & 3;
    let section_index = u16::from_le_bytes(bytes[14..16].try_into().unwrap());
    let name = if name_offset == 0 {
        String::new()
    } else {
        let table_size = dynamic
            .strsz
            .ok_or(ElfError::Invalid("dynamic symbols are missing DT_STRSZ"))?;
        let string_table = dynamic
            .strtab
            .ok_or(ElfError::Invalid("dynamic symbols are missing DT_STRTAB"))?
            .checked_add(image.load_bias)
            .ok_or(ElfError::Bounds("relocated DT_STRTAB address overflow"))?;
        read_dynamic_string(
            &image.memory.segments,
            string_table,
            table_size,
            name_offset,
        )?
    };
    Ok(DynamicSymbol {
        name,
        value,
        size,
        binding,
        visibility,
        section_index,
    })
}

fn set_dynamic_value(
    target: &mut Option<u32>,
    value: u32,
    duplicate_message: &'static str,
) -> Result<(), ElfError> {
    if target.replace(value).is_some() {
        return Err(ElfError::Invalid(duplicate_message));
    }
    Ok(())
}

fn read_image_bytes(
    segments: &[Segment],
    address: u32,
    length: usize,
) -> Result<Vec<u8>, ElfError> {
    if length == 0 {
        return Ok(Vec::new());
    }
    let end = checked_memory_end(address, length, "read")?;
    let mut current = address as u64;
    let mut bytes = Vec::with_capacity(length);
    while current < end {
        let segment = segments
            .iter()
            .find(|segment| current >= segment.start as u64 && current < segment.end())
            .ok_or(ElfError::Bounds("dynamic data is outside PT_LOAD segments"))?;
        let count = (end.min(segment.end()) - current) as usize;
        let offset = (current - segment.start as u64) as usize;
        bytes.extend_from_slice(&segment.bytes[offset..offset + count]);
        current += count as u64;
    }
    Ok(bytes)
}

fn read_image_u32(segments: &[Segment], address: u32) -> Result<u32, ElfError> {
    let bytes = read_image_bytes(segments, address, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn write_image_u32(segments: &mut [Segment], address: u32, value: u32) -> Result<(), ElfError> {
    let end = address as u64 + 4;
    let segment = segments
        .iter_mut()
        .find(|segment| address >= segment.start && end <= segment.end())
        .ok_or(ElfError::Bounds(
            "ARM relocation target is outside PT_LOAD segments",
        ))?;
    let offset = (address - segment.start) as usize;
    segment.bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn write_image_bytes(segments: &mut [Segment], address: u32, bytes: &[u8]) -> Result<(), ElfError> {
    if bytes.is_empty() {
        return Ok(());
    }
    let end = checked_memory_end(address, bytes.len(), "write")?;
    let mut check_current = address as u64;
    while check_current < end {
        let segment = segments
            .iter()
            .find(|segment| check_current >= segment.start as u64 && check_current < segment.end())
            .ok_or(ElfError::Bounds(
                "ARM relocation target is outside PT_LOAD segments",
            ))?;
        check_current = end.min(segment.end());
    }
    let mut current = address as u64;
    let mut source_offset = 0;
    while current < end {
        let segment = segments
            .iter_mut()
            .find(|segment| current >= segment.start as u64 && current < segment.end())
            .ok_or(ElfError::Bounds(
                "ARM relocation target is outside PT_LOAD segments",
            ))?;
        let count = (end.min(segment.end()) - current) as usize;
        let offset = (current - segment.start as u64) as usize;
        segment.bytes[offset..offset + count]
            .copy_from_slice(&bytes[source_offset..source_offset + count]);
        current += count as u64;
        source_offset += count;
    }
    Ok(())
}

/// Load and execute one ELF32 ARM guest under a small ARMv7/Thumb interpreter.
/// ET_EXEC and self-relocating ET_DYN images are supported; PT_INTERP images map
/// the named guest linker, resolve a restricted rootfs DT_NEEDED graph and ARM
/// REL relocation subset, then begin at the linker entry with an initial stack.
/// EABI `svc #0` calls are routed only through the supplied broker or local VM.
///
/// This is a host-side compatibility prototype, not a general ARM emulator,
/// Linux kernel, Android runtime, or security boundary. Unsupported guest
/// instructions stop execution explicitly. This host-side dependency resolver is
/// not Bionic: it supports SysV DT_HASH plus R_ARM_RELATIVE, R_ARM_ABS32,
/// R_ARM_REL32, R_ARM_COPY, R_ARM_GLOB_DAT, and R_ARM_JUMP_SLOT for bounded test
/// images. Real Bionic execution remains limited by the ARM instruction and
/// syscall subsets; GNU hash, Android packed relocations, VFP/NEON, MMU, signals,
/// threads, and Android framework services are outside this runner's scope.
pub fn run_elf(
    image: &[u8],
    broker: &mut SyscallBroker,
    max_steps: u64,
) -> Result<ElfExecutionReport, ElfError> {
    run_elf_with_args(image, broker, max_steps, &[], &[])
}

/// Execute an ARM ELF with an explicit guest argument vector and environment.
/// The strings are copied into the guest stack and are never interpreted by the
/// host shell or forwarded to a host process.
pub fn run_elf_with_args(
    image: &[u8],
    broker: &mut SyscallBroker,
    max_steps: u64,
    argv: &[String],
    env: &[String],
) -> Result<ElfExecutionReport, ElfError> {
    run_elf_mode(
        image,
        broker,
        max_steps,
        argv,
        env,
        DependencyLoading::HostCompatibility,
    )
}

/// Execute a PT_INTERP ELF without preloading or relocating DT_NEEDED on the
/// host. The guest interpreter receives the original main image and must load
/// its dependencies through guest syscalls.
pub fn run_elf_with_interpreter(
    image: &[u8],
    broker: &mut SyscallBroker,
    max_steps: u64,
    argv: &[String],
    env: &[String],
) -> Result<ElfExecutionReport, ElfError> {
    run_elf_mode(
        image,
        broker,
        max_steps,
        argv,
        env,
        DependencyLoading::GuestInterpreter,
    )
}

fn run_elf_mode(
    image: &[u8],
    broker: &mut SyscallBroker,
    max_steps: u64,
    argv: &[String],
    env: &[String],
    dependency_loading: DependencyLoading,
) -> Result<ElfExecutionReport, ElfError> {
    let loaded = load_elf(
        image,
        broker.rootfs(),
        broker.identity(),
        argv,
        env,
        dependency_loading,
    )?;
    let mut cpu = Cpu {
        regs: [0; 16],
        pc: loaded.entry,
        thumb: loaded.instruction_set == InstructionSet::Thumb,
        n: false,
        z: false,
        c: false,
        v: false,
        it_state: 0,
        thread_pointer: 0,
        file_creation_mask: 0o022,
        vfp_double_registers: [0; 16],
        virtual_time_ns: 0,
        waiting_for_events: false,
        exclusive_monitor: None,
        signal_actions: [LegacySignalAction::default(); GINGERBREAD_SIGNAL_COUNT + 1],
        memory: loaded.memory,
        brk_base: loaded.brk_base,
        program_break: loaded.brk_base,
        events: Vec::new(),
        syscall_trace: Vec::new(),
        instructions: 0,
        recent_instructions: VecDeque::with_capacity(16),
    };
    cpu.regs[13] = loaded.stack_pointer;

    let (exit_code, stop_reason) = loop {
        if cpu.waiting_for_events {
            break (0, ElfStopReason::WaitingForEvents);
        }
        if cpu.instructions >= max_steps {
            return Err(ElfError::StepLimit { limit: max_steps });
        }
        cpu.instructions += 1;
        let instruction_pc = cpu.pc;
        let instruction_set = if cpu.thumb {
            InstructionSet::Thumb
        } else {
            InstructionSet::Arm
        };
        let (trace_entry, instruction) = cpu.instruction_trace_entry(instruction_pc);
        cpu.recent_instructions.push_back(trace_entry);
        if cpu.recent_instructions.len() > 16 {
            cpu.recent_instructions.pop_front();
        }
        let mut registers = cpu.regs;
        registers[15] = instruction_pc.wrapping_add(if cpu.thumb { 4 } else { 8 });
        let cpsr_nzcv =
            ((cpu.n as u8) << 3) | ((cpu.z as u8) << 2) | ((cpu.c as u8) << 1) | (cpu.v as u8);
        let step_result = if cpu.thumb {
            cpu.step_thumb(broker, instruction_pc)
        } else {
            cpu.step_arm(broker, instruction_pc)
        };
        let flow = match step_result {
            Ok(flow) => flow,
            Err(ElfError::MemoryAccess { address, access }) => {
                return Err(ElfError::CpuMemoryFault {
                    address,
                    access,
                    pc: instruction_pc,
                    instruction,
                    instruction_set,
                    registers,
                    cpsr_nzcv,
                    instructions: cpu.instructions,
                    trace: cpu
                        .recent_instructions
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
                });
            }
            Err(error) => return Err(error),
        };
        if let Some(status) = flow {
            break (status, ElfStopReason::GuestExited);
        }
    };

    Ok(ElfExecutionReport {
        entry: loaded.entry,
        instruction_set: loaded.instruction_set,
        instructions_executed: cpu.instructions,
        exit_code,
        stop_reason,
        events: cpu.events,
        syscall_trace: cpu.syscall_trace,
    })
}

struct Cpu {
    regs: [u32; 16],
    pc: u32,
    thumb: bool,
    n: bool,
    z: bool,
    c: bool,
    v: bool,
    /// Architectural Thumb ITSTATE; zero means no active If-Then block.
    it_state: u8,
    /// User-visible thread pointer read by Bionic through CP15 TPIDRURO.
    thread_pointer: u32,
    /// Guest-local umask; never changes the host process umask.
    file_creation_mask: u32,
    /// VFPv3-D16 state for the supported double-register stack transfers.
    vfp_double_registers: [u64; 16],
    /// Deterministic monotonic time; nanosleep advances guest time without host sleeping.
    virtual_time_ns: u64,
    /// A headless guest blocked indefinitely with no virtual fd ready to wake it.
    waiting_for_events: bool,
    /// ARM local exclusive monitor for this single-threaded guest CPU.
    exclusive_monitor: Option<u32>,
    /// Registered legacy ARM signal actions; no signal delivery is implemented.
    signal_actions: [LegacySignalAction; GINGERBREAD_SIGNAL_COUNT + 1],
    memory: GuestMemory,
    brk_base: u32,
    program_break: u32,
    events: Vec<ElfSyscallEvent>,
    syscall_trace: Vec<ElfSyscallTrace>,
    instructions: u64,
    recent_instructions: VecDeque<String>,
}

impl Cpu {
    fn instruction_trace_entry(&self, instruction_pc: u32) -> (String, Option<u32>) {
        let instruction_set = if self.thumb {
            InstructionSet::Thumb
        } else {
            InstructionSet::Arm
        };
        let byte_count = if self.thumb { 2 } else { 4 };
        let instruction = self
            .memory
            .fetch(instruction_pc, byte_count)
            .ok()
            .map(|bytes| match byte_count {
                2 => u16::from_le_bytes([bytes[0], bytes[1]]) as u32,
                _ => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            });
        let encoding = match instruction {
            Some(word) if self.thumb => format!("0x{word:04x}"),
            Some(word) => format!("0x{word:08x}"),
            None => "unavailable".to_owned(),
        };
        (
            format!(
                "#{:>6} {instruction_set} pc=0x{instruction_pc:08x} instruction={encoding}",
                self.instructions
            ),
            instruction,
        )
    }

    fn thumb_expand_modified_immediate(imm12: u16) -> Option<u32> {
        let imm8 = (imm12 & 0x00ff) as u32;
        if imm12 & 0x0c00 == 0 {
            if imm8 == 0 {
                return None;
            }
            return Some(match (imm12 >> 8) & 3 {
                0 => imm8,
                1 => (imm8 << 16) | imm8,
                2 => (imm8 << 24) | (imm8 << 8),
                3 => imm8.wrapping_mul(0x0101_0101),
                _ => unreachable!(),
            });
        }

        let unrotated = 0x80 | (imm12 as u32 & 0x7f);
        let rotation = ((imm12 >> 7) & 0x1f) as u32;
        Some(unrotated.rotate_right(rotation))
    }

    fn step_thumb(
        &mut self,
        broker: &mut SyscallBroker,
        instruction_pc: u32,
    ) -> Result<Option<i32>, ElfError> {
        let bytes = self.memory.fetch(instruction_pc, 2)?;
        let instruction = u16::from_le_bytes([bytes[0], bytes[1]]);
        self.pc = instruction_pc.wrapping_add(2);
        self.regs[15] = instruction_pc.wrapping_add(4);

        let in_it_block = self.it_state != 0;
        if in_it_block {
            let condition = self.it_state >> 4;
            self.advance_it_state();
            if !self.condition_passed(condition) {
                if matches!(instruction & 0xf800, 0xe800 | 0xf000 | 0xf800) {
                    self.pc = instruction_pc.wrapping_add(4);
                }
                return Ok(None);
            }
        }

        // Thumb IT (If-Then) block; decode its condition and mask into ITSTATE.
        if instruction & 0xff00 == 0xbf00 && instruction & 0x000f != 0 {
            let condition = ((instruction >> 4) & 0xf) as u8;
            if in_it_block || condition >= 0xe {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }
            self.it_state = instruction as u8;
            return Ok(None);
        }

        // Thumb-2 PUSH.W {registers}: the STMDB sp!, register-list encoding.
        // Keep this bounded to the exact form observed in the Gingerbread linker.
        if instruction == 0xe92d {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let register_list = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let forbidden_registers = (1_u16 << 13) | (1_u16 << 15);
            if register_list == 0 || register_list & forbidden_registers != 0 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let byte_count = register_list.count_ones() * 4;
            let new_stack_pointer = self.regs[13].wrapping_sub(byte_count);
            let mut stack_bytes = Vec::with_capacity(byte_count as usize);
            for register in 0..15 {
                if register_list & (1_u16 << register) != 0 {
                    stack_bytes.extend_from_slice(&self.regs[register].to_le_bytes());
                }
            }
            self.memory
                .check_write(new_stack_pointer, stack_bytes.len())?;
            self.memory.write(new_stack_pointer, &stack_bytes)?;
            self.regs[13] = new_stack_pointer;
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 LDR (literal), with an aligned architectural PC base.
        if instruction & 0xff7f == 0xf85f {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let destination = ((second >> 12) & 0xf) as usize;
            if matches!(destination, 13 | 15) {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let immediate = (second & 0x0fff) as u32;
            let pc_base = instruction_pc.wrapping_add(4) & !3;
            let address = if instruction & 0x0080 != 0 {
                pc_base.wrapping_add(immediate)
            } else {
                pc_base.wrapping_sub(immediate)
            };
            self.regs[destination] = self.read_u32(address)?;
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 LDRB (register): [Rn, Rm, LSL #imm2].
        if instruction & 0xfff0 == 0xf810 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let destination = ((second >> 12) & 0xf) as usize;
            let rn = (instruction & 0xf) as usize;
            let shift = ((second >> 4) & 3) as u32;
            let rm = (second & 0xf) as usize;
            if second & 0x0fc0 != 0
                || destination == 13
                || destination == 15
                || rn == 15
                || rm == 15
            {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let address = self.regs[rn].wrapping_add(self.regs[rm].wrapping_shl(shift));
            self.regs[destination] = self.memory.read(address, 1)?[0] as u32;
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 LDR (word, positive imm12): the form observed in the linker.
        if instruction & 0xfff0 == 0xf8d0 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let destination = ((second >> 12) & 0xf) as usize;
            let rn = (instruction & 0xf) as usize;
            if destination == 13 || destination == 15 || rn == 15 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let address = self.regs[rn].wrapping_add((second & 0x0fff) as u32);
            self.regs[destination] = self.read_u32(address)?;
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 LDR (immediate), positive post-index with writeback.
        if instruction & 0xfff0 == 0xf850 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            if second & 0x0f00 == 0x0b00 {
                let destination = ((second >> 12) & 0xf) as usize;
                let rn = (instruction & 0xf) as usize;
                let immediate = (second & 0x00ff) as u32;
                if destination == 13 || destination == 15 || rn == 15 || destination == rn {
                    return Err(ElfError::InvalidInstruction {
                        pc: instruction_pc,
                        instruction: instruction as u32,
                        thumb: true,
                    });
                }

                let base = self.regs[rn];
                let value = self.read_u32(base)?;
                self.regs[rn] = base.wrapping_add(immediate);
                self.regs[destination] = value;
                self.pc = instruction_pc.wrapping_add(4);
                return Ok(None);
            }
        }

        // Thumb-2 LDR (register): [Rn, Rm, LSL #imm2].
        if instruction & 0xfff0 == 0xf850 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let destination = ((second >> 12) & 0xf) as usize;
            let rn = (instruction & 0xf) as usize;
            let shift = ((second >> 4) & 3) as u32;
            let rm = (second & 0xf) as usize;
            if second & 0x0fc0 != 0
                || destination == 13
                || destination == 15
                || rn == 15
                || rm == 15
            {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let offset = self.regs[rm].wrapping_shl(shift);
            let address = self.regs[rn].wrapping_add(offset);
            self.regs[destination] = self.read_u32(address)?;
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 STR (register): [Rn, Rm, LSL #imm2].
        if instruction & 0xfff0 == 0xf840 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let source = ((second >> 12) & 0xf) as usize;
            let rn = (instruction & 0xf) as usize;
            let shift = ((second >> 4) & 3) as u32;
            let rm = (second & 0xf) as usize;
            if second & 0x0fc0 != 0 || source == 13 || source == 15 || rn == 15 || rm == 15 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let offset = self.regs[rm].wrapping_shl(shift);
            let address = self.regs[rn].wrapping_add(offset);
            self.memory
                .write(address, &self.regs[source].to_le_bytes())?;
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 STRB (positive imm12), used by the API 10 linker.
        if instruction & 0xfff0 == 0xf880 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let source = ((second >> 12) & 0xf) as usize;
            let rn = (instruction & 0xf) as usize;
            if source == 13 || source == 15 || rn == 15 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let address = self.regs[rn].wrapping_add((second & 0x0fff) as u32);
            self.memory.write(address, &[self.regs[source] as u8])?;
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 STR (word, positive imm12): the form observed in the linker.
        if instruction & 0xfff0 == 0xf8c0 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let source = ((second >> 12) & 0xf) as usize;
            let rn = (instruction & 0xf) as usize;
            if source == 13 || source == 15 || rn == 15 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let address = self.regs[rn].wrapping_add((second & 0x0fff) as u32);
            self.memory
                .write(address, &self.regs[source].to_le_bytes())?;
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 MOVW (T3); the linker uses it to materialize 16-bit constants.
        if instruction & 0xfbf0 == 0xf240 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let destination = ((second >> 8) & 0xf) as usize;
            if second & 0x8000 != 0 || destination == 13 || destination == 15 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let immediate = (((instruction as u32) & 0xf) << 12)
                | ((((instruction as u32) >> 10) & 1) << 11)
                | ((((second as u32) >> 12) & 7) << 8)
                | (second as u32 & 0xff);
            self.regs[destination] = immediate;
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 MOV (modified immediate), restricted to the unflagged form.
        if instruction & 0xfbff == 0xf04f {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let destination = ((second >> 8) & 0xf) as usize;
            let imm12 =
                (((instruction >> 10) & 1) << 11) | (((second >> 12) & 7) << 8) | (second & 0x00ff);
            let immediate = if imm12 == 0 {
                0 // MOV.W Rd, #0 is valid and used by the API 10 linker.
            } else if let Some(value) = Self::thumb_expand_modified_immediate(imm12) {
                value
            } else {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            };
            if second & 0x8000 != 0 || destination == 13 || destination == 15 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            self.regs[destination] = immediate;
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 LSL/LSLS (register), restricted to non-PC register operands.
        if instruction & 0xffe0 == 0xfa00 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let destination = ((second >> 8) & 0xf) as usize;
            let rn = (instruction & 0xf) as usize;
            let rm = (second & 0xf) as usize;
            let set_flags = instruction & 0x0010 != 0;
            if second & 0xf0f0 != 0xf000
                || destination == 13
                || destination == 15
                || rn == 15
                || rm == 15
            {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let value = self.regs[rn];
            let amount = self.regs[rm] & 0xff;
            let (result, carry) = match amount {
                0 => (value, None),
                1..=31 => (value << amount, Some(value >> (32 - amount) & 1 != 0)),
                32 => (0, Some(value & 1 != 0)),
                _ => (0, Some(false)),
            };
            if set_flags {
                self.set_nz(result);
                if let Some(carry) = carry {
                    self.c = carry;
                }
            }
            self.regs[destination] = result;
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 LSR/LSRS (register), restricted to non-PC register operands.
        if instruction & 0xffe0 == 0xfa20 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let destination = ((second >> 8) & 0xf) as usize;
            let rn = (instruction & 0xf) as usize;
            let rm = (second & 0xf) as usize;
            let set_flags = instruction & 0x0010 != 0;
            if second & 0xf0f0 != 0xf000
                || destination == 13
                || destination == 15
                || rn == 15
                || rm == 15
            {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let value = self.regs[rn];
            let amount = self.regs[rm] & 0xff;
            let (result, carry) = match amount {
                0 => (value, None),
                1..=31 => (value >> amount, Some(value >> (amount - 1) & 1 != 0)),
                32 => (0, Some(value >> 31 != 0)),
                _ => (0, Some(false)),
            };
            if set_flags {
                self.set_nz(result);
                if let Some(carry) = carry {
                    self.c = carry;
                }
            }
            self.regs[destination] = result;
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 ADD (shifted register), limited to the unflagged LSL form.
        if instruction & 0xfff0 == 0xeb00 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let destination = ((second >> 8) & 0xf) as usize;
            let rn = (instruction & 0xf) as usize;
            let shift_type = (second >> 4) & 3;
            let shift = ((((second >> 12) & 7) << 2) | ((second >> 6) & 3)) as u32;
            let rm = (second & 0xf) as usize;
            if second & 0x8000 != 0
                || shift_type != 0
                || destination == 13
                || destination == 15
                || rn == 15
                || rm == 15
            {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            self.regs[destination] = self.regs[rn].wrapping_add(self.regs[rm].wrapping_shl(shift));
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 ADD/ADDS (modified immediate), without PC writes.
        if instruction & 0xfbe0 == 0xf100 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let destination = ((second >> 8) & 0xf) as usize;
            let rn = (instruction & 0xf) as usize;
            let set_flags = instruction & 0x0010 != 0;
            let imm12 =
                (((instruction >> 10) & 1) << 11) | (((second >> 12) & 7) << 8) | (second & 0x00ff);
            let Some(immediate) = Self::thumb_expand_modified_immediate(imm12) else {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            };
            if second & 0x8000 != 0 || destination == 13 || destination == 15 || rn == 15 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let left = self.regs[rn];
            self.regs[destination] = if set_flags {
                self.add_with_flags(left, immediate, false)
            } else {
                left.wrapping_add(immediate)
            };
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 RSB/RSBS (modified immediate), with no PC or SP destinations.
        if instruction & 0xfbe0 == 0xf1c0 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let destination = ((second >> 8) & 0xf) as usize;
            let rn = (instruction & 0xf) as usize;
            let set_flags = instruction & 0x0010 != 0;
            let imm12 =
                (((instruction >> 10) & 1) << 11) | (((second >> 12) & 7) << 8) | (second & 0x00ff);
            let Some(immediate) = Self::thumb_expand_modified_immediate(imm12) else {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            };
            if second & 0x8000 != 0 || destination == 13 || destination == 15 || rn == 15 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let right = self.regs[rn];
            self.regs[destination] = if set_flags {
                self.sub_with_flags(immediate, right, true)
            } else {
                immediate.wrapping_sub(right)
            };
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 SUB/SUBS (modified immediate); Rd=PC with S is CMP.
        if instruction & 0xfbe0 == 0xf1a0 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let destination = ((second >> 8) & 0xf) as usize;
            let rn = (instruction & 0xf) as usize;
            let set_flags = instruction & 0x0010 != 0;
            let imm12 =
                (((instruction >> 10) & 1) << 11) | (((second >> 12) & 7) << 8) | (second & 0x00ff);
            let Some(immediate) = Self::thumb_expand_modified_immediate(imm12) else {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            };
            let compare = destination == 15 && set_flags;
            let stack_adjust = destination == 13 && rn == 13 && !set_flags;
            if second & 0x8000 != 0
                || (destination == 13 && !stack_adjust)
                || (destination == 15 && !set_flags)
                || rn == 15
            {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let left = self.regs[rn];
            let result = if set_flags {
                self.sub_with_flags(left, immediate, true)
            } else {
                left.wrapping_sub(immediate)
            };
            if !compare {
                self.regs[destination] = result;
            }
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 AND (modified immediate), restricted to unflagged non-PC forms.
        if instruction & 0xfbf0 == 0xf000 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            // F000 also prefixes wide branches; their second halfword has bit 15 set.
            if second & 0x8000 == 0 {
                let destination = ((second >> 8) & 0xf) as usize;
                let rn = (instruction & 0xf) as usize;
                let imm12 = (((instruction >> 10) & 1) << 11)
                    | (((second >> 12) & 7) << 8)
                    | (second & 0x00ff);
                let Some(immediate) = Self::thumb_expand_modified_immediate(imm12) else {
                    return Err(ElfError::InvalidInstruction {
                        pc: instruction_pc,
                        instruction: instruction as u32,
                        thumb: true,
                    });
                };
                if destination == 13 || destination == 15 || rn == 15 {
                    return Err(ElfError::InvalidInstruction {
                        pc: instruction_pc,
                        instruction: instruction as u32,
                        thumb: true,
                    });
                }

                self.regs[destination] = self.regs[rn] & immediate;
                self.pc = instruction_pc.wrapping_add(4);
                return Ok(None);
            }
        }

        // Thumb-2 ORR (modified immediate), restricted to unflagged non-PC forms.
        if instruction & 0xfbf0 == 0xf040 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            // F040 also prefixes wide branches; bit 15 set means defer to the branch decoder.
            if second & 0x8000 == 0 {
                let destination = ((second >> 8) & 0xf) as usize;
                let rn = (instruction & 0xf) as usize;
                let imm12 = (((instruction >> 10) & 1) << 11)
                    | (((second >> 12) & 7) << 8)
                    | (second & 0x00ff);
                let Some(immediate) = Self::thumb_expand_modified_immediate(imm12) else {
                    return Err(ElfError::InvalidInstruction {
                        pc: instruction_pc,
                        instruction: instruction as u32,
                        thumb: true,
                    });
                };
                if destination == 13 || destination == 15 || rn == 15 {
                    return Err(ElfError::InvalidInstruction {
                        pc: instruction_pc,
                        instruction: instruction as u32,
                        thumb: true,
                    });
                }

                self.regs[destination] = self.regs[rn] | immediate;
                self.pc = instruction_pc.wrapping_add(4);
                return Ok(None);
            }
        }

        // Thumb-2 BIC (modified immediate), restricted to unflagged non-PC forms.
        if instruction & 0xfbf0 == 0xf020 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            // F020 also prefixes wide branches; let the branch decoder own their suffixes.
            if second & 0x8000 == 0 {
                let destination = ((second >> 8) & 0xf) as usize;
                let rn = (instruction & 0xf) as usize;
                let imm12 = (((instruction >> 10) & 1) << 11)
                    | (((second >> 12) & 7) << 8)
                    | (second & 0x00ff);
                let Some(immediate) = Self::thumb_expand_modified_immediate(imm12) else {
                    return Err(ElfError::InvalidInstruction {
                        pc: instruction_pc,
                        instruction: instruction as u32,
                        thumb: true,
                    });
                };
                if destination == 13 || destination == 15 || rn == 15 {
                    return Err(ElfError::InvalidInstruction {
                        pc: instruction_pc,
                        instruction: instruction as u32,
                        thumb: true,
                    });
                }

                self.regs[destination] = self.regs[rn] & !immediate;
                self.pc = instruction_pc.wrapping_add(4);
                return Ok(None);
            }
        }

        // Thumb-2 BFI/BFC and UBFX, limited to the observed non-PC destination forms.
        let bitfield_class = instruction & 0xfff0;
        if bitfield_class == 0xf360 || bitfield_class == 0xf3c0 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let destination = ((second >> 8) & 0xf) as usize;
            let rn = (instruction & 0xf) as usize;
            let lsb = (((second >> 12) & 7) as u32) << 2 | ((second >> 6) & 3) as u32;
            let encoded_msb_or_width = (second & 0x1f) as u32;
            let is_insert = bitfield_class == 0xf360;
            let range_valid = if is_insert {
                lsb <= encoded_msb_or_width
            } else {
                lsb + encoded_msb_or_width + 1 <= 32
            };
            if second & 0x8020 != 0
                || destination == 13
                || destination == 15
                || rn == 13
                || (!is_insert && rn == 15)
                || !range_valid
            {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let width = if is_insert {
                encoded_msb_or_width - lsb + 1
            } else {
                encoded_msb_or_width + 1
            };
            let width_mask = if width == 32 {
                u32::MAX
            } else {
                (1_u32 << width) - 1
            };
            if is_insert {
                let field_mask = width_mask << lsb;
                let source_value = if rn == 15 { 0 } else { self.regs[rn] };
                self.regs[destination] =
                    (self.regs[destination] & !field_mask) | ((source_value << lsb) & field_mask);
            } else {
                self.regs[destination] = (self.regs[rn] >> lsb) & width_mask;
            }
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 MLA used by Gingerbread's linker; keep MLS and MUL aliases unsupported.
        if instruction & 0xfff0 == 0xfb00 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let accumulator = ((second >> 12) & 0xf) as usize;
            let destination = ((second >> 8) & 0xf) as usize;
            let rn = (instruction & 0xf) as usize;
            let rm = (second & 0xf) as usize;
            if second & 0x00f0 != 0
                || destination == 13
                || destination == 15
                || accumulator == 13
                || accumulator == 15
                || rn == 13
                || rn == 15
                || rm == 13
                || rm == 15
            {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }
            self.regs[destination] = self.regs[rn]
                .wrapping_mul(self.regs[rm])
                .wrapping_add(self.regs[accumulator]);
            self.pc = instruction_pc.wrapping_add(4);
            return Ok(None);
        }

        // Thumb-2 TBB [PC, Rm], limited to the aligned PC-relative linker form.
        if instruction & 0xfff0 == 0xe8d0 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            let rn = (instruction & 0xf) as usize;
            let rm = (second & 0xf) as usize;
            if instruction_pc & 3 != 0
                || rn != 15
                || second & 0xfff0 != 0xf000
                || rm == 13
                || rm == 15
            {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }

            let table_base = instruction_pc.wrapping_add(4);
            let table_address = table_base.wrapping_add(self.regs[rm]);
            let branch_offset = self.memory.read(table_address, 1)?[0] as u32;
            self.pc = table_base.wrapping_add(branch_offset.wrapping_mul(2));
            self.regs[15] = self.pc;
            return Ok(None);
        }

        // Thumb-2 BL/BLX and conditional B.W branches; unconditional B.W remains unsupported.
        if instruction & 0xf800 == 0xf000 {
            let second_bytes = self.memory.fetch(instruction_pc.wrapping_add(2), 2)?;
            let second = u16::from_le_bytes([second_bytes[0], second_bytes[1]]);
            if second & 0xf800 == 0xf800 {
                let high_offset = sign_extend((instruction & 0x07ff) as u32, 11) << 12;
                let low_offset = ((second & 0x07ff) as u32) << 1;
                let target = instruction_pc
                    .wrapping_add(4)
                    .wrapping_add(high_offset as u32)
                    .wrapping_add(low_offset);
                self.regs[14] = instruction_pc.wrapping_add(4) | 1;
                self.pc = target & !1;
                self.regs[15] = self.pc;
                return Ok(None);
            }

            if second & 0xf800 == 0xe800 && second & 1 == 0 {
                let sign = ((instruction >> 10) & 1) as u32;
                let j1 = ((second >> 13) & 1) as u32;
                let j2 = ((second >> 11) & 1) as u32;
                let i1 = 1 ^ (j1 ^ sign);
                let i2 = 1 ^ (j2 ^ sign);
                let encoded_offset = (sign << 24)
                    | (i1 << 23)
                    | (i2 << 22)
                    | (((instruction & 0x03ff) as u32) << 12)
                    | ((((second >> 1) & 0x03ff) as u32) << 2);
                let offset = sign_extend(encoded_offset, 25);
                let pc_base = instruction_pc.wrapping_add(4) & !3;
                let target = pc_base.wrapping_add(offset as u32) & !3;
                self.regs[14] = instruction_pc.wrapping_add(4) | 1;
                self.thumb = false;
                self.pc = target;
                self.regs[15] = self.pc;
                return Ok(None);
            }

            if second & 0xd000 == 0x8000 {
                let condition = ((instruction >> 6) & 0xf) as u8;
                if condition >= 0xe {
                    return Err(ElfError::InvalidInstruction {
                        pc: instruction_pc,
                        instruction: instruction as u32,
                        thumb: true,
                    });
                }
                let sign = ((instruction >> 10) & 1) as u32;
                let j1 = ((second >> 13) & 1) as u32;
                let j2 = ((second >> 11) & 1) as u32;
                let encoded_offset = (sign << 20)
                    | ((instruction as u32 & 0x003f) << 14)
                    | (j1 << 13)
                    | (j2 << 12)
                    | (((second & 0x07ff) as u32) << 1);
                let offset = sign_extend(encoded_offset, 21);
                let branch_base = instruction_pc.wrapping_add(4);
                self.pc = branch_base;
                self.regs[15] = branch_base;
                if self.condition_passed(condition) {
                    self.pc = branch_base.wrapping_add(offset as u32);
                    self.regs[15] = self.pc;
                }
                return Ok(None);
            }

            return Err(ElfError::InvalidInstruction {
                pc: instruction_pc,
                instruction: instruction as u32,
                thumb: true,
            });
        }
        if instruction & 0xff00 == 0xdf00 {
            return self.handle_svc(broker, instruction_pc);
        }
        if instruction == 0xbf00 {
            return Ok(None);
        }
        // Thumb-1 CBZ/CBNZ: the forward-only immediate is i:imm5:'0'.
        if instruction & 0xf500 == 0xb100 {
            let rn = (instruction & 7) as usize;
            let nonzero = instruction & 0x0800 != 0;
            let take_branch = if nonzero {
                self.regs[rn] != 0
            } else {
                self.regs[rn] == 0
            };
            if take_branch {
                let immediate = (((instruction >> 9) & 1) as u32) << 6
                    | (((instruction >> 3) & 0x1f) as u32) << 1;
                self.pc = instruction_pc.wrapping_add(4).wrapping_add(immediate);
                self.regs[15] = self.pc;
            }
            return Ok(None);
        }
        // Thumb-1 immediate shifts (LSL/LSR/ASR).
        if instruction & 0xe000 == 0 && instruction & 0x1800 != 0x1800 {
            let operation = (instruction >> 11) & 3;
            let amount = ((instruction >> 6) & 0x1f) as u32;
            let rs = ((instruction >> 3) & 7) as usize;
            let rd = (instruction & 7) as usize;
            let value = self.regs[rs];
            let (result, carry) = match operation {
                0 => {
                    if amount == 0 {
                        (value, None)
                    } else {
                        (
                            value.wrapping_shl(amount),
                            Some(value >> (32 - amount) & 1 != 0),
                        )
                    }
                }
                1 => {
                    let amount = if amount == 0 { 32 } else { amount };
                    if amount == 32 {
                        (0, Some(value >> 31 != 0))
                    } else {
                        (value >> amount, Some(value >> (amount - 1) & 1 != 0))
                    }
                }
                2 => {
                    let amount = if amount == 0 { 32 } else { amount };
                    if amount == 32 {
                        let sign = value >> 31 != 0;
                        (if sign { u32::MAX } else { 0 }, Some(sign))
                    } else {
                        (
                            ((value as i32) >> amount) as u32,
                            Some(value >> (amount - 1) & 1 != 0),
                        )
                    }
                }
                _ => unreachable!(),
            };
            self.regs[rd] = result;
            self.set_nz(result);
            if let Some(carry) = carry {
                self.c = carry;
            }
            return Ok(None);
        }
        // Thumb-1 register ALU: all sixteen operations in the low-register group.
        if instruction & 0xfc00 == 0x4000 {
            let operation = (instruction >> 6) & 0xf;
            let rs = ((instruction >> 3) & 7) as usize;
            let rd = (instruction & 7) as usize;
            let left = self.regs[rd];
            let right = self.regs[rs];
            let result = match operation {
                0 => {
                    let result = left & right;
                    self.set_nz(result);
                    result
                }
                1 => {
                    let result = left ^ right;
                    self.set_nz(result);
                    result
                }
                2..=4 | 7 => {
                    let amount = right & 0xff;
                    let (result, carry) = match operation {
                        2 => match amount {
                            0 => (left, None),
                            1..=31 => (left << amount, Some(left >> (32 - amount) & 1 != 0)),
                            32 => (0, Some(left & 1 != 0)),
                            _ => (0, Some(false)),
                        },
                        3 => match amount {
                            0 => (left, None),
                            1..=31 => (left >> amount, Some(left >> (amount - 1) & 1 != 0)),
                            32 => (0, Some(left >> 31 != 0)),
                            _ => (0, Some(false)),
                        },
                        4 => {
                            if amount == 0 {
                                (left, None)
                            } else if amount >= 32 {
                                let sign = left >> 31 != 0;
                                (if sign { u32::MAX } else { 0 }, Some(sign))
                            } else {
                                (
                                    ((left as i32) >> amount) as u32,
                                    Some(left >> (amount - 1) & 1 != 0),
                                )
                            }
                        }
                        _ => {
                            if amount == 0 {
                                (left, None)
                            } else {
                                let rotation = amount & 31;
                                let result = left.rotate_right(rotation);
                                (result, Some(result >> 31 != 0))
                            }
                        }
                    };
                    self.set_nz(result);
                    if let Some(carry) = carry {
                        self.c = carry;
                    }
                    result
                }
                5 => self.add_with_flags(left, right, self.c),
                6 => self.sub_with_flags(left, right, self.c),
                8 => {
                    let result = left & right;
                    self.set_nz(result);
                    return Ok(None);
                }
                9 => self.sub_with_flags(0, right, true),
                10 => {
                    self.sub_with_flags(left, right, true);
                    return Ok(None);
                }
                11 => {
                    self.add_with_flags(left, right, false);
                    return Ok(None);
                }
                12 => {
                    let result = left | right;
                    self.set_nz(result);
                    result
                }
                13 => {
                    let result = left.wrapping_mul(right);
                    self.set_nz(result);
                    result
                }
                14 => {
                    let result = left & !right;
                    self.set_nz(result);
                    result
                }
                15 => {
                    let result = !right;
                    self.set_nz(result);
                    result
                }
                _ => unreachable!(),
            };
            self.regs[rd] = result;
            return Ok(None);
        }
        // Register-offset STR/STRH/STRB/LDRSB/LDR/LDRH/LDRB/LDRSH.
        if instruction & 0xf000 == 0x5000 {
            let operation = (instruction >> 9) & 7;
            let rm = ((instruction >> 6) & 7) as usize;
            let rn = ((instruction >> 3) & 7) as usize;
            let rd = (instruction & 7) as usize;
            let address = self.regs[rn].wrapping_add(self.regs[rm]);
            match operation {
                0 => self.memory.write(address, &self.regs[rd].to_le_bytes())?,
                1 => self
                    .memory
                    .write(address, &(self.regs[rd] as u16).to_le_bytes())?,
                2 => self.memory.write(address, &[self.regs[rd] as u8])?,
                3 => self.regs[rd] = (self.memory.read(address, 1)?[0] as i8 as i32) as u32,
                4 => self.regs[rd] = self.read_u32(address)?,
                5 => self.regs[rd] = self.read_u16(address)? as u32,
                6 => self.regs[rd] = self.memory.read(address, 1)?[0] as u32,
                7 => self.regs[rd] = (self.read_u16(address)? as i16 as i32) as u32,
                _ => unreachable!(),
            }
            return Ok(None);
        }
        // Immediate word/byte transfers use a scaled word offset or byte offset.
        if instruction & 0xe000 == 0x6000 {
            let byte = instruction & (1 << 12) != 0;
            let load = instruction & (1 << 11) != 0;
            let immediate = ((instruction >> 6) & 0x1f) as u32;
            let rn = ((instruction >> 3) & 7) as usize;
            let rd = (instruction & 7) as usize;
            let offset = if byte { immediate } else { immediate << 2 };
            let address = self.regs[rn].wrapping_add(offset);
            if load {
                self.regs[rd] = if byte {
                    self.memory.read(address, 1)?[0] as u32
                } else {
                    self.read_u32(address)?
                };
            } else if byte {
                self.memory.write(address, &[self.regs[rd] as u8])?;
            } else {
                self.memory.write(address, &self.regs[rd].to_le_bytes())?;
            }
            return Ok(None);
        }
        // Immediate halfword transfers and SP-relative word transfers.
        if instruction & 0xf000 == 0x8000 {
            let load = instruction & (1 << 11) != 0;
            let offset = (((instruction >> 6) & 0x1f) as u32) << 1;
            let rn = ((instruction >> 3) & 7) as usize;
            let rd = (instruction & 7) as usize;
            let address = self.regs[rn].wrapping_add(offset);
            if load {
                self.regs[rd] = self.read_u16(address)? as u32;
            } else {
                self.memory
                    .write(address, &(self.regs[rd] as u16).to_le_bytes())?;
            }
            return Ok(None);
        }
        if instruction & 0xf000 == 0x9000 {
            let load = instruction & (1 << 11) != 0;
            let rd = ((instruction >> 8) & 7) as usize;
            let address = self.regs[13].wrapping_add(((instruction & 0xff) as u32) << 2);
            if load {
                self.regs[rd] = self.read_u32(address)?;
            } else {
                self.memory.write(address, &self.regs[rd].to_le_bytes())?;
            }
            return Ok(None);
        }
        // ADR and ADD Rd,SP,#imm.
        if instruction & 0xf000 == 0xa000 {
            let rd = ((instruction >> 8) & 7) as usize;
            let offset = ((instruction & 0xff) as u32) << 2;
            let base = if instruction & (1 << 11) == 0 {
                instruction_pc.wrapping_add(4) & !3
            } else {
                self.regs[13]
            };
            self.regs[rd] = base.wrapping_add(offset);
            return Ok(None);
        }
        // LDMIA/STMIA over the low register bank.
        if instruction & 0xf000 == 0xc000 {
            let load = instruction & (1 << 11) != 0;
            let rn = ((instruction >> 8) & 7) as usize;
            let register_list = instruction & 0xff;
            if register_list == 0 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }
            let count = register_list.count_ones();
            let base = self.regs[rn];
            let mut address = base;
            if load {
                let mut loaded = Vec::with_capacity(count as usize);
                for register in 0..8 {
                    if register_list & (1 << register) != 0 {
                        loaded.push((register, self.read_u32(address)?));
                        address = address.wrapping_add(4);
                    }
                }
                for (register, value) in loaded {
                    self.regs[register] = value;
                }
                if register_list & (1 << rn) == 0 {
                    self.regs[rn] = base.wrapping_add(count * 4);
                }
            } else {
                let mut bytes = Vec::with_capacity(count as usize * 4);
                for register in 0..8 {
                    if register_list & (1 << register) != 0 {
                        bytes.extend_from_slice(&self.regs[register].to_le_bytes());
                    }
                }
                self.memory.check_write(base, bytes.len())?;
                self.memory.write(base, &bytes)?;
                self.regs[rn] = base.wrapping_add(count * 4);
            }
            return Ok(None);
        }
        if instruction & 0xfe00 == 0xb400 || instruction & 0xfe00 == 0xbc00 {
            let push = instruction & 0xfe00 == 0xb400;
            let include_extra = instruction & (1 << 8) != 0;
            let mut register_list = instruction & 0x00ff;
            if include_extra {
                register_list |= 1 << if push { 14 } else { 15 };
            }
            if register_list == 0 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction: instruction as u32,
                    thumb: true,
                });
            }
            let byte_count = register_list.count_ones() * 4;
            let byte_count_usize = byte_count as usize;
            let stack_pointer = self.regs[13];
            if push {
                let new_stack_pointer = stack_pointer.wrapping_sub(byte_count);
                let mut bytes = Vec::with_capacity(byte_count_usize);
                for register in 0..16 {
                    if register_list & (1 << register) != 0 {
                        bytes.extend_from_slice(&self.regs[register].to_le_bytes());
                    }
                }
                self.memory
                    .check_write(new_stack_pointer, byte_count_usize)?;
                self.memory.write(new_stack_pointer, &bytes)?;
                self.regs[13] = new_stack_pointer;
            } else {
                let bytes = self.memory.read(stack_pointer, byte_count_usize)?;
                let mut offset = 0;
                let mut loaded_pc = None;
                for register in 0..16 {
                    if register_list & (1 << register) != 0 {
                        let value = u32::from_le_bytes([
                            bytes[offset],
                            bytes[offset + 1],
                            bytes[offset + 2],
                            bytes[offset + 3],
                        ]);
                        self.regs[register] = value;
                        if register == 15 {
                            loaded_pc = Some(value);
                        }
                        offset += 4;
                    }
                }
                self.regs[13] = stack_pointer.wrapping_add(byte_count);
                if let Some(target) = loaded_pc {
                    self.branch_exchange(target);
                }
            }
            return Ok(None);
        }
        if instruction & 0xff80 == 0xb000 || instruction & 0xff80 == 0xb080 {
            let subtract = instruction & (1 << 7) != 0;
            let offset = ((instruction & 0x7f) as u32) << 2;
            self.regs[13] = if subtract {
                self.regs[13].wrapping_sub(offset)
            } else {
                self.regs[13].wrapping_add(offset)
            };
            return Ok(None);
        }
        if instruction & 0xf800 == 0x4800 {
            let rd = ((instruction >> 8) & 7) as usize;
            let offset = ((instruction & 0xff) as u32) << 2;
            let address = instruction_pc.wrapping_add(4) & !3;
            self.regs[rd] = self.read_u32(address.wrapping_add(offset))?;
            return Ok(None);
        }
        if instruction & 0xf800 == 0x2000 {
            let rd = ((instruction >> 8) & 7) as usize;
            self.regs[rd] = (instruction & 0xff) as u32;
            self.set_nz(self.regs[rd]);
            return Ok(None);
        }
        if instruction & 0xf800 == 0x3000 || instruction & 0xf800 == 0x3800 {
            let rd = ((instruction >> 8) & 7) as usize;
            let immediate = (instruction & 0xff) as u32;
            let old = self.regs[rd];
            let subtract = instruction & 0xf800 == 0x3800;
            self.regs[rd] = if subtract {
                self.sub_with_flags(old, immediate, true)
            } else {
                self.add_with_flags(old, immediate, false)
            };
            return Ok(None);
        }
        if instruction & 0xf800 == 0x2800 {
            let rd = ((instruction >> 8) & 7) as usize;
            self.sub_with_flags(self.regs[rd], (instruction & 0xff) as u32, true);
            return Ok(None);
        }
        if instruction & 0xfc00 == 0x4400 {
            let operation = (instruction >> 8) & 3;
            let rd = ((instruction & 7) | ((instruction >> 4) & 8)) as usize;
            let rm = ((instruction >> 3) & 0xf) as usize;
            match operation {
                0 => self.regs[rd] = self.regs[rd].wrapping_add(self.regs[rm]),
                1 => {
                    self.sub_with_flags(self.regs[rd], self.regs[rm], true);
                    return Ok(None);
                }
                2 => self.regs[rd] = self.regs[rm],
                3 => {
                    let target = self.regs[rm];
                    if instruction & 0x0080 != 0 {
                        self.regs[14] = instruction_pc.wrapping_add(2) | 1;
                    }
                    self.branch_exchange(target);
                    return Ok(None);
                }
                _ => unreachable!(),
            }
            if rd == 15 {
                let target = self.regs[15];
                self.thumb = target & 1 != 0;
                self.pc = target & if self.thumb { !1 } else { !3 };
            }
            return Ok(None);
        }
        if instruction & 0xf800 == 0xe000 {
            let immediate = sign_extend((instruction & 0x07ff) as u32, 11) << 1;
            self.pc = instruction_pc
                .wrapping_add(4)
                .wrapping_add(immediate as u32);
            self.regs[15] = self.pc;
            return Ok(None);
        }
        if instruction & 0xf000 == 0xd000 && instruction & 0x0f00 < 0x0e00 {
            let condition = ((instruction >> 8) & 0xf) as u8;
            if self.condition_passed(condition) {
                let immediate = sign_extend((instruction & 0xff) as u32, 8) << 1;
                self.pc = instruction_pc
                    .wrapping_add(4)
                    .wrapping_add(immediate as u32);
                self.regs[15] = self.pc;
            }
            return Ok(None);
        }
        if instruction & 0xf800 == 0x6000 || instruction & 0xf800 == 0x6800 {
            let load = instruction & 0x0800 != 0;
            let immediate = (((instruction >> 6) & 0x1f) as u32) << 2;
            let rn = ((instruction >> 3) & 7) as usize;
            let rd = (instruction & 7) as usize;
            let address = self.regs[rn].wrapping_add(immediate);
            if load {
                self.regs[rd] = self.read_u32(address)?;
            } else {
                self.memory.write(address, &self.regs[rd].to_le_bytes())?;
            }
            return Ok(None);
        }
        if instruction & 0xf800 == 0x1800 {
            let immediate = instruction & (1 << 10) != 0;
            let subtract = instruction & (1 << 9) != 0;
            let operand = if immediate {
                ((instruction >> 6) & 7) as u32
            } else {
                self.regs[((instruction >> 6) & 7) as usize]
            };
            let rn = ((instruction >> 3) & 7) as usize;
            let rd = (instruction & 7) as usize;
            self.regs[rd] = if subtract {
                self.sub_with_flags(self.regs[rn], operand, true)
            } else {
                self.add_with_flags(self.regs[rn], operand, false)
            };
            return Ok(None);
        }

        Err(ElfError::InvalidInstruction {
            pc: instruction_pc,
            instruction: instruction as u32,
            thumb: true,
        })
    }

    fn step_arm(
        &mut self,
        broker: &mut SyscallBroker,
        instruction_pc: u32,
    ) -> Result<Option<i32>, ElfError> {
        let bytes = self.memory.fetch(instruction_pc, 4)?;
        let instruction = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        self.pc = instruction_pc.wrapping_add(4);
        self.regs[15] = instruction_pc.wrapping_add(8);

        let condition = (instruction >> 28) as u8;
        let blx_immediate = instruction & 0xfe00_0000 == 0xfa00_0000;
        if !blx_immediate && !self.condition_passed(condition) {
            return Ok(None);
        }
        if instruction & 0x0f00_0000 == 0x0f00_0000 {
            return self.handle_svc(broker, instruction_pc);
        }
        if blx_immediate {
            let h = ((instruction >> 24) & 1) as i32;
            let immediate = (sign_extend(instruction & 0x00ff_ffff, 24) << 2) | (h << 1);
            let target = instruction_pc
                .wrapping_add(8)
                .wrapping_add(immediate as u32);
            self.regs[14] = instruction_pc.wrapping_add(4);
            self.thumb = true;
            self.pc = target & !1;
            self.regs[15] = self.pc;
            return Ok(None);
        }
        if instruction & 0x0e00_0000 == 0x0c00_0000
            && instruction & (1 << 24) != 0
            && instruction & (1 << 21) == 0
            && (instruction >> 8) & 0xf == 0xb
        {
            self.step_vfp_double_transfer(instruction_pc, instruction)?;
            return Ok(None);
        }
        if instruction & 0x0e00_0000 == 0x0c00_0000
            && instruction & (1 << 21) != 0
            && (instruction >> 8) & 0xf == 0xb
        {
            self.step_vfp_double_multiple(instruction_pc, instruction)?;
            return Ok(None);
        }
        if instruction & 0x0ff0_0fff == 0x0190_0f9f {
            let rn = ((instruction >> 16) & 0xf) as usize;
            let rd = ((instruction >> 12) & 0xf) as usize;
            if rn == 15 || rd == 15 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            }
            let address = self.regs[rn];
            if address & 3 != 0 {
                return Err(ElfError::MemoryAccess {
                    address,
                    access: "exclusive read",
                });
            }
            self.regs[rd] = self.read_u32(address)?;
            self.exclusive_monitor = Some(address);
            return Ok(None);
        }
        if instruction & 0x0ff0_0ff0 == 0x0180_0f90 {
            let rn = ((instruction >> 16) & 0xf) as usize;
            let rd = ((instruction >> 12) & 0xf) as usize;
            let rm = (instruction & 0xf) as usize;
            if rn == 15 || rd == 15 || rm == 15 || rd == rn {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            }
            let address = self.regs[rn];
            if address & 3 != 0 {
                return Err(ElfError::MemoryAccess {
                    address,
                    access: "exclusive write",
                });
            }
            let stored = self.exclusive_monitor == Some(address);
            self.exclusive_monitor = None;
            if stored {
                self.memory.check_write(address, 4)?;
                self.memory.write(address, &self.regs[rm].to_le_bytes())?;
                self.regs[rd] = 0;
            } else {
                self.regs[rd] = 1;
            }
            return Ok(None);
        }
        let register_branch = instruction & 0x0fff_fff0;
        if register_branch == 0x012f_ff10 || register_branch == 0x012f_ff30 {
            let rm = (instruction & 0xf) as usize;
            if rm == 15 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            }
            let target = self.regs[rm];
            if register_branch == 0x012f_ff30 {
                self.regs[14] = instruction_pc.wrapping_add(4);
            }
            self.branch_exchange(target);
            return Ok(None);
        }
        // Gingerbread Bionic's HAVE_ARM_TLS_REGISTER path reads TPIDRURO with
        // MRC p15, 0, Rt, c13, c0, 3. Linux installs that user read-only value
        // through the ARM-private set_tls syscall below.
        if instruction & 0x0fff_0fff == 0x0e1d_0f70 {
            let destination = ((instruction >> 12) & 0xf) as usize;
            if destination == 15 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            }
            self.regs[destination] = self.thread_pointer;
            return Ok(None);
        }
        let wide_move = instruction & 0x0ff0_0000;
        if wide_move == 0x0300_0000 || wide_move == 0x0340_0000 {
            let destination = ((instruction >> 12) & 0xf) as usize;
            if destination == 15 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            }
            let immediate = ((instruction >> 4) & 0xf000) | (instruction & 0x0fff);
            if wide_move == 0x0340_0000 {
                self.regs[destination] = (self.regs[destination] & 0x0000_ffff) | (immediate << 16);
            } else {
                self.regs[destination] = immediate;
            }
            return Ok(None);
        }
        if instruction & 0x0fff_0ff0 == 0x016f_0f10 {
            let destination = ((instruction >> 12) & 0xf) as usize;
            let source = (instruction & 0xf) as usize;
            if destination == 15 || source == 15 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            }
            self.regs[destination] = self.regs[source].leading_zeros();
            return Ok(None);
        }
        let bitfield_class = instruction & 0x0fe0_0070;
        if bitfield_class == 0x07c0_0010 {
            let destination = ((instruction >> 12) & 0xf) as usize;
            let source = (instruction & 0xf) as usize;
            let lsb = (instruction >> 7) & 0x1f;
            let msb = (instruction >> 16) & 0x1f;
            if destination == 15 || lsb > msb {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            }
            let width = msb - lsb + 1;
            let width_mask = if width == 32 {
                u32::MAX
            } else {
                (1_u32 << width) - 1
            };
            let field_mask = width_mask << lsb;
            let source_value = if source == 15 { 0 } else { self.regs[source] };
            self.regs[destination] =
                (self.regs[destination] & !field_mask) | ((source_value << lsb) & field_mask);
            return Ok(None);
        }
        if bitfield_class == 0x07e0_0050 {
            let destination = ((instruction >> 12) & 0xf) as usize;
            let source = (instruction & 0xf) as usize;
            let lsb = (instruction >> 7) & 0x1f;
            let width = ((instruction >> 16) & 0x1f) + 1;
            if destination == 15 || source == 15 || lsb + width > 32 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            }
            let width_mask = if width == 32 {
                u32::MAX
            } else {
                (1_u32 << width) - 1
            };
            self.regs[destination] = (self.regs[source] >> lsb) & width_mask;
            return Ok(None);
        }
        let extend_class = instruction & 0x0ff0_00f0;
        if extend_class == 0x06e0_0070 || extend_class == 0x06f0_0070 {
            let destination = ((instruction >> 12) & 0xf) as usize;
            let accumulator = ((instruction >> 16) & 0xf) as usize;
            let source = (instruction & 0xf) as usize;
            if destination == 15 || source == 15 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            }
            let rotate = ((instruction >> 10) & 3) * 8;
            let rotated = self.regs[source].rotate_right(rotate);
            let extended = if extend_class == 0x06e0_0070 {
                rotated & 0xff
            } else {
                rotated & 0xffff
            };
            self.regs[destination] = if accumulator == 15 {
                extended
            } else {
                self.regs[accumulator].wrapping_add(extended)
            };
            return Ok(None);
        }
        if instruction & 0x0e00_0000 == 0x0a00_0000 {
            if instruction & (1 << 24) != 0 {
                self.regs[14] = instruction_pc.wrapping_add(4);
            }
            let immediate = sign_extend(instruction & 0x00ff_ffff, 24) << 2;
            self.pc = instruction_pc
                .wrapping_add(8)
                .wrapping_add(immediate as u32);
            self.regs[15] = self.pc;
            return Ok(None);
        }
        let flags = ArmFlags {
            n: self.n,
            z: self.z,
            c: self.c,
            v: self.v,
        };
        if let Some(result) = execute_multiply(instruction, &self.regs, flags) {
            self.regs[result.low_destination] = result.low_result;
            if let Some((destination, value)) = result.high_result {
                self.regs[destination] = value;
            }
            if let Some(flags) = result.flags {
                self.n = flags.n;
                self.z = flags.z;
                self.c = flags.c;
                self.v = flags.v;
            }
            return Ok(None);
        }
        if instruction & 0x0e10_00d0 == 0x0000_00d0 {
            let pre_index = instruction & (1 << 24) != 0;
            let up = instruction & (1 << 23) != 0;
            let immediate = instruction & (1 << 22) != 0;
            let writeback = instruction & (1 << 21) != 0;
            let load = instruction & (1 << 5) == 0; // SH=10: LDRD, SH=11: STRD.
            let rn = ((instruction >> 16) & 0xf) as usize;
            let rd = ((instruction >> 12) & 0xf) as usize;
            if rn == 15 || rd >= 14 || rd & 1 != 0 || (!pre_index && writeback) {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            }
            let offset = if immediate {
                ((instruction >> 4) & 0xf0) | (instruction & 0xf)
            } else {
                let rm = (instruction & 0xf) as usize;
                if instruction & 0x0000_0f00 != 0 || rm == 15 {
                    return Err(ElfError::InvalidInstruction {
                        pc: instruction_pc,
                        instruction,
                        thumb: false,
                    });
                }
                self.regs[rm]
            };
            let base = self.regs[rn];
            let adjusted = if up {
                base.wrapping_add(offset)
            } else {
                base.wrapping_sub(offset)
            };
            let address = if pre_index { adjusted } else { base };
            let update_base = writeback || !pre_index;
            if update_base && (rn == rd || rn == rd + 1) {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            }
            if load {
                let bytes = self.memory.read(address, 8)?;
                self.regs[rd] = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
                self.regs[rd + 1] = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
            } else {
                let mut bytes = Vec::with_capacity(8);
                bytes.extend_from_slice(&self.regs[rd].to_le_bytes());
                bytes.extend_from_slice(&self.regs[rd + 1].to_le_bytes());
                self.memory.check_write(address, 8)?;
                self.memory.write(address, &bytes)?;
            }
            if update_base {
                self.regs[rn] = adjusted;
            }
            return Ok(None);
        }
        let halfword_class = instruction & 0x0e00_0090;
        let transfer_kind = (instruction >> 5) & 3;
        if halfword_class == 0x0000_0090 && transfer_kind != 0 {
            let pre_index = instruction & (1 << 24) != 0;
            let up = instruction & (1 << 23) != 0;
            let immediate = instruction & (1 << 22) != 0;
            let writeback = instruction & (1 << 21) != 0;
            let load = instruction & (1 << 20) != 0;
            let rn = ((instruction >> 16) & 0xf) as usize;
            let rd = ((instruction >> 12) & 0xf) as usize;
            let (size, signed) = match (transfer_kind, load) {
                (1, _) => (2, false),   // LDRH / STRH.
                (2, true) => (1, true), // LDRSB.
                (3, true) => (2, true), // LDRSH.
                _ => {
                    return Err(ElfError::InvalidInstruction {
                        pc: instruction_pc,
                        instruction,
                        thumb: false,
                    });
                }
            };
            if rd == 15
                || (!pre_index && writeback)
                || (rn == 15 && (!load || !pre_index || writeback))
            {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            }
            let offset = if immediate {
                ((instruction >> 4) & 0xf0) | (instruction & 0xf)
            } else {
                let rm = (instruction & 0xf) as usize;
                if instruction & 0x0000_0f00 != 0 || rm == 15 {
                    return Err(ElfError::InvalidInstruction {
                        pc: instruction_pc,
                        instruction,
                        thumb: false,
                    });
                }
                self.regs[rm]
            };
            let base = if rn == 15 {
                instruction_pc.wrapping_add(8)
            } else {
                self.regs[rn]
            };
            let adjusted = if up {
                base.wrapping_add(offset)
            } else {
                base.wrapping_sub(offset)
            };
            let address = if pre_index { adjusted } else { base };
            let update_base = writeback || !pre_index;
            if load && update_base && rn == rd {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            }
            if load {
                let bytes = self.memory.read(address, size)?;
                self.regs[rd] = match (size, signed) {
                    (1, true) => bytes[0] as i8 as i32 as u32,
                    (2, true) => i16::from_le_bytes([bytes[0], bytes[1]]) as i32 as u32,
                    (2, false) => u16::from_le_bytes([bytes[0], bytes[1]]) as u32,
                    _ => {
                        return Err(ElfError::InvalidInstruction {
                            pc: instruction_pc,
                            instruction,
                            thumb: false,
                        });
                    }
                };
            } else {
                self.memory
                    .write(address, &(self.regs[rd] as u16).to_le_bytes())?;
            }
            if update_base {
                self.regs[rn] = adjusted;
            }
            return Ok(None);
        }
        if instruction & 0x0e00_0000 == 0x0800_0000 {
            let pre_index = instruction & (1 << 24) != 0;
            let up = instruction & (1 << 23) != 0;
            let user_registers = instruction & (1 << 22) != 0;
            let writeback = instruction & (1 << 21) != 0;
            let load = instruction & (1 << 20) != 0;
            let rn = ((instruction >> 16) & 0xf) as usize;
            let register_list = instruction as u16;
            let base_in_list = register_list & (1 << rn) != 0;
            let base_is_lowest = register_list.trailing_zeros() as usize == rn;
            if user_registers
                || rn == 15
                || register_list == 0
                || (writeback && base_in_list && (load || !base_is_lowest))
                || (!load && register_list & (1 << 15) != 0)
            {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            }
            let base = self.regs[rn];
            let byte_count = register_list.count_ones() * 4;
            let start = match (pre_index, up) {
                (false, true) => base,
                (true, true) => base.wrapping_add(4),
                (false, false) => base.wrapping_sub(byte_count).wrapping_add(4),
                (true, false) => base.wrapping_sub(byte_count),
            };
            let updated_base = if up {
                base.wrapping_add(byte_count)
            } else {
                base.wrapping_sub(byte_count)
            };
            let byte_count = byte_count as usize;
            if load {
                let bytes = self.memory.read(start, byte_count)?;
                let mut loaded = Vec::with_capacity(register_list.count_ones() as usize);
                let mut offset = 0;
                for register in 0..16 {
                    if register_list & (1 << register) != 0 {
                        let value = u32::from_le_bytes([
                            bytes[offset],
                            bytes[offset + 1],
                            bytes[offset + 2],
                            bytes[offset + 3],
                        ]);
                        loaded.push((register, value));
                        offset += 4;
                    }
                }
                let mut loaded_pc = None;
                for (register, value) in loaded {
                    self.regs[register] = value;
                    if register == 15 {
                        loaded_pc = Some(value);
                    }
                }
                if writeback {
                    self.regs[rn] = updated_base;
                }
                if let Some(target) = loaded_pc {
                    self.branch_exchange(target);
                }
            } else {
                let mut bytes = Vec::with_capacity(byte_count);
                for register in 0..16 {
                    if register_list & (1 << register) != 0 {
                        let value = if register == 15 {
                            instruction_pc.wrapping_add(12)
                        } else {
                            self.regs[register]
                        };
                        bytes.extend_from_slice(&value.to_le_bytes());
                    }
                }
                self.memory.check_write(start, byte_count)?;
                self.memory.write(start, &bytes)?;
                if writeback {
                    self.regs[rn] = updated_base;
                }
            }
            return Ok(None);
        }
        if instruction & 0x0c00_0000 == 0x0400_0000 {
            let load = instruction & (1 << 20) != 0;
            let pre_index = instruction & (1 << 24) != 0;
            let up = instruction & (1 << 23) != 0;
            let byte = instruction & (1 << 22) != 0;
            let writeback = instruction & (1 << 21) != 0;
            let rn = ((instruction >> 16) & 0xf) as usize;
            let rd = ((instruction >> 12) & 0xf) as usize;
            let offset = if instruction & (1 << 25) != 0 {
                if (!pre_index && writeback) || (rn == 15 && writeback) {
                    return Err(ElfError::InvalidInstruction {
                        pc: instruction_pc,
                        instruction,
                        thumb: false,
                    });
                }
                let Some(offset) =
                    decode_single_transfer_register_offset(instruction, &self.regs, self.c)
                else {
                    return Err(ElfError::InvalidInstruction {
                        pc: instruction_pc,
                        instruction,
                        thumb: false,
                    });
                };
                offset
            } else {
                instruction & 0xfff
            };
            let base = if rn == 15 {
                instruction_pc.wrapping_add(8)
            } else {
                self.regs[rn]
            };
            let adjusted = if up {
                base.wrapping_add(offset)
            } else {
                base.wrapping_sub(offset)
            };
            let address = if pre_index { adjusted } else { base };
            if load {
                self.regs[rd] = if byte {
                    self.memory.read(address, 1)?[0] as u32
                } else {
                    self.read_u32(address)?
                };
                if rd == 15 {
                    let target = self.regs[15];
                    self.thumb = target & 1 != 0;
                    self.pc = target & if self.thumb { !1 } else { !3 };
                    self.regs[15] = self.pc;
                    return Ok(None);
                }
            } else if byte {
                self.memory.write(address, &[self.regs[rd] as u8])?;
            } else {
                self.memory.write(address, &self.regs[rd].to_le_bytes())?;
            }
            if writeback || !pre_index {
                self.regs[rn] = adjusted;
            }
            return Ok(None);
        }
        if instruction & 0x0c00_0000 == 0 {
            let flags = ArmFlags {
                n: self.n,
                z: self.z,
                c: self.c,
                v: self.v,
            };
            let Some(result) = execute_data_processing(instruction, &self.regs, flags) else {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            };
            if result.writes_destination {
                self.regs[result.destination] = result.result;
                if result.destination == 15 {
                    self.pc = result.result & !3;
                    self.regs[15] = self.pc;
                }
            }
            if let Some(flags) = result.flags {
                self.n = flags.n;
                self.z = flags.z;
                self.c = flags.c;
                self.v = flags.v;
            }
            return Ok(None);
        }

        Err(ElfError::InvalidInstruction {
            pc: instruction_pc,
            instruction,
            thumb: false,
        })
    }

    fn step_vfp_double_multiple(
        &mut self,
        instruction_pc: u32,
        instruction: u32,
    ) -> Result<(), ElfError> {
        let words = instruction & 0xff;
        let registers = (words / 2) as usize;
        let first_register =
            ((((instruction >> 22) & 1) << 4) | ((instruction >> 12) & 0xf)) as usize;
        let base_register = ((instruction >> 16) & 0xf) as usize;
        if words == 0
            || words & 1 != 0
            || registers == 0
            || first_register + registers > self.vfp_double_registers.len()
            || base_register == 15
        {
            return Err(ElfError::InvalidInstruction {
                pc: instruction_pc,
                instruction,
                thumb: false,
            });
        }
        let pre_index = instruction & (1 << 24) != 0;
        let add = instruction & (1 << 23) != 0;
        let load = instruction & (1 << 20) != 0;
        let writeback = instruction & (1 << 21) != 0;
        let transfer_bytes = words * 4;
        let base = self.regs[base_register];
        let start = match (add, pre_index) {
            (true, true) => base.wrapping_add(4),
            (true, false) => base,
            (false, true) => base.wrapping_sub(transfer_bytes),
            (false, false) => base.wrapping_sub(transfer_bytes).wrapping_add(4),
        };
        for offset in 0..registers {
            let address = start.wrapping_add((offset as u32) * 8);
            let register = first_register + offset;
            if load {
                let bytes = self.memory.read(address, 8)?;
                self.vfp_double_registers[register] =
                    u64::from_le_bytes(bytes.try_into().expect("eight-byte VFP register"));
            } else {
                self.memory
                    .write(address, &self.vfp_double_registers[register].to_le_bytes())?;
            }
        }
        if writeback {
            self.regs[base_register] = if add {
                base.wrapping_add(transfer_bytes)
            } else {
                base.wrapping_sub(transfer_bytes)
            };
        }
        Ok(())
    }

    fn step_vfp_double_transfer(
        &mut self,
        instruction_pc: u32,
        instruction: u32,
    ) -> Result<(), ElfError> {
        let register = ((((instruction >> 22) & 1) << 4) | ((instruction >> 12) & 0xf)) as usize;
        let base_register = ((instruction >> 16) & 0xf) as usize;
        let load = instruction & (1 << 20) != 0;
        if register >= self.vfp_double_registers.len() || (base_register == 15 && !load) {
            return Err(ElfError::InvalidInstruction {
                pc: instruction_pc,
                instruction,
                thumb: false,
            });
        }
        let base = if base_register == 15 {
            self.regs[15] & !3
        } else {
            self.regs[base_register]
        };
        let offset = (instruction & 0xff) * 4;
        let address = if instruction & (1 << 23) != 0 {
            base.wrapping_add(offset)
        } else {
            base.wrapping_sub(offset)
        };
        if load {
            let bytes = self.memory.read(address, 8)?;
            self.vfp_double_registers[register] =
                u64::from_le_bytes(bytes.try_into().expect("eight-byte VFP register"));
        } else {
            self.memory
                .write(address, &self.vfp_double_registers[register].to_le_bytes())?;
        }
        Ok(())
    }

    fn branch_exchange(&mut self, target: u32) {
        self.thumb = target & 1 != 0;
        self.pc = target & if self.thumb { !1 } else { !3 };
        self.regs[15] = self.pc;
    }

    fn resize_program_break(&mut self, requested: u32) -> u32 {
        if requested == 0 {
            return self.program_break;
        }
        if requested < self.brk_base || requested > MMAP_BASE {
            return self.program_break;
        }
        let new_length = (requested - self.brk_base) as usize;
        if self
            .memory
            .overlaps_except(self.brk_base, new_length, Some(self.brk_base))
        {
            return self.program_break;
        }
        if self.memory.allocated_bytes().saturating_sub(
            self.memory
                .segments
                .iter()
                .find(|segment| segment.start == self.brk_base)
                .map_or(0, |segment| segment.bytes.len()),
        ) + new_length
            > MAX_GUEST_MEMORY_BYTES
        {
            return self.program_break;
        }

        if let Some(index) = self
            .memory
            .segments
            .iter()
            .position(|segment| segment.start == self.brk_base)
        {
            if new_length == 0 {
                self.memory.segments.remove(index);
            } else {
                self.memory.segments[index].bytes.resize(new_length, 0);
            }
        } else if new_length != 0 {
            self.memory.segments.push(Segment {
                start: self.brk_base,
                bytes: vec![0; new_length],
                flags: PF_R | PF_W,
                fault_after: None,
            });
            self.memory.segments.sort_by_key(|segment| segment.start);
        }
        self.program_break = requested;
        requested
    }

    fn handle_memory_syscall(&mut self, number: u32, broker: &mut SyscallBroker) -> u32 {
        const PROT_READ: u32 = 1;
        const PROT_WRITE: u32 = 2;
        const PROT_EXEC: u32 = 4;
        const MAP_SHARED: u32 = 0x01;
        const MAP_PRIVATE: u32 = 0x02;
        const MAP_FIXED: u32 = 0x10;
        const MAP_ANONYMOUS: u32 = 0x20;

        match number {
            45 => self.resize_program_break(self.regs[0]),
            91 => {
                let address = self.regs[0];
                let length = self.regs[1] as usize;
                let Some(length) = page_rounded_length(length) else {
                    return negative_errno(22);
                };
                if address & (PAGE_SIZE - 1) != 0 || length == 0 {
                    return negative_errno(22);
                }
                if checked_memory_end(address, length, "unmap").is_err() {
                    return negative_errno(22);
                }
                self.memory.unmap(address, length);
                0
            }
            125 => {
                let address = self.regs[0];
                let length = self.regs[1] as usize;
                let protection = self.regs[2];
                let Some(length) = page_rounded_length(length) else {
                    return negative_errno(22);
                };
                if address & (PAGE_SIZE - 1) != 0
                    || length == 0
                    || protection & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0
                    || checked_memory_end(address, length, "protect").is_err()
                {
                    return negative_errno(22);
                }
                let mut flags = 0;
                if protection & PROT_READ != 0 {
                    flags |= PF_R;
                }
                if protection & PROT_WRITE != 0 {
                    flags |= PF_W;
                }
                if protection & PROT_EXEC != 0 {
                    flags |= PF_X;
                }
                match self.memory.protect(address, length, flags) {
                    Ok(()) => 0,
                    Err(_) => negative_errno(12), // ENOMEM
                }
            }
            192 => {
                let address_hint = self.regs[0];
                let length = self.regs[1] as usize;
                let protection = self.regs[2];
                let map_flags = self.regs[3];
                let file_descriptor = self.regs[4] as i32;
                let page_offset = self.regs[5];
                let Some(length) = page_rounded_length(length) else {
                    return negative_errno(22);
                };
                let sharing = map_flags & (MAP_SHARED | MAP_PRIVATE);
                if length == 0
                    || length > MAX_MAPPING_BYTES
                    || protection & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0
                    || map_flags & !(MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS) != 0
                    || sharing == 0
                    || sharing == (MAP_SHARED | MAP_PRIVATE)
                {
                    return negative_errno(22);
                }
                let anonymous = map_flags & MAP_ANONYMOUS != 0;
                if anonymous && page_offset != 0 {
                    return negative_errno(22);
                }
                if !anonymous && file_descriptor < 0 {
                    return negative_errno(9); // EBADF
                }
                let file_bytes = if anonymous {
                    None
                } else {
                    match read_guest_mapping_file(broker, file_descriptor, page_offset, length) {
                        Ok(bytes) => Some(bytes),
                        Err(errno) => return negative_errno(errno),
                    }
                };
                let flags = (if protection & PROT_READ != 0 { PF_R } else { 0 })
                    | (if protection & PROT_WRITE != 0 {
                        PF_W
                    } else {
                        0
                    })
                    | (if protection & PROT_EXEC != 0 { PF_X } else { 0 });
                let fixed = map_flags & MAP_FIXED != 0;
                let address = if fixed {
                    if address_hint == 0
                        || address_hint & (PAGE_SIZE - 1) != 0
                        || checked_memory_end(address_hint, length, "map").is_err()
                    {
                        return negative_errno(22);
                    }
                    address_hint
                } else {
                    let hint = address_hint & !(PAGE_SIZE - 1);
                    let Some(address) = self.memory.find_free_mapping(hint, length) else {
                        return negative_errno(12);
                    };
                    address
                };
                let replaced = if fixed {
                    self.memory.mapped_bytes_in_range(address, length)
                } else {
                    0
                };
                if self
                    .memory
                    .allocated_bytes()
                    .saturating_sub(replaced)
                    .saturating_add(length)
                    > MAX_GUEST_MEMORY_BYTES
                {
                    return negative_errno(12);
                }
                if fixed {
                    self.memory.unmap(address, length);
                }
                let mapping = if let Some(bytes) = file_bytes {
                    self.memory.map_file_bytes(address, length, &bytes, flags)
                } else {
                    self.memory.map_zeroed(address, length, flags)
                };
                match mapping {
                    Ok(()) => address,
                    Err(_) => negative_errno(12),
                }
            }
            _ => unreachable!("only process-memory syscalls are dispatched here"),
        }
    }

    fn handle_svc(
        &mut self,
        broker: &mut SyscallBroker,
        instruction_pc: u32,
    ) -> Result<Option<i32>, ElfError> {
        let number = self.regs[7];
        let args = [
            self.regs[0],
            self.regs[1],
            self.regs[2],
            self.regs[3],
            self.regs[4],
            self.regs[5],
        ];
        let outcome = self.handle_svc_inner(broker, instruction_pc);
        self.syscall_trace.push(ElfSyscallTrace {
            step: self.instructions,
            pc: instruction_pc,
            number,
            args,
            result: self.regs[0],
            blocked: self.waiting_for_events,
        });
        if std::env::var_os("GINGERVM_TRACE_SYSCALLS").is_some() {
            let result = if self.waiting_for_events {
                "blocked (no ready guest fd)".to_owned()
            } else {
                (self.regs[0] as i32).to_string()
            };
            eprintln!(
                "guest syscall #{} {} args={args:?} -> {result} at 0x{instruction_pc:08x}",
                number,
                syscall_name(number)
            );
        }
        outcome
    }

    fn handle_svc_inner(
        &mut self,
        broker: &mut SyscallBroker,
        instruction_pc: u32,
    ) -> Result<Option<i32>, ElfError> {
        let number = self.regs[7];
        if number == 168 {
            self.handle_poll_syscall(broker, instruction_pc);
            return Ok(None);
        }
        if number == 285 {
            self.handle_accept_syscall(broker, instruction_pc);
            return Ok(None);
        }
        if number == 295 {
            self.handle_getsockopt_syscall(broker, instruction_pc);
            return Ok(None);
        }
        if number == ARM_NR_SET_TLS {
            self.thread_pointer = self.regs[0];
            self.regs[0] = 0;
            return Ok(None);
        }
        if number == 191 {
            self.handle_getrlimit_syscall(instruction_pc);
            return Ok(None);
        }
        if matches!(number, 78 | 162 | 263) {
            self.handle_time_syscall(instruction_pc, number);
            return Ok(None);
        }
        if number == 60 {
            let previous = self.file_creation_mask;
            self.file_creation_mask = self.regs[0] & 0o777;
            self.regs[0] = previous;
            return Ok(None);
        }
        if number == 67 {
            self.handle_legacy_sigaction(instruction_pc);
            return Ok(None);
        }
        if number == 1 || number == 248 {
            return Ok(Some(self.regs[0] as i32));
        }
        if matches!(number, 45 | 91 | 125 | 192) {
            self.regs[0] = self.handle_memory_syscall(number, broker);
            return Ok(None);
        }

        let args = [
            self.regs[0],
            self.regs[1],
            self.regs[2],
            self.regs[3],
            self.regs[4],
            self.regs[5],
        ];
        let operation: GuestSyscall = match number {
            21 => {
                let strings = (|| {
                    let source = self.read_c_string(args[0])?;
                    let target = self.read_c_string(args[1])?;
                    let fs_type = self.read_c_string(args[2])?;
                    let data = if args[4] == 0 {
                        None
                    } else {
                        Some(self.read_c_string(args[4])?)
                    };
                    Ok::<_, ElfError>((source, target, fs_type, data))
                })();
                match strings {
                    Ok((source, target, fs_type, data)) => GuestSyscall::Mount {
                        source,
                        target,
                        fs_type,
                        flags: args[3],
                        data,
                    },
                    Err(_) => {
                        self.record_errno(
                            instruction_pc,
                            GuestSyscall::Control {
                                name: "mount".into(),
                            },
                            14,
                        );
                        self.regs[0] = negative_errno(14);
                        return Ok(None);
                    }
                }
            }
            52 => match self.read_c_string(args[0]) {
                Ok(target) => GuestSyscall::Umount {
                    target,
                    flags: args[1],
                },
                Err(_) => {
                    self.record_errno(
                        instruction_pc,
                        GuestSyscall::Control {
                            name: "umount2".into(),
                        },
                        14,
                    );
                    self.regs[0] = negative_errno(14);
                    return Ok(None);
                }
            },
            10 => match self.read_c_string(args[0]) {
                Ok(path) => GuestSyscall::Unlink { path },
                Err(_) => {
                    self.record_errno(
                        instruction_pc,
                        GuestSyscall::Control {
                            name: "unlink".into(),
                        },
                        14,
                    );
                    self.regs[0] = negative_errno(14);
                    return Ok(None);
                }
            },
            14 => match self.read_c_string(args[0]) {
                Ok(path) => GuestSyscall::Mknod {
                    path,
                    mode: args[1],
                    device: args[2],
                },
                Err(_) => {
                    self.record_errno(
                        instruction_pc,
                        GuestSyscall::Control {
                            name: "mknod".into(),
                        },
                        14,
                    );
                    self.regs[0] = negative_errno(14);
                    return Ok(None);
                }
            },
            19 => GuestSyscall::Lseek {
                fd: args[0] as i32,
                offset: args[1] as i32,
                whence: args[2] as i32,
            },
            39 => match self.read_c_string(args[0]) {
                Ok(path) => GuestSyscall::Mkdir {
                    path,
                    mode: args[1] & !self.file_creation_mask,
                },
                Err(_) => {
                    self.record_errno(
                        instruction_pc,
                        GuestSyscall::Control {
                            name: "mkdir".into(),
                        },
                        14,
                    );
                    self.regs[0] = negative_errno(14);
                    return Ok(None);
                }
            },
            195 => {
                if self.memory.check_write(args[1], STAT64_SIZE).is_err() {
                    self.record_errno(
                        instruction_pc,
                        GuestSyscall::Control {
                            name: "stat64".into(),
                        },
                        14,
                    );
                    self.regs[0] = negative_errno(14);
                    return Ok(None);
                }
                match self.read_c_string(args[0]) {
                    Ok(path) => GuestSyscall::Stat { path },
                    Err(_) => {
                        self.record_errno(
                            instruction_pc,
                            GuestSyscall::Control {
                                name: "stat64".into(),
                            },
                            14,
                        );
                        self.regs[0] = negative_errno(14);
                        return Ok(None);
                    }
                }
            }
            3 | 292 => {
                let fd = args[0] as i32;
                if number == 292 && (args[3] != 0 || args[4] != 0 || args[5] != 0) {
                    self.record_errno(
                        instruction_pc,
                        GuestSyscall::Control {
                            name: "recvfrom".to_owned(),
                        },
                        95,
                    );
                    self.regs[0] = negative_errno(95);
                    return Ok(None);
                }
                let count = args[2] as usize;
                if count > MAX_TRANSFER_BYTES {
                    self.record_errno(instruction_pc, GuestSyscall::Read { fd, count }, 7);
                    self.regs[0] = negative_errno(7);
                    return Ok(None);
                } else if self.memory.check_write(args[1], count).is_err() {
                    self.record_errno(
                        instruction_pc,
                        GuestSyscall::Control {
                            name: "read".into(),
                        },
                        14,
                    );
                    self.regs[0] = negative_errno(14);
                    return Ok(None);
                } else {
                    GuestSyscall::Read { fd, count }
                }
            }
            4 => {
                let fd = args[0] as i32;
                let count = args[2] as usize;
                if count > MAX_TRANSFER_BYTES {
                    self.record_errno(
                        instruction_pc,
                        GuestSyscall::Control {
                            name: "write".into(),
                        },
                        7,
                    );
                    self.regs[0] = negative_errno(7);
                    return Ok(None);
                } else {
                    match self.memory.read(args[1], count) {
                        Ok(bytes) => GuestSyscall::Write { fd, bytes },
                        Err(_) => {
                            self.record_errno(
                                instruction_pc,
                                GuestSyscall::Control {
                                    name: "write".into(),
                                },
                                14,
                            );
                            self.regs[0] = negative_errno(14);
                            return Ok(None);
                        }
                    }
                }
            }
            5 => match self.read_c_string(args[0]) {
                Ok(path) => match linux_open_flags(args[1]) {
                    Some(flags) => GuestSyscall::Open { path, flags },
                    None => {
                        self.record_errno(
                            instruction_pc,
                            GuestSyscall::Control {
                                name: "open".into(),
                            },
                            22,
                        );
                        self.regs[0] = negative_errno(22);
                        return Ok(None);
                    }
                },
                Err(_) => {
                    self.record_errno(
                        instruction_pc,
                        GuestSyscall::Control {
                            name: "open".into(),
                        },
                        14,
                    );
                    self.regs[0] = negative_errno(14);
                    return Ok(None);
                }
            },
            6 => GuestSyscall::Close { fd: args[0] as i32 },
            217 => {
                let fd = args[0] as i32;
                let count = args[2] as usize;
                if count > MAX_TRANSFER_BYTES {
                    self.record_errno(instruction_pc, GuestSyscall::Getdents64 { fd, count }, 7);
                    self.regs[0] = negative_errno(7);
                    return Ok(None);
                }
                if self.memory.check_write(args[1], count).is_err() {
                    self.record_errno(
                        instruction_pc,
                        GuestSyscall::Control {
                            name: "getdents64".into(),
                        },
                        14,
                    );
                    self.regs[0] = negative_errno(14);
                    return Ok(None);
                }
                GuestSyscall::Getdents64 { fd, count }
            }
            93 => {
                let length = args[1] as i32;
                if length < 0 {
                    self.record_errno(
                        instruction_pc,
                        GuestSyscall::Control {
                            name: "ftruncate".to_owned(),
                        },
                        22,
                    );
                    self.regs[0] = negative_errno(22);
                    return Ok(None);
                }
                GuestSyscall::Ftruncate {
                    fd: args[0] as i32,
                    length: length as u64,
                }
            }
            63 => GuestSyscall::Dup2 {
                old_fd: args[0] as i32,
                new_fd: args[1] as i32,
            },
            20 | 224 => GuestSyscall::GetPid,
            24 | 49 | 199 | 201 => GuestSyscall::GetUid,
            47 | 50 | 200 | 202 => GuestSyscall::GetGid,
            281 => GuestSyscall::Socket {
                domain: args[0] as i32,
                socket_type: args[1] as i32,
                protocol: args[2] as i32,
            },
            282 => {
                let address = match self.read_unix_sockaddr(args[1], args[2]) {
                    Ok(address) => address,
                    Err(errno) => {
                        self.record_errno(
                            instruction_pc,
                            GuestSyscall::Control {
                                name: "bind".to_owned(),
                            },
                            errno,
                        );
                        self.regs[0] = negative_errno(errno);
                        return Ok(None);
                    }
                };
                GuestSyscall::Bind {
                    fd: args[0] as i32,
                    address,
                }
            }
            284 => GuestSyscall::Listen {
                fd: args[0] as i32,
                backlog: args[1] as i32,
            },
            288 => {
                if self.memory.check_write(args[3], 8).is_err() {
                    self.record_errno(
                        instruction_pc,
                        GuestSyscall::Control {
                            name: "socketpair".to_owned(),
                        },
                        14,
                    );
                    self.regs[0] = negative_errno(14);
                    return Ok(None);
                }
                GuestSyscall::SocketPair {
                    domain: args[0] as i32,
                    socket_type: args[1] as i32,
                    protocol: args[2] as i32,
                }
            }
            322 => match self.read_c_string(args[1]) {
                Ok(path) => match linux_open_flags(args[2]) {
                    Some(flags) => GuestSyscall::OpenAt {
                        dirfd: args[0] as i32,
                        path,
                        flags,
                    },
                    None => {
                        self.record_errno(
                            instruction_pc,
                            GuestSyscall::Control {
                                name: "openat".into(),
                            },
                            22,
                        );
                        self.regs[0] = negative_errno(22);
                        return Ok(None);
                    }
                },
                Err(_) => {
                    self.record_errno(
                        instruction_pc,
                        GuestSyscall::Control {
                            name: "openat".into(),
                        },
                        14,
                    );
                    self.regs[0] = negative_errno(14);
                    return Ok(None);
                }
            },
            _ => GuestSyscall::Control {
                name: syscall_name(number),
            },
        };

        let request = operation;
        let result = broker.dispatch(&request);
        match result {
            Ok(value) => {
                let result_register = match &value {
                    BrokerValue::FileDescriptor(fd) => *fd as u32,
                    BrokerValue::Bytes(bytes) => {
                        self.memory
                            .write(args[1], bytes)
                            .map_err(|_| ElfError::Broker {
                                pc: instruction_pc,
                                source: BrokerError::InvalidArgument(
                                    "syscall output buffer is not writable",
                                ),
                            })?;
                        bytes.len() as u32
                    }
                    BrokerValue::Count(count) => *count as u32,
                    BrokerValue::Identity(identity) => *identity,
                    BrokerValue::FileDescriptorPair(first, second) => {
                        let mut bytes = [0; 8];
                        bytes[..4].copy_from_slice(&first.to_le_bytes());
                        bytes[4..].copy_from_slice(&second.to_le_bytes());
                        self.memory
                            .write(args[3], &bytes)
                            .map_err(|_| ElfError::Broker {
                                pc: instruction_pc,
                                source: BrokerError::InvalidArgument(
                                    "socketpair output buffer is not writable",
                                ),
                            })?;
                        0
                    }
                    BrokerValue::Unit => 0,
                };
                self.events.push(ElfSyscallEvent {
                    step: self.instructions,
                    pc: instruction_pc,
                    syscall: request,
                    result: Ok(value),
                });
                self.regs[0] = result_register;
            }
            Err(error) => {
                let errno = broker_errno(&error);
                self.record_errno(instruction_pc, request, errno);
                self.regs[0] = negative_errno(errno);
            }
        }
        Ok(None)
    }

    fn handle_time_syscall(&mut self, pc: u32, number: u32) {
        let seconds = (self.virtual_time_ns / 1_000_000_000) as u32;
        let nanoseconds = (self.virtual_time_ns % 1_000_000_000) as u32;
        match number {
            263 => {
                let clock_id = self.regs[0] as i32;
                let address = self.regs[1];
                if !matches!(clock_id, 0 | 1) {
                    self.time_syscall_error(pc, number, 22);
                    return;
                }
                let mut bytes = [0; 8];
                bytes[..4].copy_from_slice(&seconds.to_le_bytes());
                bytes[4..].copy_from_slice(&nanoseconds.to_le_bytes());
                if self.memory.write(address, &bytes).is_err() {
                    self.time_syscall_error(pc, number, 14);
                    return;
                }
                self.regs[0] = 0;
            }
            78 => {
                let address = self.regs[0];
                if address != 0 {
                    let mut bytes = [0; 8];
                    bytes[..4].copy_from_slice(&seconds.to_le_bytes());
                    bytes[4..].copy_from_slice(&(nanoseconds / 1_000).to_le_bytes());
                    if self.memory.write(address, &bytes).is_err() {
                        self.time_syscall_error(pc, number, 14);
                        return;
                    }
                }
                self.regs[0] = 0;
            }
            162 => {
                let address = self.regs[0];
                let requested = match self.memory.read(address, 8) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        self.time_syscall_error(pc, number, 14);
                        return;
                    }
                };
                let requested_seconds =
                    i32::from_le_bytes(requested[..4].try_into().expect("timespec seconds"));
                let requested_nanoseconds =
                    i32::from_le_bytes(requested[4..].try_into().expect("timespec nanoseconds"));
                if requested_seconds < 0 || !(0..1_000_000_000).contains(&requested_nanoseconds) {
                    self.time_syscall_error(pc, number, 22);
                    return;
                }
                let duration = (requested_seconds as u64)
                    .saturating_mul(1_000_000_000)
                    .saturating_add(requested_nanoseconds as u64);
                self.virtual_time_ns = self.virtual_time_ns.saturating_add(duration);
                self.regs[0] = 0;
            }
            _ => unreachable!("only virtual-time syscalls are dispatched here"),
        }
    }

    fn handle_getrlimit_syscall(&mut self, pc: u32) {
        let resource = self.regs[0];
        let address = self.regs[1];
        if resource != RLIMIT_STACK {
            self.record_errno(
                pc,
                GuestSyscall::Control {
                    name: "getrlimit".to_owned(),
                },
                22,
            );
            self.regs[0] = negative_errno(22);
            return;
        }

        // Expose exactly the stack range mapped by the runner; Bionic raises
        // smaller limits to its 128 KiB minimum during initial TLS setup.
        let limit = (STACK_SIZE as u32).to_le_bytes();
        let mut bytes = [0; 8];
        bytes[..4].copy_from_slice(&limit);
        bytes[4..].copy_from_slice(&limit);
        if self.memory.write(address, &bytes).is_err() {
            self.record_errno(
                pc,
                GuestSyscall::Control {
                    name: "getrlimit".to_owned(),
                },
                14,
            );
            self.regs[0] = negative_errno(14);
        } else {
            self.regs[0] = 0;
        }
    }

    fn handle_accept_syscall(&mut self, broker: &mut SyscallBroker, pc: u32) {
        let fd = self.regs[0] as i32;
        let address = self.regs[1];
        let length_address = self.regs[2];
        let address_length = if address != 0 && length_address != 0 {
            match self.memory.read(length_address, 4) {
                Ok(bytes) => {
                    Some(u32::from_le_bytes(bytes.try_into().expect("socklen_t")) as usize)
                }
                Err(_) => {
                    self.record_errno(
                        pc,
                        GuestSyscall::Control {
                            name: "accept".to_owned(),
                        },
                        14,
                    );
                    self.regs[0] = negative_errno(14);
                    return;
                }
            }
        } else {
            None
        };
        if let Some(length) = address_length {
            if self.memory.check_write(length_address, 4).is_err()
                || self.memory.check_write(address, length.min(2)).is_err()
            {
                self.record_errno(
                    pc,
                    GuestSyscall::Control {
                        name: "accept".to_owned(),
                    },
                    14,
                );
                self.regs[0] = negative_errno(14);
                return;
            }
        }
        let request = GuestSyscall::Accept { fd };
        match broker.dispatch(&request) {
            Ok(value @ BrokerValue::FileDescriptor(accepted_fd)) => {
                if let Some(length) = address_length {
                    let family = 1u16.to_le_bytes(); // AF_UNIX, anonymous simulated peer
                    if self
                        .memory
                        .write(address, &family[..length.min(2)])
                        .is_err()
                        || self
                            .memory
                            .write(length_address, &2u32.to_le_bytes())
                            .is_err()
                    {
                        self.record_errno(pc, request, 14);
                        self.regs[0] = negative_errno(14);
                        return;
                    }
                }
                self.events.push(ElfSyscallEvent {
                    step: self.instructions,
                    pc,
                    syscall: request,
                    result: Ok(value),
                });
                self.regs[0] = accepted_fd as u32;
            }
            Ok(_) => {
                self.record_errno(pc, request, 5);
                self.regs[0] = negative_errno(5);
            }
            Err(error) => {
                let errno = broker_errno(&error);
                self.record_errno(pc, request, errno);
                self.regs[0] = negative_errno(errno);
            }
        }
    }

    fn handle_getsockopt_syscall(&mut self, broker: &mut SyscallBroker, pc: u32) {
        const SOL_SOCKET: u32 = 1;
        const SO_PEERCRED: u32 = 17;
        let fd = self.regs[0] as i32;
        let level = self.regs[1];
        let option = self.regs[2];
        let value_address = self.regs[3];
        let length_address = self.regs[4];
        let request = GuestSyscall::PeerCredentials { fd };
        if level != SOL_SOCKET || option != SO_PEERCRED {
            self.record_errno(
                pc,
                GuestSyscall::Control {
                    name: "getsockopt".to_owned(),
                },
                92,
            );
            self.regs[0] = negative_errno(92);
            return;
        }
        if value_address == 0
            || length_address == 0
            || self.memory.check_write(value_address, 12).is_err()
            || self.memory.check_write(length_address, 4).is_err()
        {
            self.record_errno(pc, request, 14);
            self.regs[0] = negative_errno(14);
            return;
        }
        let length = match self.memory.read(length_address, 4) {
            Ok(bytes) => u32::from_le_bytes(bytes.try_into().expect("socklen_t")),
            Err(_) => {
                self.record_errno(pc, request, 14);
                self.regs[0] = negative_errno(14);
                return;
            }
        };
        if length < 12 {
            self.record_errno(pc, request, 22);
            self.regs[0] = negative_errno(22);
            return;
        }
        match broker.dispatch(&request) {
            Ok(BrokerValue::Bytes(bytes)) if bytes.len() == 12 => {
                if self.memory.write(value_address, &bytes).is_err()
                    || self
                        .memory
                        .write(length_address, &12u32.to_le_bytes())
                        .is_err()
                {
                    self.record_errno(pc, request, 14);
                    self.regs[0] = negative_errno(14);
                    return;
                }
                self.events.push(ElfSyscallEvent {
                    step: self.instructions,
                    pc,
                    syscall: request,
                    result: Ok(BrokerValue::Bytes(bytes)),
                });
                self.regs[0] = 0;
            }
            Ok(_) => {
                self.record_errno(pc, request, 5);
                self.regs[0] = negative_errno(5);
            }
            Err(error) => {
                let errno = broker_errno(&error);
                self.record_errno(pc, request, errno);
                self.regs[0] = negative_errno(errno);
            }
        }
    }

    fn handle_poll_syscall(&mut self, broker: &SyscallBroker, pc: u32) {
        const MAX_POLL_FDS: usize = 1024;
        let address = self.regs[0];
        let nfds = self.regs[1] as usize;
        let timeout_ms = self.regs[2] as i32;
        if nfds > MAX_POLL_FDS {
            self.record_errno(
                pc,
                GuestSyscall::Control {
                    name: "poll".to_owned(),
                },
                22,
            );
            self.regs[0] = negative_errno(22);
            return;
        }
        let byte_count = nfds * 8;
        let mut poll_fds = if byte_count == 0 {
            Vec::new()
        } else {
            match self.memory.read(address, byte_count) {
                Ok(bytes) => bytes,
                Err(_) => {
                    self.record_errno(
                        pc,
                        GuestSyscall::Control {
                            name: "poll".to_owned(),
                        },
                        14,
                    );
                    self.regs[0] = negative_errno(14);
                    return;
                }
            }
        };
        let mut ready_descriptors = 0u32;
        for descriptor in poll_fds.chunks_exact_mut(8) {
            let fd = i32::from_le_bytes(descriptor[..4].try_into().expect("poll fd"));
            let requested = u16::from_le_bytes(descriptor[4..6].try_into().expect("poll events"));
            let revents = broker.poll_revents(fd, requested);
            descriptor[6..8].copy_from_slice(&revents.to_le_bytes());
            if revents != 0 {
                ready_descriptors += 1;
            }
        }
        if byte_count != 0 && self.memory.write(address, &poll_fds).is_err() {
            self.record_errno(
                pc,
                GuestSyscall::Control {
                    name: "poll".to_owned(),
                },
                14,
            );
            self.regs[0] = negative_errno(14);
            return;
        }
        if ready_descriptors != 0 {
            self.regs[0] = ready_descriptors;
        } else if timeout_ms < 0 {
            self.waiting_for_events = true;
            self.regs[0] = 0;
        } else {
            self.virtual_time_ns = self
                .virtual_time_ns
                .saturating_add((timeout_ms as u64).saturating_mul(1_000_000));
            self.regs[0] = 0;
        }
    }

    fn time_syscall_error(&mut self, pc: u32, number: u32, errno: i32) {
        self.record_errno(
            pc,
            GuestSyscall::Control {
                name: syscall_name(number),
            },
            errno,
        );
        self.regs[0] = negative_errno(errno);
    }

    fn record_errno(&mut self, pc: u32, syscall: GuestSyscall, errno: i32) {
        self.events.push(ElfSyscallEvent {
            step: self.instructions,
            pc,
            syscall,
            result: Err(errno),
        });
    }

    fn handle_legacy_sigaction(&mut self, pc: u32) {
        const SIGKILL: i32 = 9;
        const SIGSTOP: i32 = 19;
        const UNBLOCKABLE_SIGNAL_MASK: u32 = (1 << (SIGKILL - 1)) | (1 << (SIGSTOP - 1));

        let signal = self.regs[0] as i32;
        if !(1..=GINGERBREAD_SIGNAL_COUNT as i32).contains(&signal)
            || signal == SIGKILL
            || signal == SIGSTOP
        {
            self.record_errno(
                pc,
                GuestSyscall::Control {
                    name: "sigaction".to_owned(),
                },
                22,
            );
            self.regs[0] = negative_errno(22);
            return;
        }

        let action_address = self.regs[1];
        let old_action_address = self.regs[2];
        let action = if action_address == 0 {
            None
        } else {
            match self.memory.read(action_address, LEGACY_SIGACTION_SIZE) {
                Ok(bytes) => Some(LegacySignalAction::from_abi_bytes(&bytes)),
                Err(_) => {
                    self.record_errno(
                        pc,
                        GuestSyscall::Control {
                            name: "sigaction".to_owned(),
                        },
                        14,
                    );
                    self.regs[0] = negative_errno(14);
                    return;
                }
            }
        };

        if old_action_address != 0
            && self
                .memory
                .check_write(old_action_address, LEGACY_SIGACTION_SIZE)
                .is_err()
        {
            self.record_errno(
                pc,
                GuestSyscall::Control {
                    name: "sigaction".to_owned(),
                },
                14,
            );
            self.regs[0] = negative_errno(14);
            return;
        }

        let index = signal as usize;
        if old_action_address != 0
            && self
                .memory
                .write(
                    old_action_address,
                    &self.signal_actions[index].to_abi_bytes(),
                )
                .is_err()
        {
            self.record_errno(
                pc,
                GuestSyscall::Control {
                    name: "sigaction".to_owned(),
                },
                14,
            );
            self.regs[0] = negative_errno(14);
            return;
        }

        if let Some(mut action) = action {
            action.mask &= !UNBLOCKABLE_SIGNAL_MASK;
            self.signal_actions[index] = action;
        }
        self.regs[0] = 0;
    }

    fn read_c_string(&self, address: u32) -> Result<String, ElfError> {
        let mut bytes = Vec::new();
        for offset in 0..MAX_PATH_BYTES {
            let current = address
                .checked_add(offset as u32)
                .ok_or(ElfError::MemoryAccess {
                    address,
                    access: "read",
                })?;
            let byte = self.memory.read(current, 1)?[0];
            if byte == 0 {
                return String::from_utf8(bytes)
                    .map_err(|_| ElfError::Invalid("guest path is not UTF-8"));
            }
            bytes.push(byte);
        }
        Err(ElfError::Invalid(
            "guest path is not NUL-terminated within 4096 bytes",
        ))
    }

    fn read_unix_sockaddr(&self, address: u32, length: u32) -> Result<Vec<u8>, i32> {
        let length = length as usize;
        if !(3..=110).contains(&length) {
            return Err(22);
        }
        let bytes = self.memory.read(address, length).map_err(|_| 14)?;
        if u16::from_le_bytes([bytes[0], bytes[1]]) != 1 {
            return Err(97);
        }
        let path = &bytes[2..];
        if path[0] == 0 {
            return Ok(path.to_vec());
        }
        let path_length = path
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(path.len());
        if path_length == 0 {
            return Err(22);
        }
        Ok(path[..path_length].to_vec())
    }

    fn read_u32(&self, address: u32) -> Result<u32, ElfError> {
        let bytes = self.memory.read(address, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u16(&self, address: u32) -> Result<u16, ElfError> {
        let bytes = self.memory.read(address, 2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn set_nz(&mut self, value: u32) {
        self.n = value & 0x8000_0000 != 0;
        self.z = value == 0;
    }

    fn add_with_flags(&mut self, left: u32, right: u32, carry_in: bool) -> u32 {
        let sum = left as u64 + right as u64 + u64::from(carry_in);
        let result = sum as u32;
        self.set_nz(result);
        self.c = sum >> 32 != 0;
        self.v = (!(left ^ right) & (left ^ result) & 0x8000_0000) != 0;
        result
    }

    fn sub_with_flags(&mut self, left: u32, right: u32, carry_in: bool) -> u32 {
        let result = left.wrapping_add(!right).wrapping_add(u32::from(carry_in));
        self.set_nz(result);
        self.c = (left as u64) + (!right) as u64 + u64::from(carry_in) > u32::MAX as u64;
        self.v = ((left ^ right) & (left ^ result) & 0x8000_0000) != 0;
        result
    }

    fn advance_it_state(&mut self) {
        if self.it_state & 0x07 == 0 {
            self.it_state = 0;
        } else {
            self.it_state = (self.it_state & 0xe0) | ((self.it_state << 1) & 0x1f);
        }
    }

    fn condition_passed(&self, condition: u8) -> bool {
        match condition {
            0 => self.z,
            1 => !self.z,
            2 => self.c,
            3 => !self.c,
            4 => self.n,
            5 => !self.n,
            6 => self.v,
            7 => !self.v,
            8 => self.c && !self.z,
            9 => !self.c || self.z,
            10 => self.n == self.v,
            11 => self.n != self.v,
            12 => !self.z && self.n == self.v,
            13 => self.z || self.n != self.v,
            14 => true,
            _ => false,
        }
    }
}

fn read_guest_mapping_file(
    broker: &mut SyscallBroker,
    file_descriptor: i32,
    page_offset: u32,
    length: usize,
) -> Result<Vec<u8>, i32> {
    let start_offset = (page_offset as u64)
        .checked_mul(PAGE_SIZE as u64)
        .ok_or(22)?;
    let mut bytes = Vec::with_capacity(length);
    while bytes.len() < length {
        let count = (length - bytes.len()).min(MAX_TRANSFER_BYTES);
        let offset = start_offset.checked_add(bytes.len() as u64).ok_or(22)?;
        let chunk = broker
            .read_file_at(file_descriptor, offset, count)
            .map_err(|error| broker_errno(&error))?;
        let received = chunk.len();
        bytes.extend_from_slice(&chunk);
        if received < count {
            break;
        }
    }
    Ok(bytes)
}

fn sign_extend(value: u32, bits: u32) -> i32 {
    ((value << (32 - bits)) as i32) >> (32 - bits)
}

fn linux_open_flags(flags: u32) -> Option<OpenFlags> {
    const O_ACCMODE: u32 = 3;
    const O_CREAT: u32 = 0x40;
    const O_TRUNC: u32 = 0x200;
    const O_DIRECTORY: u32 = 0x1_0000;
    const O_LARGEFILE: u32 = 0x20000;
    const SUPPORTED: u32 = O_ACCMODE | O_CREAT | O_TRUNC | O_DIRECTORY | O_LARGEFILE;
    if flags & !SUPPORTED != 0 {
        return None;
    }
    let (read, write) = match flags & O_ACCMODE {
        0 => (true, false),
        1 => (false, true),
        2 => (true, true),
        _ => return None,
    };
    let create = flags & O_CREAT != 0;
    let truncate = flags & O_TRUNC != 0;
    if (create || truncate) && !write {
        return None;
    }
    Some(OpenFlags {
        read,
        write,
        create,
        truncate,
        directory: flags & O_DIRECTORY != 0,
    })
}

fn syscall_name(number: u32) -> String {
    match number {
        1 => "exit".into(),
        10 => "unlink".into(),
        14 => "mknod".into(),
        15 => "chmod".into(),
        45 => "brk".into(),
        19 => "lseek".into(),
        93 => "ftruncate".into(),
        281 => "socket".into(),
        282 => "bind".into(),
        284 => "listen".into(),
        285 => "accept".into(),
        292 => "recvfrom".into(),
        295 => "getsockopt".into(),
        288 => "socketpair".into(),
        78 => "gettimeofday".into(),
        162 => "nanosleep".into(),
        168 => "poll".into(),
        67 => "sigaction".into(),
        3 => "read".into(),
        4 => "write".into(),
        5 => "open".into(),
        6 => "close".into(),
        91 => "munmap".into(),
        125 => "mprotect".into(),
        192 => "mmap2".into(),
        195 => "stat64".into(),
        197 => "fstat64".into(),
        20 => "getpid".into(),
        21 => "mount".into(),
        39 => "mkdir".into(),
        60 => "umask".into(),
        63 => "dup2".into(),
        24 => "getuid".into(),
        199 => "getuid32".into(),
        26 => "ptrace".into(),
        47 => "getgid".into(),
        200 => "getgid32".into(),
        49 => "geteuid".into(),
        50 => "getegid".into(),
        201 => "geteuid32".into(),
        202 => "getegid32".into(),
        52 => "umount2".into(),
        217 => "getdents64".into(),
        218 => "pivot_root".into(),
        88 => "reboot".into(),
        224 => "gettid".into(),
        248 => "exit_group".into(),
        263 => "clock_gettime".into(),
        191 => "getrlimit".into(),
        322 => "openat".into(),
        ARM_NR_SET_TLS => "ARM_set_tls".into(),
        _ => format!("syscall_{number}"),
    }
}

fn broker_errno(error: &BrokerError) -> i32 {
    match error {
        BrokerError::InvalidArgument(_) => 22,     // EINVAL
        BrokerError::BadFileDescriptor(_) => 9,    // EBADF
        BrokerError::TransferTooLarge { .. } => 7, // E2BIG
        BrokerError::Denied(_) => 1,               // EPERM
        BrokerError::RootFs(RootFsError::InvalidGuestPath(_)) => 22,
        BrokerError::RootFs(RootFsError::EscapesRoot(_)) => 13, // EACCES
        BrokerError::RootFs(RootFsError::Io(error)) | BrokerError::Io(error) => {
            match error.raw_os_error() {
                Some(11) => 11,   // EAGAIN
                Some(2) => 2,     // ENOENT
                Some(9) => 9,     // EBADF
                Some(13) => 13,   // EACCES
                Some(17) => 17,   // EEXIST
                Some(16) => 16,   // EBUSY
                Some(22) => 22,   // EINVAL
                Some(19) => 19,   // ENODEV
                Some(20) => 20,   // ENOTDIR
                Some(21) => 21,   // EISDIR
                Some(29) => 29,   // ESPIPE
                Some(30) => 30,   // EROFS
                Some(88) => 88,   // ENOTSOCK
                Some(91) => 91,   // EPROTOTYPE
                Some(93) => 93,   // EPROTONOSUPPORT
                Some(97) => 97,   // EAFNOSUPPORT
                Some(107) => 107, // ENOTCONN
                _ => match error.kind() {
                    std::io::ErrorKind::NotFound => 2,          // ENOENT
                    std::io::ErrorKind::PermissionDenied => 13, // EACCES
                    std::io::ErrorKind::AlreadyExists => 17,    // EEXIST
                    std::io::ErrorKind::InvalidInput => 22,     // EINVAL
                    _ => 5,                                     // EIO
                },
            }
        }
    }
}

fn negative_errno(errno: i32) -> u32 {
    (-(errno as i64)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::VirtualIdentity;
    use crate::rootfs::RootFs;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const BASE: u32 = 0x0001_0000;
    // Gingerbread's private Bionic TLS ABI reserves 64 pointer-sized slots.
    const BIONIC_TLS_SLOTS: usize = 64;
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn test_broker(label: &str) -> (PathBuf, SyscallBroker) {
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let base =
            std::env::temp_dir().join(format!("gingervm-elf-{label}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let root = RootFs::open(base.join("root")).unwrap();
        root.initialize_layout().unwrap();
        let broker = SyscallBroker::new(
            root,
            VirtualIdentity {
                uid: 10042,
                gid: 10043,
                pid: 29,
            },
        );
        (base, broker)
    }

    fn put_u16_at(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32_at(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn make_elf(entry: u32, code_and_data: &[u8]) -> Vec<u8> {
        let file_offset = 0x100usize;
        let mut image = vec![0u8; file_offset + code_and_data.len()];
        image[0..4].copy_from_slice(b"\x7fELF");
        image[4] = ELFCLASS32;
        image[5] = ELFDATA2LSB;
        image[6] = 1;
        put_u16_at(&mut image, 16, ET_EXEC);
        put_u16_at(&mut image, 18, EM_ARM);
        put_u32_at(&mut image, 20, 1);
        put_u32_at(&mut image, 24, entry);
        put_u32_at(&mut image, 28, ELF_HEADER_SIZE as u32);
        put_u16_at(&mut image, 40, ELF_HEADER_SIZE as u16);
        put_u16_at(&mut image, 42, ELF_PROGRAM_HEADER_SIZE as u16);
        put_u16_at(&mut image, 44, 1);
        let ph = ELF_HEADER_SIZE;
        put_u32_at(&mut image, ph, PT_LOAD);
        put_u32_at(&mut image, ph + 4, file_offset as u32);
        put_u32_at(&mut image, ph + 8, BASE);
        put_u32_at(&mut image, ph + 12, BASE);
        put_u32_at(&mut image, ph + 16, code_and_data.len() as u32);
        put_u32_at(&mut image, ph + 20, code_and_data.len() as u32);
        put_u32_at(&mut image, ph + 24, PF_R | PF_W | PF_X);
        put_u32_at(&mut image, ph + 28, 4);
        image[file_offset..].copy_from_slice(code_and_data);
        image
    }

    #[test]
    fn cpu_memory_fault_reports_instruction_pc_registers_and_trace() {
        let mut code = Vec::new();
        for instruction in [0xe3a0_0000_u32, 0xe580_1008] {
            code.extend_from_slice(&instruction.to_le_bytes());
        }
        let image = make_elf(BASE, &code);
        let (base, mut broker) = test_broker("cpu-memory-fault-trace");

        let error = run_elf(&image, &mut broker, 8).unwrap_err();
        match error {
            ElfError::CpuMemoryFault {
                address,
                access,
                pc,
                instruction,
                instruction_set,
                registers,
                cpsr_nzcv,
                instructions,
                trace,
            } => {
                assert_eq!(address, 8);
                assert_eq!(access, "write");
                assert_eq!(pc, BASE + 4);
                assert_eq!(instruction, Some(0xe580_1008));
                assert_eq!(instruction_set, InstructionSet::Arm);
                assert_eq!(registers[0], 0);
                assert_eq!(registers[15], BASE + 12);
                assert_eq!(cpsr_nzcv, 0);
                assert_eq!(instructions, 2);
                assert!(trace.contains("#     1 ARM pc=0x00010000 instruction=0xe3a00000"));
                assert!(trace.contains("#     2 ARM pc=0x00010004 instruction=0xe5801008"));
            }
            other => panic!("expected a contextual CPU memory fault, got: {other}"),
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_getrlimit_stack_returns_the_mapped_guest_stack_limits() {
        let instructions = [
            0xe3a0_0003_u32, // mov r0, #RLIMIT_STACK
            0xe1a0_100d,     // mov r1, sp
            0xe3a0_70bf,     // mov r7, #191 (ugetrlimit)
            0xef00_0000,     // svc #0
            0xe591_2000,     // ldr r2, [r1] (rlim_cur)
            0xe300_3000,     // movw r3, #0
            0xe340_3002,     // movt r3, #2 (128 KiB)
            0xe152_0003,     // cmp r2, r3
            0x13a0_0001,     // movne r0, #1
            0xe591_2004,     // ldr r2, [r1, #4] (rlim_max)
            0xe152_0003,     // cmp r2, r3
            0x13a0_0001,     // movne r0, #1
            0xe3a0_7001,     // mov r7, #exit
            0xef00_0000,     // svc #0
        ];
        let code: Vec<u8> = instructions
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let image = make_elf(BASE, &code);
        let (base, mut broker) = test_broker("getrlimit-stack");

        let report = run_elf(&image, &mut broker, 32).unwrap();
        assert_eq!(report.stop_reason, ElfStopReason::GuestExited);
        assert_eq!(report.exit_code, 0);
        let call = report
            .syscall_trace
            .iter()
            .find(|call| call.number == 191)
            .expect("guest getrlimit call should be traced");
        assert_eq!(call.args[0], RLIMIT_STACK);
        assert_eq!(call.result, 0);
        let _ = fs::remove_dir_all(base);
    }

    fn make_pt_interp_elf(path: &str, code: &[u8]) -> Vec<u8> {
        let program_header_offset = ELF_HEADER_SIZE;
        let code_offset = 0x100;
        let interpreter_offset = code_offset + code.len();
        let mut interpreter_path = path.as_bytes().to_vec();
        interpreter_path.push(0);
        let image_size = interpreter_offset + interpreter_path.len();
        let mut image = vec![0_u8; image_size];
        image[0..4].copy_from_slice(b"\x7fELF");
        image[4] = ELFCLASS32;
        image[5] = ELFDATA2LSB;
        image[6] = 1;
        put_u16_at(&mut image, 16, ET_EXEC);
        put_u16_at(&mut image, 18, EM_ARM);
        put_u32_at(&mut image, 20, 1);
        put_u32_at(&mut image, 24, BASE + code_offset as u32);
        put_u32_at(&mut image, 28, program_header_offset as u32);
        put_u16_at(&mut image, 40, ELF_HEADER_SIZE as u16);
        put_u16_at(&mut image, 42, ELF_PROGRAM_HEADER_SIZE as u16);
        put_u16_at(&mut image, 44, 2);

        let load = program_header_offset;
        put_u32_at(&mut image, load, PT_LOAD);
        put_u32_at(&mut image, load + 4, 0);
        put_u32_at(&mut image, load + 8, BASE);
        put_u32_at(&mut image, load + 12, BASE);
        put_u32_at(&mut image, load + 16, image_size as u32);
        put_u32_at(&mut image, load + 20, image_size as u32);
        put_u32_at(&mut image, load + 24, PF_R | PF_W | PF_X);
        put_u32_at(&mut image, load + 28, PAGE_SIZE);

        let interp = load + ELF_PROGRAM_HEADER_SIZE;
        put_u32_at(&mut image, interp, PT_INTERP);
        put_u32_at(&mut image, interp + 4, interpreter_offset as u32);
        put_u32_at(&mut image, interp + 16, interpreter_path.len() as u32);
        put_u32_at(&mut image, interp + 28, 1);
        image[code_offset..code_offset + code.len()].copy_from_slice(code);
        image[interpreter_offset..].copy_from_slice(&interpreter_path);
        image
    }

    fn make_relative_dyn_elf() -> Vec<u8> {
        const DYNAMIC_OFFSET: usize = 64;
        const REL_OFFSET: usize = 96;
        let mut payload = vec![0_u8; 104];
        let instructions = [
            0xe59f_4000_u32, // ldr r4, [pc] -> relocated pointer literal at +8
            0xea00_0000,     // b to +12, skipping the literal
            BASE + 32,       // R_ARM_RELATIVE addend: address of the value below
            0xe594_2000,     // ldr r2, [r4]
            0xe352_002a,     // cmp r2, #42
            0x13a0_0001,     // movne r0, #1
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        for (index, instruction) in instructions.into_iter().enumerate() {
            put_u32_at(&mut payload, index * 4, instruction);
        }
        put_u32_at(&mut payload, 32, 42);
        put_u32_at(&mut payload, DYNAMIC_OFFSET, DT_REL);
        put_u32_at(&mut payload, DYNAMIC_OFFSET + 4, BASE + REL_OFFSET as u32);
        put_u32_at(&mut payload, DYNAMIC_OFFSET + 8, DT_RELSZ);
        put_u32_at(&mut payload, DYNAMIC_OFFSET + 12, 8);
        put_u32_at(&mut payload, DYNAMIC_OFFSET + 16, DT_RELENT);
        put_u32_at(&mut payload, DYNAMIC_OFFSET + 20, 8);
        put_u32_at(&mut payload, DYNAMIC_OFFSET + 24, DT_NULL);
        put_u32_at(&mut payload, DYNAMIC_OFFSET + 28, 0);
        put_u32_at(&mut payload, REL_OFFSET, BASE + 8);
        put_u32_at(&mut payload, REL_OFFSET + 4, R_ARM_RELATIVE);

        let mut image = make_elf(BASE, &payload);
        put_u16_at(&mut image, 16, ET_DYN);
        put_u16_at(&mut image, 44, 2);
        let dynamic_header = ELF_HEADER_SIZE + ELF_PROGRAM_HEADER_SIZE;
        put_u32_at(&mut image, dynamic_header, PT_DYNAMIC);
        put_u32_at(
            &mut image,
            dynamic_header + 4,
            (0x100 + DYNAMIC_OFFSET) as u32,
        );
        put_u32_at(&mut image, dynamic_header + 8, BASE + DYNAMIC_OFFSET as u32);
        put_u32_at(
            &mut image,
            dynamic_header + 12,
            BASE + DYNAMIC_OFFSET as u32,
        );
        put_u32_at(&mut image, dynamic_header + 16, 32);
        put_u32_at(&mut image, dynamic_header + 20, 32);
        put_u32_at(&mut image, dynamic_header + 24, PF_R | PF_W);
        put_u32_at(&mut image, dynamic_header + 28, 4);
        image
    }

    #[test]
    fn guest_memory_accesses_can_cross_adjacent_segments() {
        let mut memory = GuestMemory::new(vec![
            Segment {
                start: 0x1000,
                bytes: vec![1, 2],
                flags: PF_R | PF_W,
                fault_after: None,
            },
            Segment {
                start: 0x1002,
                bytes: vec![3, 4],
                flags: PF_R | PF_W,
                fault_after: None,
            },
        ]);
        assert_eq!(memory.read(0x1001, 3).unwrap(), [2, 3, 4]);
        memory.write(0x1001, &[9, 8, 7]).unwrap();
        assert_eq!(memory.read(0x1000, 4).unwrap(), [1, 9, 8, 7]);
        assert!(memory.read(0x0fff, 2).is_err());
        assert!(checked_memory_end(u32::MAX - 3, 4, "read").is_ok());
        assert!(checked_memory_end(u32::MAX - 3, 5, "read").is_err());
    }

    #[test]
    fn image_copy_writer_crosses_adjacent_segments_without_partial_failure_writes() {
        let mut segments = vec![
            Segment {
                start: 0x2000,
                bytes: vec![1, 2],
                flags: PF_R | PF_W,
                fault_after: None,
            },
            Segment {
                start: 0x2002,
                bytes: vec![3, 4],
                flags: PF_R | PF_W,
                fault_after: None,
            },
        ];

        write_image_bytes(&mut segments, 0x2001, &[9, 8, 7]).unwrap();
        assert_eq!(
            read_image_bytes(&segments, 0x2000, 4).unwrap(),
            [1, 9, 8, 7]
        );
        assert!(write_image_bytes(&mut segments, 0x2003, &[6, 5]).is_err());
        assert_eq!(
            read_image_bytes(&segments, 0x2000, 4).unwrap(),
            [1, 9, 8, 7]
        );
    }

    #[test]
    fn guest_memory_mapping_protect_and_unmap_preserve_neighbor_pages() {
        let mut memory = GuestMemory::new(Vec::new());
        memory
            .map_zeroed(MMAP_BASE, PAGE_SIZE as usize * 3, PF_R | PF_W)
            .unwrap();
        memory.write(MMAP_BASE, &[0x11]).unwrap();
        memory.write(MMAP_BASE + PAGE_SIZE, &[0x22]).unwrap();
        memory.write(MMAP_BASE + PAGE_SIZE * 2, &[0x33]).unwrap();

        memory
            .protect(MMAP_BASE + PAGE_SIZE, PAGE_SIZE as usize, PF_R)
            .unwrap();
        assert_eq!(memory.read(MMAP_BASE + PAGE_SIZE, 1).unwrap(), [0x22]);
        assert!(memory.write(MMAP_BASE + PAGE_SIZE, &[0]).is_err());
        assert!(memory.write(MMAP_BASE, &[0x44]).is_ok());

        memory.unmap(MMAP_BASE + PAGE_SIZE, PAGE_SIZE as usize);
        assert!(!memory.is_page_range_mapped(MMAP_BASE + PAGE_SIZE, PAGE_SIZE as usize));
        assert!(memory.is_page_range_mapped(MMAP_BASE, PAGE_SIZE as usize));
        assert!(memory.is_page_range_mapped(MMAP_BASE + PAGE_SIZE * 2, PAGE_SIZE as usize));
        assert!(memory.read(MMAP_BASE, PAGE_SIZE as usize * 3).is_err());

        memory
            .map_zeroed(MMAP_BASE + PAGE_SIZE, PAGE_SIZE as usize, PF_R | PF_W)
            .unwrap();
        assert_eq!(memory.read(MMAP_BASE + PAGE_SIZE, 4).unwrap(), [0; 4]);
    }

    #[test]
    fn guest_memory_mprotect_accepts_mapped_pages_with_unmapped_byte_gaps() {
        let mut memory = GuestMemory::new(vec![
            Segment {
                start: MMAP_BASE,
                bytes: vec![0x11; 128],
                flags: PF_R | PF_W,
                fault_after: None,
            },
            Segment {
                start: MMAP_BASE + PAGE_SIZE,
                bytes: vec![0x22; 256],
                flags: PF_R | PF_W,
                fault_after: None,
            },
        ]);

        memory
            .protect(MMAP_BASE, PAGE_SIZE as usize * 2, PF_R)
            .unwrap();
        assert_eq!(memory.read(MMAP_BASE, 1).unwrap(), [0x11]);
        assert_eq!(memory.read(MMAP_BASE + PAGE_SIZE, 1).unwrap(), [0x22]);
        assert!(memory.write(MMAP_BASE, &[0]).is_err());
        assert!(memory.write(MMAP_BASE + PAGE_SIZE, &[0]).is_err());
    }

    #[test]
    fn guest_memory_mprotect_rejects_a_truly_unmapped_page_without_partial_changes() {
        let mut memory = GuestMemory::new(vec![
            Segment {
                start: MMAP_BASE,
                bytes: vec![0x11; 128],
                flags: PF_R | PF_W,
                fault_after: None,
            },
            Segment {
                start: MMAP_BASE + PAGE_SIZE * 2,
                bytes: vec![0x22; 256],
                flags: PF_R | PF_W,
                fault_after: None,
            },
        ]);

        assert!(memory
            .protect(MMAP_BASE, PAGE_SIZE as usize * 3, PF_R)
            .is_err());
        assert!(memory.write(MMAP_BASE, &[0]).is_ok());
        assert!(memory.write(MMAP_BASE + PAGE_SIZE * 2, &[0]).is_ok());
    }

    #[test]
    fn file_mapping_zeroes_the_eof_page_tail_and_faults_after_it() {
        let mut memory = GuestMemory::new(Vec::new());
        let page = PAGE_SIZE as usize;
        let file_bytes = vec![0x41; page]
            .into_iter()
            .chain([0x42])
            .collect::<Vec<_>>();
        memory
            .map_file_bytes(MMAP_BASE, page * 3, &file_bytes, PF_R | PF_W)
            .unwrap();
        assert_eq!(
            memory.read(MMAP_BASE + PAGE_SIZE - 1, 3).unwrap(),
            [0x41, 0x42, 0]
        );
        assert!(memory.is_page_range_mapped(MMAP_BASE + PAGE_SIZE * 2, page));
        assert!(memory.read(MMAP_BASE + PAGE_SIZE * 2, 1).is_err());
        assert!(memory.write(MMAP_BASE + PAGE_SIZE * 2, &[0]).is_err());

        memory.unmap(MMAP_BASE, page);
        memory.protect(MMAP_BASE + PAGE_SIZE, page, PF_R).unwrap();
        assert_eq!(memory.read(MMAP_BASE + PAGE_SIZE, 1).unwrap(), [0x42]);
        assert!(memory.write(MMAP_BASE + PAGE_SIZE, &[0]).is_err());
        assert!(memory.read(MMAP_BASE + PAGE_SIZE * 2, 1).is_err());
    }

    #[test]
    fn mmap_allocator_honors_free_hints_and_skips_occupied_ranges() {
        let mut memory = GuestMemory::new(Vec::new());
        memory
            .map_zeroed(MMAP_BASE, PAGE_SIZE as usize, PF_R | PF_W)
            .unwrap();
        assert_eq!(
            memory.find_free_mapping(MMAP_BASE, PAGE_SIZE as usize),
            Some(MMAP_BASE + PAGE_SIZE)
        );
        assert_eq!(
            memory.find_free_mapping(MMAP_BASE + PAGE_SIZE * 4, PAGE_SIZE as usize),
            Some(MMAP_BASE + PAGE_SIZE * 4)
        );
        assert_eq!(page_rounded_length(1), Some(PAGE_SIZE as usize));
        assert_eq!(page_rounded_length(0), Some(0));
    }

    fn emit_thumb(code: &mut Vec<u8>, instruction: u16) {
        code.extend_from_slice(&instruction.to_le_bytes());
    }

    fn emit_movs(code: &mut Vec<u8>, rd: u8, immediate: u8) {
        emit_thumb(code, 0x2000 | ((rd as u16) << 8) | immediate as u16);
    }

    fn emit_mov_reg(code: &mut Vec<u8>, rd: u8, rm: u8) {
        let high_rd = ((rd as u16) & 8) << 4;
        emit_thumb(
            code,
            0x4600 | high_rd | (((rm as u16) & 0xf) << 3) | (rd as u16 & 7),
        );
    }

    fn emit_ldr_literal(
        code: &mut Vec<u8>,
        rd: u8,
        fixups: &mut Vec<(usize, u8, &'static str)>,
        label: &'static str,
    ) {
        let offset = code.len();
        emit_thumb(code, 0x4800 | ((rd as u16) << 8));
        fixups.push((offset, rd, label));
    }

    fn make_thumb_broker_probe() -> Vec<u8> {
        let mut code = Vec::new();
        let mut fixups = Vec::new();
        emit_ldr_literal(&mut code, 0, &mut fixups, "path");
        emit_ldr_literal(&mut code, 1, &mut fixups, "flags");
        emit_ldr_literal(&mut code, 2, &mut fixups, "mode");
        emit_movs(&mut code, 7, 5); // open
        emit_thumb(&mut code, 0xdf00);
        emit_mov_reg(&mut code, 4, 0);
        emit_ldr_literal(&mut code, 1, &mut fixups, "payload");
        emit_movs(&mut code, 2, 15);
        emit_mov_reg(&mut code, 0, 4);
        emit_movs(&mut code, 7, 4); // write
        emit_thumb(&mut code, 0xdf00);
        emit_mov_reg(&mut code, 0, 4);
        emit_movs(&mut code, 7, 6); // close
        emit_thumb(&mut code, 0xdf00);
        emit_ldr_literal(&mut code, 0, &mut fixups, "path");
        emit_movs(&mut code, 1, 0);
        emit_movs(&mut code, 7, 5); // open read-only
        emit_thumb(&mut code, 0xdf00);
        emit_mov_reg(&mut code, 4, 0);
        emit_ldr_literal(&mut code, 1, &mut fixups, "buffer");
        emit_movs(&mut code, 2, 64);
        emit_mov_reg(&mut code, 0, 4);
        emit_movs(&mut code, 7, 3); // read
        emit_thumb(&mut code, 0xdf00);
        emit_mov_reg(&mut code, 0, 4);
        emit_movs(&mut code, 7, 6); // close
        emit_thumb(&mut code, 0xdf00);
        emit_movs(&mut code, 7, 199); // getuid32 (Android ARM EABI)
        emit_thumb(&mut code, 0xdf00);
        emit_movs(&mut code, 7, 200); // getgid32
        emit_thumb(&mut code, 0xdf00);
        emit_movs(&mut code, 7, 20); // getpid
        emit_thumb(&mut code, 0xdf00);
        emit_movs(&mut code, 0, 0);
        emit_movs(&mut code, 7, 1); // exit(0)
        emit_thumb(&mut code, 0xdf00);

        while code.len() % 4 != 0 {
            emit_thumb(&mut code, 0xbf00);
        }
        let literal_offset = code.len();
        let labels = [
            ("path", 0u32),
            ("flags", 577u32),
            ("mode", 0o600u32),
            ("payload", 0u32),
            ("buffer", 0u32),
        ];
        for (_, value) in labels {
            code.extend_from_slice(&value.to_le_bytes());
        }
        let path_offset = code.len();
        code.extend_from_slice(b"/tmp/real-elf.txt\0");
        let payload_offset = code.len();
        code.extend_from_slice(b"Thumb guest OK\n");
        let buffer_offset = code.len();
        code.extend_from_slice(&[0; 64]);

        for (index, name) in ["path", "flags", "mode", "payload", "buffer"]
            .iter()
            .enumerate()
        {
            let value = match *name {
                "path" => BASE + path_offset as u32,
                "flags" => 577,
                "mode" => 0o600,
                "payload" => BASE + payload_offset as u32,
                "buffer" => BASE + buffer_offset as u32,
                _ => unreachable!(),
            };
            let offset = literal_offset + index * 4;
            code[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (instruction_offset, rd, label) in fixups {
            let label_index = match label {
                "path" => 0,
                "flags" => 1,
                "mode" => 2,
                "payload" => 3,
                "buffer" => 4,
                _ => unreachable!(),
            };
            let literal_address = BASE + (literal_offset + label_index * 4) as u32;
            let instruction_address = BASE + instruction_offset as u32;
            let pc_base = instruction_address.wrapping_add(4) & !3;
            let displacement = literal_address - pc_base;
            assert_eq!(displacement % 4, 0);
            assert!(displacement / 4 <= 255);
            let instruction = 0x4800 | ((rd as u16) << 8) | (displacement / 4) as u16;
            code[instruction_offset..instruction_offset + 2]
                .copy_from_slice(&instruction.to_le_bytes());
        }
        code
    }

    #[test]
    fn thumb_elf_executes_real_instructions_and_routes_file_syscalls_through_broker() {
        let (base, mut broker) = test_broker("thumb");
        let image = make_elf(BASE | 1, &make_thumb_broker_probe());
        let report = run_elf(&image, &mut broker, 256).unwrap();
        assert_eq!(report.instruction_set, InstructionSet::Thumb);
        assert_eq!(report.exit_code, 0);
        assert!(report.instructions_executed > 20);
        assert_eq!(report.events.len(), 9);
        assert_eq!(report.events[0].syscall.name(), "open");
        assert_eq!(report.events[1].syscall.name(), "write");
        assert_eq!(report.events[3].syscall.name(), "open");
        assert_eq!(report.events[4].syscall.name(), "read");
        assert_eq!(
            report.events[4].result,
            Ok(BrokerValue::Bytes(b"Thumb guest OK\n".to_vec()))
        );
        assert_eq!(report.events[6].result, Ok(BrokerValue::Identity(10042)));
        assert_eq!(report.events[7].result, Ok(BrokerValue::Identity(10043)));
        assert_eq!(report.events[8].result, Ok(BrokerValue::Identity(29)));
        assert!(broker.rootfs().root().join("tmp/real-elf.txt").exists());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_push_stores_low_high_and_lr_registers_in_address_order() {
        let (base, mut broker) = test_broker("thumb2-wide-push");
        let mut code = Vec::new();
        for register in 4..=7 {
            emit_movs(&mut code, register, register);
        }
        for (destination, source) in [(8, 4), (9, 5), (10, 6), (11, 7)] {
            emit_mov_reg(&mut code, destination, source);
        }
        emit_movs(&mut code, 0, 12);
        emit_mov_reg(&mut code, 14, 0); // lr = 12
        emit_thumb(&mut code, 0xe92d); // push.w {r4-r11, lr}
        emit_thumb(&mut code, 0x4ff0);

        let expected = [4_u8, 5, 6, 7, 4, 5, 6, 7, 12];
        let mut failure_branches = Vec::new();
        for (slot, value) in expected.into_iter().enumerate() {
            emit_thumb(&mut code, 0x9800 | slot as u16); // ldr r0, [sp, #slot * 4]
            emit_thumb(&mut code, 0x2800 | value as u16); // cmp r0, #value
            failure_branches.push(code.len());
            emit_thumb(&mut code, 0xd100); // bne failure (patched below)
        }

        emit_movs(&mut code, 0, 0);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00); // exit(0)
        let failure_offset = code.len();
        emit_movs(&mut code, 0, 1);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00); // exit(1)

        for branch_offset in failure_branches {
            let displacement = failure_offset as i32 - (branch_offset as i32 + 4);
            assert!(displacement >= 0 && displacement <= 254 && displacement % 2 == 0);
            let branch = 0xd100 | (displacement / 2) as u16;
            code[branch_offset..branch_offset + 2].copy_from_slice(&branch.to_le_bytes());
        }

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 64).unwrap();
        assert_eq!(report.instructions_executed, 41);
        assert_eq!(report.exit_code, 0);
        assert!(report.events.is_empty());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_push_rejects_empty_sp_and_pc_register_lists() {
        let (base, mut broker) = test_broker("thumb2-wide-push-invalid");
        for register_list in [0, 1 << 13, 1 << 15] {
            let mut code = Vec::new();
            emit_thumb(&mut code, 0xe92d);
            emit_thumb(&mut code, register_list);
            let image = make_elf(BASE | 1, &code);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    instruction: 0xe92d,
                    thumb: true
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_ldr_literal_loads_real_positive_and_negative_pc_offsets() {
        let (base, mut broker) = test_broker("thumb2-wide-ldr-literal");

        // The positive instruction is the exact LDR.W r9, [pc, #0x25c]
        // encoding observed immediately after the Gingerbread linker's PUSH.W.
        let mut positive = Vec::new();
        emit_thumb(&mut positive, 0xf8df);
        emit_thumb(&mut positive, 0x925c);
        emit_mov_reg(&mut positive, 0, 9);
        emit_movs(&mut positive, 7, 1);
        emit_thumb(&mut positive, 0xdf00);
        positive.resize(0x260, 0);
        positive.extend_from_slice(&0xcafe_babe_u32.to_le_bytes());
        let image = make_elf(BASE | 1, &positive);
        let report = run_elf(&image, &mut broker, 8).unwrap();
        assert_eq!(report.instructions_executed, 4);
        assert_eq!(report.exit_code as u32, 0xcafe_babe);

        // Exercise U=0 with an entry at BASE + 4: Align(PC, 4) - 8 == BASE.
        let mut negative = 0xcafe_babe_u32.to_le_bytes().to_vec();
        emit_thumb(&mut negative, 0xf85f);
        emit_thumb(&mut negative, 0x9008);
        emit_mov_reg(&mut negative, 0, 9);
        emit_movs(&mut negative, 7, 1);
        emit_thumb(&mut negative, 0xdf00);
        let image = make_elf((BASE + 4) | 1, &negative);
        let report = run_elf(&image, &mut broker, 8).unwrap();
        assert_eq!(report.instructions_executed, 4);
        assert_eq!(report.exit_code as u32, 0xcafe_babe);

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_ldr_literal_rejects_sp_and_pc_destinations() {
        let (base, mut broker) = test_broker("thumb2-wide-ldr-literal-invalid");
        for destination in [13_u16, 15] {
            let mut code = Vec::new();
            emit_thumb(&mut code, 0xf8df);
            emit_thumb(&mut code, destination << 12);
            let image = make_elf(BASE | 1, &code);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    instruction: 0xf8df,
                    thumb: true
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_ldr_register_uses_base_plus_shifted_register_offset() {
        let (base, mut broker) = test_broker("thumb2-wide-ldr-register");
        for (register_offset, second_halfword) in [(4_u8, 0x2009_u16), (1, 0x2029)] {
            let mut code = Vec::new();
            emit_thumb(&mut code, 0x4d07); // ldr r5, [pc, #28] -> BASE + 0x80
            emit_movs(&mut code, 3, register_offset);
            emit_mov_reg(&mut code, 9, 3);
            emit_thumb(&mut code, 0xf855); // ldr.w r2, [r5, r9, LSL #imm2]
            emit_thumb(&mut code, second_halfword);
            emit_mov_reg(&mut code, 0, 2);
            emit_movs(&mut code, 7, 1);
            emit_thumb(&mut code, 0xdf00); // exit with the loaded value

            code.resize(0x20, 0);
            code.extend_from_slice(&(BASE + 0x80).to_le_bytes());
            code.resize(0x80, 0);
            code.extend_from_slice(&0x1122_3344_u32.to_le_bytes());
            code.extend_from_slice(&0xcafe_babe_u32.to_le_bytes());

            let image = make_elf(BASE | 1, &code);
            let report = run_elf(&image, &mut broker, 16).unwrap();
            assert_eq!(report.instructions_executed, 7);
            assert_eq!(report.exit_code as u32, 0xcafe_babe);
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_ldrb_register_loads_linker_byte_and_rejects_invalid_forms() {
        let (base, mut broker) = test_broker("thumb2-wide-ldrb-register");
        let mut code = Vec::new();
        emit_thumb(&mut code, 0x4d07); // ldr r5, [pc, #28] -> byte-array address
        emit_movs(&mut code, 3, 3);
        emit_mov_reg(&mut code, 9, 3);
        emit_thumb(&mut code, 0xf815); // linker: ldrb.w r12, [r5, r9]
        emit_thumb(&mut code, 0xc009);
        emit_mov_reg(&mut code, 0, 12);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);
        code.resize(0x20, 0);
        code.extend_from_slice(&(BASE + 0x80).to_le_bytes());
        code.resize(0x80, 0);
        code.extend_from_slice(&[0x11, 0x22, 0x33, 0xfe]);

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 12).unwrap();
        assert_eq!(report.instructions_executed, 7);
        assert_eq!(report.exit_code, 0xfe);

        for (first, second) in [
            (0xf815_u16, 0xd009_u16), // SP destination
            (0xf815, 0xf009),         // PC destination
            (0xf81f, 0xc009),         // PC base
            (0xf815, 0xc00f),         // PC offset register
            (0xf815, 0xc049),         // reserved field
        ] {
            let mut invalid = Vec::new();
            emit_thumb(&mut invalid, first);
            emit_thumb(&mut invalid, second);
            let image = make_elf(BASE | 1, &invalid);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    thumb: true,
                    ..
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_ldr_post_index_loads_old_word_and_writes_back_base() {
        let (base, mut broker) = test_broker("thumb2-wide-ldr-post-index");
        let destination_offset = 0x100_u32;
        let destination_address = BASE + destination_offset;
        let mut code = Vec::new();
        emit_thumb(&mut code, 0x4a07); // ldr r2, [pc, #28] -> data address
        emit_thumb(&mut code, 0xf852); // linker: ldr r4, [r2], #4
        emit_thumb(&mut code, 0x4b04);
        emit_thumb(&mut code, 0x2c07); // cmp r4, #7
        emit_thumb(&mut code, 0xd102); // bne failure
        emit_thumb(&mut code, 0x6810); // ldr r0, [r2] -> second word after writeback
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);
        emit_movs(&mut code, 0, 9); // failure result
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);

        code.resize(0x20, 0);
        code.extend_from_slice(&destination_address.to_le_bytes());
        code.resize(destination_offset as usize, 0);
        code.extend_from_slice(&7_u32.to_le_bytes());
        code.extend_from_slice(&42_u32.to_le_bytes());

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();
        assert_eq!(report.instructions_executed, 7);
        assert_eq!(report.exit_code, 42);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_ldr_register_rejects_reserved_fields_and_pc_registers() {
        let (base, mut broker) = test_broker("thumb2-wide-ldr-register-invalid");
        for (first, second) in [
            (0xf855_u16, 0x2049_u16), // nonzero reserved field
            (0xf855, 0xd009),         // SP destination
            (0xf855, 0xf009),         // PC destination
            (0xf855, 0x200f),         // PC offset register
            (0xf852, 0xdb04),         // post-index SP destination
            (0xf852, 0xfb04),         // post-index PC destination
            (0xf854, 0x4b04),         // post-index destination aliases writeback base
        ] {
            let mut code = Vec::new();
            emit_thumb(&mut code, first);
            emit_thumb(&mut code, second);
            let image = make_elf(BASE | 1, &code);
            assert!(
                matches!(
                    run_elf(&image, &mut broker, 4),
                    Err(ElfError::InvalidInstruction {
                        pc: BASE,
                        thumb: true,
                        ..
                    })
                ),
                "unexpectedly accepted LDR encoding {first:#06x} {second:#06x}"
            );
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_str_register_stores_linker_encoding_to_guest_memory() {
        let (base, mut broker) = test_broker("thumb2-wide-str-register");
        let destination_offset = 0x100_u32;
        let destination_address = BASE + destination_offset;
        let mut code = Vec::new();
        emit_thumb(&mut code, 0x4807); // ldr r0, [pc, #28] -> destination
        emit_movs(&mut code, 3, 1);
        emit_movs(&mut code, 5, 0x5a);
        emit_thumb(&mut code, 0xf840); // linker: str.w r5, [r0, r3, lsl #2]
        emit_thumb(&mut code, 0x5023);
        emit_thumb(&mut code, 0xf850); // reload the stored word
        emit_thumb(&mut code, 0x2023);
        emit_mov_reg(&mut code, 0, 2);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);

        code.resize(0x20, 0);
        code.extend_from_slice(&destination_address.to_le_bytes());
        code.resize(destination_offset as usize + 8, 0);

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 12).unwrap();
        assert_eq!(report.instructions_executed, 8);
        assert_eq!(report.exit_code, 0x5a);

        for (first, second) in [
            (0xf840_u16, 0x5049_u16), // nonzero reserved field
            (0xf840, 0xd023),         // SP source
            (0xf840, 0xf023),         // PC source
            (0xf84f, 0x5023),         // PC base
            (0xf840, 0x502f),         // PC offset register
        ] {
            let mut invalid = Vec::new();
            emit_thumb(&mut invalid, first);
            emit_thumb(&mut invalid, second);
            let image = make_elf(BASE | 1, &invalid);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    thumb: true,
                    ..
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb_modified_immediate_expansion_covers_replicated_and_rotated_forms() {
        assert_eq!(
            Cpu::thumb_expand_modified_immediate(0x008),
            Some(0x0000_0008)
        );
        assert_eq!(
            Cpu::thumb_expand_modified_immediate(0x1ff),
            Some(0x00ff_00ff)
        );
        assert_eq!(
            Cpu::thumb_expand_modified_immediate(0x2ff),
            Some(0xff00_ff00)
        );
        assert_eq!(Cpu::thumb_expand_modified_immediate(0x3ff), Some(u32::MAX));
        assert_eq!(
            Cpu::thumb_expand_modified_immediate(0xe4a),
            Some(0x0000_0ca0)
        );
        assert_eq!(Cpu::thumb_expand_modified_immediate(0x000), None);
        assert_eq!(Cpu::thumb_expand_modified_immediate(0x100), None);
    }

    #[test]
    fn thumb2_wide_add_modified_immediate_executes_observed_rotated_constant() {
        let (base, mut broker) = test_broker("thumb2-wide-add-modified-immediate");
        let mut code = Vec::new();
        emit_movs(&mut code, 4, 3);
        emit_thumb(&mut code, 0xf504); // add.w r0, r4, #0xca0
        emit_thumb(&mut code, 0x604a);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00); // exit(0xca3)

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 8).unwrap();
        assert_eq!(report.instructions_executed, 4);
        assert_eq!(report.exit_code, 0x0ca3);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_adds_modified_immediate_sets_zero_and_carry_flags() {
        let (base, mut broker) = test_broker("thumb2-wide-adds-modified-immediate");
        let mut code = Vec::new();
        emit_movs(&mut code, 0, 0);
        emit_thumb(&mut code, 0x381c); // subs r0, #28 -> 0xffffffe4
        emit_thumb(&mut code, 0xf110); // linker: adds.w r3, r0, #0x1c
        emit_thumb(&mut code, 0x031c);
        emit_thumb(&mut code, 0xd103); // bne failure
        emit_thumb(&mut code, 0xd302); // bcc failure
        emit_movs(&mut code, 0, 7);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);
        emit_movs(&mut code, 0, 9); // failure result
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();
        assert_eq!(report.instructions_executed, 8);
        assert_eq!(report.exit_code, 7);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_lsls_register_executes_linker_encoding_and_sets_zero_and_carry() {
        let (base, mut broker) = test_broker("thumb2-lsls-register");
        let mut code = Vec::new();
        emit_movs(&mut code, 6, 1);
        emit_movs(&mut code, 0, 32);
        emit_thumb(&mut code, 0xfa16); // linker: lsls.w r0, r6, r0
        emit_thumb(&mut code, 0xf000);
        emit_thumb(&mut code, 0xd103); // bne failure
        emit_thumb(&mut code, 0xd302); // bcc failure
        emit_movs(&mut code, 0, 7);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);
        emit_movs(&mut code, 0, 9); // failure result
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();
        assert_eq!(report.instructions_executed, 8);
        assert_eq!(report.exit_code, 7);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_bfi_bfc_ubfx_execute_linker_encodings_and_reject_invalid_fields() {
        let (base, mut broker) = test_broker("thumb2-bitfield-linker-encodings");

        let mut bfi = Vec::new();
        emit_movs(&mut bfi, 5, 0xff);
        emit_movs(&mut bfi, 1, 2);
        emit_thumb(&mut bfi, 0xf361); // linker: bfi r5, r1, #1, #7
        emit_thumb(&mut bfi, 0x0547);
        emit_mov_reg(&mut bfi, 0, 5);
        emit_movs(&mut bfi, 7, 1);
        emit_thumb(&mut bfi, 0xdf00);

        let mut bfc = Vec::new();
        emit_movs(&mut bfc, 2, 0xff);
        emit_thumb(&mut bfc, 0xf36f); // linker: bfc r2, #0, #1
        emit_thumb(&mut bfc, 0x0200);
        emit_mov_reg(&mut bfc, 0, 2);
        emit_movs(&mut bfc, 7, 1);
        emit_thumb(&mut bfc, 0xdf00);

        let mut ubfx = Vec::new();
        emit_movs(&mut ubfx, 0, 0xff);
        emit_thumb(&mut ubfx, 0xf3c0); // linker: ubfx r0, r0, #1, #7
        emit_thumb(&mut ubfx, 0x0046);
        emit_movs(&mut ubfx, 7, 1);
        emit_thumb(&mut ubfx, 0xdf00);

        for (code, expected, steps) in [(&bfi, 5_u32, 6), (&bfc, 0xfe, 5), (&ubfx, 0x7f, 4)] {
            let image = make_elf(BASE | 1, code);
            let report = run_elf(&image, &mut broker, 8).unwrap();
            assert_eq!(report.instructions_executed, steps);
            assert_eq!(report.exit_code as u32, expected);
        }

        for (first, second) in [
            (0xf361_u16, 0x8547_u16), // reserved high bit
            (0xf361, 0x0527),         // reserved bit
            (0xf361, 0x0440),         // lsb exceeds msb
            (0xf36f, 0x0d00),         // SP destination
            (0xf3cf, 0x0046),         // PC source for UBFX
            (0xf3c0, 0x007f),         // extracted field extends past bit 31
        ] {
            let mut invalid = Vec::new();
            emit_thumb(&mut invalid, first);
            emit_thumb(&mut invalid, second);
            let image = make_elf(BASE | 1, &invalid);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    thumb: true,
                    ..
                })
            ));
        }

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_cmp_modified_immediate_executes_linker_encoding_and_sets_flags() {
        let (base, mut broker) = test_broker("thumb2-wide-cmp-modified-immediate");
        let mut code = Vec::new();
        emit_movs(&mut code, 2, 0);
        emit_thumb(&mut code, 0x3a01); // subs r2, #1 -> 0xffffffff
        emit_thumb(&mut code, 0xf1b2); // linker: cmp.w r2, #0xffffffff
        emit_thumb(&mut code, 0x3fff);
        emit_thumb(&mut code, 0xd103); // bne failure
        emit_thumb(&mut code, 0xd302); // bcc failure
        emit_movs(&mut code, 0, 7);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);
        emit_movs(&mut code, 0, 9); // failure result
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();
        assert_eq!(report.instructions_executed, 8);
        assert_eq!(report.exit_code, 7);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_rsbs_modified_immediate_sets_flags_for_linker_itlo() {
        let (base, mut broker) = test_broker("thumb2-wide-rsbs-modified-immediate");
        let mut code = Vec::new();
        emit_movs(&mut code, 2, 9);
        emit_movs(&mut code, 0, 2);
        emit_mov_reg(&mut code, 12, 0);
        emit_thumb(&mut code, 0xf1dc); // linker: rsbs.w r2, r12, #1
        emit_thumb(&mut code, 0x0201);
        emit_thumb(&mut code, 0xbf38); // it lo: 1 - 2 borrows, so execute MOVS
        emit_thumb(&mut code, 0x2200); // movs r2, #0
        emit_mov_reg(&mut code, 0, 2);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);
        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 12).unwrap();
        assert_eq!(report.instructions_executed, 9);
        assert_eq!(report.exit_code, 0);

        for (first, second) in [
            (0xf1dc_u16, 0x8201_u16), // reserved high bit
            (0xf1dc, 0x0d01),         // SP destination
            (0xf1dc, 0x0f01),         // PC destination
            (0xf1cf, 0x0201),         // PC base
        ] {
            let mut invalid = Vec::new();
            emit_thumb(&mut invalid, first);
            emit_thumb(&mut invalid, second);
            let image = make_elf(BASE | 1, &invalid);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    thumb: true,
                    ..
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_sub_modified_immediate_rejects_invalid_forms() {
        let (base, mut broker) = test_broker("thumb2-wide-sub-modified-immediate-invalid");
        for (first, second) in [
            (0xf1b2_u16, 0xbfff_u16), // reserved high bit
            (0xf1b2, 0x3dff),         // SP destination
            (0xf1bd, 0x7d04),         // flag-setting SP adjustment
            (0xf1a2, 0x3fff),         // PC destination without CMP flags
            (0xf1bf, 0x3fff),         // PC base
            (0xf1b2, 0x3000),         // zero replication encoding
        ] {
            let mut code = Vec::new();
            emit_thumb(&mut code, first);
            emit_thumb(&mut code, second);
            let image = make_elf(BASE | 1, &code);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    thumb: true,
                    ..
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_sub_adjusts_sp_by_linker_immediate() {
        let (base, mut broker) = test_broker("thumb2-wide-sub-sp-adjust");

        let mut baseline = Vec::new();
        emit_thumb(&mut baseline, 0xa800); // add r0, sp, #0
        emit_movs(&mut baseline, 7, 1);
        emit_thumb(&mut baseline, 0xdf00);
        let image = make_elf(BASE | 1, &baseline);
        let baseline_report = run_elf(&image, &mut broker, 8).unwrap();
        let initial_sp = baseline_report.exit_code as u32;

        let mut adjusted = Vec::new();
        emit_thumb(&mut adjusted, 0xf5ad); // linker: sub.w sp, sp, #0x210
        emit_thumb(&mut adjusted, 0x7d04);
        emit_thumb(&mut adjusted, 0xa800); // read back SP
        emit_movs(&mut adjusted, 7, 1);
        emit_thumb(&mut adjusted, 0xdf00);
        let image = make_elf(BASE | 1, &adjusted);
        let report = run_elf(&image, &mut broker, 8).unwrap();
        assert_eq!(report.instructions_executed, 4);
        assert_eq!(report.exit_code as u32, initial_sp.wrapping_sub(0x210));

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_add_modified_immediate_rejects_pc_and_unpredictable_forms() {
        let (base, mut broker) = test_broker("thumb2-wide-add-modified-immediate-invalid");
        for (first, second) in [
            (0xf100_u16, 0x8001_u16), // reserved high bit
            (0xf100, 0xd001),         // SP destination
            (0xf100, 0xf001),         // PC destination
            (0xf10f, 0x0001),         // PC base
            (0xf100, 0x0000),         // zero replication encoding
        ] {
            let mut code = Vec::new();
            emit_thumb(&mut code, first);
            emit_thumb(&mut code, second);
            let image = make_elf(BASE | 1, &code);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    thumb: true,
                    ..
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_add_shifted_register_executes_observed_and_unshifted_forms() {
        let (base, mut broker) = test_broker("thumb2-wide-add-shifted-register");
        for (second_halfword, expected) in [(0x0881_u16, 22_u32), (0x0801, 13)] {
            let mut code = Vec::new();
            emit_movs(&mut code, 0, 10);
            emit_movs(&mut code, 1, 3);
            emit_thumb(&mut code, 0xeb00); // add.w r8, r0, r1, lsl #imm
            emit_thumb(&mut code, second_halfword);
            emit_mov_reg(&mut code, 0, 8);
            emit_movs(&mut code, 7, 1);
            emit_thumb(&mut code, 0xdf00); // exit with the sum

            let image = make_elf(BASE | 1, &code);
            let report = run_elf(&image, &mut broker, 8).unwrap();
            assert_eq!(report.instructions_executed, 6);
            assert_eq!(report.exit_code as u32, expected);
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_lsrs_register_executes_linker_encoding_and_sets_zero_and_carry() {
        let (base, mut broker) = test_broker("thumb2-lsrs-register");
        let mut code = Vec::new();
        emit_movs(&mut code, 0, 1);
        emit_movs(&mut code, 3, 1);
        emit_thumb(&mut code, 0xfa30); // linker: lsrs.w r2, r0, r3
        emit_thumb(&mut code, 0xf203);
        emit_thumb(&mut code, 0xd103); // bne failure
        emit_thumb(&mut code, 0xd302); // bcc failure
        emit_movs(&mut code, 0, 7);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);
        emit_movs(&mut code, 0, 9); // failure result
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();
        assert_eq!(report.instructions_executed, 8);
        assert_eq!(report.exit_code, 7);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_wide_add_shifted_register_rejects_unimplemented_forms() {
        let (base, mut broker) = test_broker("thumb2-wide-add-shifted-register-invalid");
        for (first, second) in [
            (0xeb00_u16, 0x0891_u16), // LSR is outside this subset
            (0xeb0f, 0x0881),         // PC base
            (0xeb00, 0x088f),         // PC operand
            (0xeb00, 0x8881),         // reserved high bit
        ] {
            let mut code = Vec::new();
            emit_thumb(&mut code, first);
            emit_thumb(&mut code, second);
            let image = make_elf(BASE | 1, &code);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    thumb: true,
                    ..
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb_cbz_cbnz_take_and_skip_branches_based_on_register_value() {
        let (base, mut broker) = test_broker("thumb-cbz-cbnz");
        for (branch, initial, expected, instructions) in [
            (0xb100_u16, 0_u8, 0_u32, 4_u64), // cbz taken
            (0xb100, 1, 2, 5),                // cbz not taken
            (0xb900, 1, 1, 4),                // cbnz taken
            (0xb900, 0, 2, 5),                // cbnz not taken
        ] {
            let mut code = Vec::new();
            emit_movs(&mut code, 0, initial);
            emit_thumb(&mut code, branch); // zero-offset branch skips next movs
            emit_movs(&mut code, 0, 2);
            emit_movs(&mut code, 7, 1);
            emit_thumb(&mut code, 0xdf00);
            let image = make_elf(BASE | 1, &code);
            let report = run_elf(&image, &mut broker, 8).unwrap();
            assert_eq!(report.instructions_executed, instructions);
            assert_eq!(report.exit_code as u32, expected);
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb_cbz_uses_linker_forward_immediate_encoding() {
        let (base, mut broker) = test_broker("thumb-cbz-forward-immediate");
        for (initial, expected, instructions) in [(0_u8, 0_u32, 4_u64), (1, 2, 7)] {
            let mut code = Vec::new();
            emit_movs(&mut code, 0, initial);
            emit_thumb(&mut code, 0xb110); // cbz r0, +4; linker encoding
            emit_movs(&mut code, 0, 2);
            emit_thumb(&mut code, 0xbf00);
            emit_thumb(&mut code, 0xbf00);
            emit_movs(&mut code, 7, 1);
            emit_thumb(&mut code, 0xdf00);
            let image = make_elf(BASE | 1, &code);
            let report = run_elf(&image, &mut broker, 10).unwrap();
            assert_eq!(report.instructions_executed, instructions);
            assert_eq!(report.exit_code as u32, expected);
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_mla_executes_the_real_linker_encoding() {
        let (base, mut broker) = test_broker("thumb2-mla-linker-encoding");
        let mut code = Vec::new();
        emit_movs(&mut code, 0, 6);
        emit_mov_reg(&mut code, 14, 0); // lr = 6
        emit_movs(&mut code, 0, 7);
        emit_mov_reg(&mut code, 3, 0); // r3 = 7
        emit_movs(&mut code, 0, 10);
        emit_mov_reg(&mut code, 12, 0); // r12 = 10
        emit_thumb(&mut code, 0xfb0e); // mla r2, lr, r3, r12 (linker bytes)
        emit_thumb(&mut code, 0xc203);
        emit_mov_reg(&mut code, 0, 2);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);
        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();
        assert_eq!(report.instructions_executed, 10);
        assert_eq!(report.exit_code, 52);
        assert!(report.events.is_empty());
        let _ = fs::remove_dir_all(base);
    }
    #[test]
    fn thumb2_mla_rejects_mls_mul_alias_and_forbidden_registers() {
        let (base, mut broker) = test_broker("thumb2-mla-invalid");
        for (first, second) in [
            (0xfb0e_u16, 0xc213_u16), // MLS, not MLA.
            (0xfb0e, 0xf203),         // MUL alias, not MLA.
            (0xfb0e, 0xd203),         // SP accumulator.
            (0xfb0f, 0xc203),         // PC multiplicand.
            (0xfb0e, 0xc20f),         // PC multiplicand.
            (0xfb0e, 0xcd03),         // SP destination.
            (0xfb0e, 0xcf03),         // PC destination.
        ] {
            let mut code = Vec::new();
            emit_thumb(&mut code, first);
            emit_thumb(&mut code, second);
            let image = make_elf(BASE | 1, &code);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    instruction,
                    thumb: true
                }) if instruction == first as u32
            ));
        }
        let _ = fs::remove_dir_all(base);
    }
    #[test]
    fn thumb2_ldr_word_immediate_loads_linker_encoding() {
        let (base, mut broker) = test_broker("thumb2-ldr-word-immediate");
        for (second, base_offset) in [(0x4000_u16, 0x40_u32), (0x4004, 0x3c)] {
            let mut code = Vec::new();
            emit_thumb(&mut code, 0xf8df); // ldr.w r8, [pc, #28] -> base
            emit_thumb(&mut code, 0x801c);
            emit_thumb(&mut code, 0xf8d8); // ldr.w r4, [r8, #imm12]
            emit_thumb(&mut code, second);
            emit_mov_reg(&mut code, 0, 4);
            emit_movs(&mut code, 7, 1);
            emit_thumb(&mut code, 0xdf00);

            code.resize(0x20, 0);
            code.extend_from_slice(&(BASE + base_offset).to_le_bytes());
            code.resize(0x40, 0);
            code.extend_from_slice(&0xcafe_babe_u32.to_le_bytes());

            let image = make_elf(BASE | 1, &code);
            let report = run_elf(&image, &mut broker, 8).unwrap();
            assert_eq!(report.instructions_executed, 5);
            assert_eq!(report.exit_code as u32, 0xcafe_babe);
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_ldr_word_immediate_rejects_sp_and_pc_destinations() {
        let (base, mut broker) = test_broker("thumb2-ldr-word-immediate-invalid");
        for second in [0xd000_u16, 0xf000] {
            let mut code = Vec::new();
            emit_thumb(&mut code, 0xf8d8);
            emit_thumb(&mut code, second);
            let image = make_elf(BASE | 1, &code);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    instruction: 0xf8d8,
                    thumb: true
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_str_word_immediate_stores_the_linker_encoding_to_guest_memory() {
        let (base, mut broker) = test_broker("thumb2-str-word-immediate");
        let destination_offset = 0x1000_u32;
        let destination_address = BASE + destination_offset;
        let base_address = BASE + destination_offset - 0x0cc8;
        let mut code = Vec::new();
        emit_thumb(&mut code, 0x4c07); // ldr r4, [pc, #28] -> STR base
        emit_movs(&mut code, 6, 0x5a);
        emit_thumb(&mut code, 0xf8c4); // str.w r6, [r4, #0xcc8]
        emit_thumb(&mut code, 0x6cc8);
        emit_thumb(&mut code, 0x4d06); // ldr r5, [pc, #24] -> stored word
        emit_thumb(&mut code, 0x6828); // ldr r0, [r5]
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00); // exit with the loaded word

        code.resize(0x20, 0);
        code.extend_from_slice(&base_address.to_le_bytes());
        code.extend_from_slice(&destination_address.to_le_bytes());
        code.resize(destination_offset as usize, 0);
        code.extend_from_slice(&0xdead_beef_u32.to_le_bytes());

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 12).unwrap();
        assert_eq!(report.instructions_executed, 7);
        assert_eq!(report.exit_code, 0x5a);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_strb_immediate_stores_linker_byte_to_guest_stack() {
        let (base, mut broker) = test_broker("thumb2-strb-immediate");
        let mut code = Vec::new();
        emit_movs(&mut code, 0, 0xfe);
        emit_mov_reg(&mut code, 12, 0);
        emit_thumb(&mut code, 0xf88d); // linker: strb.w r12, [sp, #0x33]
        emit_thumb(&mut code, 0xc033);
        emit_thumb(&mut code, 0xf10d); // add.w r5, sp, #0x30
        emit_thumb(&mut code, 0x0530);
        emit_movs(&mut code, 3, 3);
        emit_mov_reg(&mut code, 9, 3);
        emit_thumb(&mut code, 0xf815); // ldrb.w r0, [r5, r9]
        emit_thumb(&mut code, 0x0009);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();
        assert_eq!(report.instructions_executed, 9);
        assert_eq!(report.exit_code, 0xfe);

        for (first, second) in [
            (0xf88d_u16, 0xd033_u16), // SP source
            (0xf88d, 0xf033),         // PC source
            (0xf88f, 0xc033),         // PC base
        ] {
            let mut invalid = Vec::new();
            emit_thumb(&mut invalid, first);
            emit_thumb(&mut invalid, second);
            let image = make_elf(BASE | 1, &invalid);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    thumb: true,
                    ..
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_str_word_immediate_rejects_pc_registers() {
        let (base, mut broker) = test_broker("thumb2-str-word-immediate-invalid");
        for (first, second) in [
            (0xf8c4_u16, 0xd000_u16), // SP source
            (0xf8c4, 0xf000),         // PC source
            (0xf8cf, 0x6000),         // PC base
        ] {
            let mut code = Vec::new();
            emit_thumb(&mut code, first);
            emit_thumb(&mut code, second);
            let image = make_elf(BASE | 1, &code);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    thumb: true,
                    ..
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_mov_modified_immediate_loads_linker_constant() {
        let (base, mut broker) = test_broker("thumb2-mov-modified-immediate");
        let mut code = Vec::new();
        emit_thumb(&mut code, 0xf04f); // mov.w r2, #0x10000000
        emit_thumb(&mut code, 0x5280);
        emit_mov_reg(&mut code, 0, 2);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 8).unwrap();
        assert_eq!(report.instructions_executed, 4);
        assert_eq!(report.exit_code as u32, 0x1000_0000);

        let mut zero = Vec::new();
        emit_movs(&mut zero, 0, 0x5a);
        emit_mov_reg(&mut zero, 8, 0);
        emit_thumb(&mut zero, 0xf04f); // linker: mov.w r8, #0
        emit_thumb(&mut zero, 0x0800);
        emit_mov_reg(&mut zero, 0, 8);
        emit_movs(&mut zero, 7, 1);
        emit_thumb(&mut zero, 0xdf00);
        let image = make_elf(BASE | 1, &zero);
        let report = run_elf(&image, &mut broker, 8).unwrap();
        assert_eq!(report.instructions_executed, 6);
        assert_eq!(report.exit_code, 0);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_movw_loads_linker_halfword_and_rejects_invalid_forms() {
        let (base, mut broker) = test_broker("thumb2-movw");
        let mut code = Vec::new();
        emit_thumb(&mut code, 0xf240); // linker: movw r10, #0x1ff
        emit_thumb(&mut code, 0x1aff);
        emit_mov_reg(&mut code, 0, 10);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);
        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 8).unwrap();
        assert_eq!(report.instructions_executed, 4);
        assert_eq!(report.exit_code, 0x1ff);

        for (first, second) in [
            (0xf240_u16, 0x8001_u16), // reserved high bit
            (0xf240, 0xd001),         // SP destination
            (0xf240, 0xf001),         // PC destination
        ] {
            let mut invalid = Vec::new();
            emit_thumb(&mut invalid, first);
            emit_thumb(&mut invalid, second);
            let image = make_elf(BASE | 1, &invalid);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    thumb: true,
                    ..
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_and_modified_immediate_executes_linker_encoding() {
        let (base, mut broker) = test_broker("thumb2-and-modified-immediate");
        let mut code = Vec::new();
        emit_movs(&mut code, 1, 0xff);
        emit_thumb(&mut code, 0xf001); // linker: and.w r1, r1, #0x7f
        emit_thumb(&mut code, 0x017f);
        emit_mov_reg(&mut code, 0, 1);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 8).unwrap();
        assert_eq!(report.instructions_executed, 5);
        assert_eq!(report.exit_code, 0x7f);

        for (first, second) in [
            (0xf001_u16, 0x0d7f_u16), // SP destination.
            (0xf001, 0x0f7f),         // PC destination.
            (0xf00f, 0x017f),         // PC base.
            (0xf001, 0x0100),         // zero replication immediate.
            (0xf011, 0x117f),         // flag-setting ANDS.
        ] {
            let mut invalid = Vec::new();
            emit_thumb(&mut invalid, first);
            emit_thumb(&mut invalid, second);
            let image = make_elf(BASE | 1, &invalid);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    thumb: true,
                    ..
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_bic_modified_immediate_executes_linker_encodings() {
        let (base, mut broker) = test_broker("thumb2-bic-modified-immediate");

        let mut wide_constant = Vec::new();
        emit_thumb(&mut wide_constant, 0x4d07); // ldr r5, [pc, #28] -> 0xfff
        emit_thumb(&mut wide_constant, 0xf425); // linker: bic.w r12, r5, #0xfe0
        emit_thumb(&mut wide_constant, 0x6c7e);
        emit_mov_reg(&mut wide_constant, 0, 12);
        emit_movs(&mut wide_constant, 7, 1);
        emit_thumb(&mut wide_constant, 0xdf00);
        wide_constant.resize(0x20, 0);
        wide_constant.extend_from_slice(&0x0000_0fff_u32.to_le_bytes());

        let image = make_elf(BASE | 1, &wide_constant);
        let report = run_elf(&image, &mut broker, 8).unwrap();
        assert_eq!(report.instructions_executed, 5);
        assert_eq!(report.exit_code, 0x1f);

        let mut narrow_constant = Vec::new();
        emit_movs(&mut narrow_constant, 1, 0xff);
        emit_mov_reg(&mut narrow_constant, 12, 1);
        emit_thumb(&mut narrow_constant, 0xf02c); // linker: bic r3, r12, #0x1f
        emit_thumb(&mut narrow_constant, 0x031f);
        emit_mov_reg(&mut narrow_constant, 0, 3);
        emit_movs(&mut narrow_constant, 7, 1);
        emit_thumb(&mut narrow_constant, 0xdf00);

        let image = make_elf(BASE | 1, &narrow_constant);
        let report = run_elf(&image, &mut broker, 8).unwrap();
        assert_eq!(report.instructions_executed, 6);
        assert_eq!(report.exit_code, 0xe0);

        for (first, second) in [
            (0xf020_u16, 0x0d01_u16), // SP destination.
            (0xf020, 0x0f01),         // PC destination.
            (0xf02f, 0x0001),         // PC base.
            (0xf020, 0x0000),         // zero replication immediate.
            (0xf030, 0x0301),         // flag-setting BICS.
        ] {
            let mut invalid = Vec::new();
            emit_thumb(&mut invalid, first);
            emit_thumb(&mut invalid, second);
            let image = make_elf(BASE | 1, &invalid);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    thumb: true,
                    ..
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_orr_modified_immediate_executes_linker_encoding() {
        let (base, mut broker) = test_broker("thumb2-orr-modified-immediate");
        let mut code = Vec::new();
        emit_movs(&mut code, 0, 3);
        emit_thumb(&mut code, 0xf040); // orr.w r3, r0, #4
        emit_thumb(&mut code, 0x0304);
        emit_mov_reg(&mut code, 0, 3);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 8).unwrap();
        assert_eq!(report.instructions_executed, 5);
        assert_eq!(report.exit_code, 7);

        for (first, second) in [
            (0xf050_u16, 0x0304_u16), // flag-setting ORRS.
            (0xf040, 0x0d04),         // SP destination.
            (0xf040, 0x0f04),         // PC destination.
            (0xf040, 0x0300),         // invalid zero-replication immediate.
        ] {
            let mut invalid = Vec::new();
            emit_thumb(&mut invalid, first);
            emit_thumb(&mut invalid, second);
            let image = make_elf(BASE | 1, &invalid);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    instruction,
                    thumb: true
                }) if instruction == first as u32
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_orr_prefix_defers_linker_bne_w_to_branch_decoder() {
        let (base, mut broker) = test_broker("thumb2-orr-prefix-bne-branch");
        let mut code = Vec::new();
        emit_movs(&mut code, 0, 1); // Z=0 so the linker BNE.W is taken.
        emit_thumb(&mut code, 0xf040);
        emit_thumb(&mut code, 0x80be); // linker: bne.w to BASE + 0x182
        emit_movs(&mut code, 0, 9); // fall-through failure
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);
        code.resize(0x182, 0);
        emit_movs(&mut code, 0, 7);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 8).unwrap();
        assert_eq!(report.instructions_executed, 5);
        assert_eq!(report.exit_code, 7);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_mov_modified_immediate_rejects_flagged_and_invalid_forms() {
        let (base, mut broker) = test_broker("thumb2-mov-modified-immediate-invalid");
        for (first, second) in [
            (0xf05f_u16, 0x0280_u16), // flag-setting MOVS is outside this subset
            (0xf04f, 0x8001),         // reserved high bit
            (0xf04f, 0xd001),         // SP destination
            (0xf04f, 0xf001),         // PC destination
            (0xf04f, 0x1300),         // noncanonical zero replication encoding
        ] {
            let mut code = Vec::new();
            emit_thumb(&mut code, first);
            emit_thumb(&mut code, second);
            let image = make_elf(BASE | 1, &code);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    thumb: true,
                    ..
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb_blx_immediate_interworks_to_arm_and_returns_to_thumb() {
        let (base, mut broker) = test_broker("thumb-blx-immediate-interwork");

        // Reuse the exact negative-offset BLX immediate from the linker.
        let mut exact = Vec::new();
        exact.resize(0x210, 0);
        for word in [0xe3a0_0007_u32, 0xe12f_ff1e] {
            exact.extend_from_slice(&word.to_le_bytes());
        }
        exact.resize(0x4038, 0);
        emit_thumb(&mut exact, 0xf7fc);
        emit_thumb(&mut exact, 0xe8ea);
        emit_movs(&mut exact, 7, 1);
        emit_thumb(&mut exact, 0xdf00);
        let image = make_elf((BASE + 0x4038) | 1, &exact);
        let report = run_elf(&image, &mut broker, 8).unwrap();
        assert_eq!(report.instruction_set, InstructionSet::Thumb);
        assert_eq!(report.instructions_executed, 5);
        assert_eq!(report.exit_code, 7);

        // Positive BLX immediate to an aligned ARM stub, then BX LR to Thumb.
        let mut positive = Vec::new();
        emit_thumb(&mut positive, 0xf000);
        emit_thumb(&mut positive, 0xe802); // target at BASE + 8
        emit_movs(&mut positive, 7, 1);
        emit_thumb(&mut positive, 0xdf00);
        for word in [0xe3a0_0009_u32, 0xe12f_ff1e] {
            positive.extend_from_slice(&word.to_le_bytes());
        }
        let image = make_elf(BASE | 1, &positive);
        let report = run_elf(&image, &mut broker, 8).unwrap();
        assert_eq!(report.instruction_set, InstructionSet::Thumb);
        assert_eq!(report.instructions_executed, 5);
        assert_eq!(report.exit_code, 9);

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb_blx_immediate_rejects_reserved_low_bit() {
        let (base, mut broker) = test_broker("thumb-blx-immediate-invalid");
        let code = [0xf000_u16, 0xe801]
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let image = make_elf(BASE | 1, &code);
        assert!(matches!(
            run_elf(&image, &mut broker, 4),
            Err(ElfError::InvalidInstruction {
                pc: BASE,
                instruction: 0xf000,
                thumb: true
            })
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_conditional_branch_executes_linker_beq_w_encoding() {
        let (base, mut broker) = test_broker("thumb2-conditional-branch");
        for (compare_value, expected_exit) in [(1_u8, 7_i32), (2, 42)] {
            let mut code = Vec::new();
            emit_movs(&mut code, 0, 1);
            emit_thumb(&mut code, 0x2800 | compare_value as u16); // cmp r0, #1/#2
            emit_thumb(&mut code, 0xf000); // linker: beq.w +0x176
            emit_thumb(&mut code, 0x80bb);
            emit_movs(&mut code, 0, 42); // fall-through result
            emit_movs(&mut code, 7, 1);
            emit_thumb(&mut code, 0xdf00);
            code.resize(0x17e, 0);
            emit_movs(&mut code, 0, 7); // branch target at BASE + 0x17e
            emit_movs(&mut code, 7, 1);
            emit_thumb(&mut code, 0xdf00);
            let image = make_elf(BASE | 1, &code);
            let report = run_elf(&image, &mut broker, 8).unwrap();
            assert_eq!(report.instructions_executed, 6);
            assert_eq!(report.exit_code, expected_exit);
        }

        let invalid = [0xf380_u16, 0x80bb]
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        let image = make_elf(BASE | 1, &invalid);
        assert!(matches!(
            run_elf(&image, &mut broker, 4),
            Err(ElfError::InvalidInstruction {
                pc: BASE,
                instruction: 0xf380,
                thumb: true
            })
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb2_tbb_pc_uses_linker_byte_table_and_register_index() {
        let (base, mut broker) = test_broker("thumb2-tbb-pc");
        let mut code = Vec::new();
        emit_movs(&mut code, 6, 2);
        emit_thumb(&mut code, 0xbf00); // keep the linker TBB word-aligned
        emit_thumb(&mut code, 0xe8df); // linker: tbb [pc, r6]
        emit_thumb(&mut code, 0xf006);
        code.extend_from_slice(&[0, 0, 5, 0]); // index 2 -> branch to BASE + 0x12
        code.resize(0x12, 0);
        emit_movs(&mut code, 0, 7);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);

        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 8).unwrap();
        assert_eq!(report.instructions_executed, 6);
        assert_eq!(report.exit_code, 7);

        for (first, second) in [
            (0xe8df_u16, 0xf016_u16), // TBH is outside the observed subset.
            (0xe8dd, 0xf006),         // SP base.
            (0xe8df, 0xf00f),         // PC index.
        ] {
            let mut invalid = Vec::new();
            emit_thumb(&mut invalid, first);
            emit_thumb(&mut invalid, second);
            let image = make_elf(BASE | 1, &invalid);
            assert!(matches!(
                run_elf(&image, &mut broker, 4),
                Err(ElfError::InvalidInstruction {
                    pc: BASE,
                    thumb: true,
                    ..
                })
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb_itt_eq_executes_matching_block_and_skips_wide_instructions_when_false() {
        let (base, mut broker) = test_broker("thumb-itt-eq");

        let mut matching = Vec::new();
        emit_movs(&mut matching, 0, 7);
        emit_thumb(&mut matching, 0x2807); // cmp r0, #7 -> EQ
        emit_thumb(&mut matching, 0xbf04); // linker: itt eq
        emit_mov_reg(&mut matching, 1, 0);
        emit_mov_reg(&mut matching, 2, 1);
        emit_mov_reg(&mut matching, 0, 2);
        emit_movs(&mut matching, 7, 1);
        emit_thumb(&mut matching, 0xdf00);
        let image = make_elf(BASE | 1, &matching);
        let report = run_elf(&image, &mut broker, 12).unwrap();
        assert_eq!(report.instructions_executed, 8);
        assert_eq!(report.exit_code, 7);

        let mut not_matching = Vec::new();
        emit_movs(&mut not_matching, 0, 7); // Z=0: do not execute the IT block.
        emit_thumb(&mut not_matching, 0xbf04);
        emit_thumb(&mut not_matching, 0xf8d8); // ldr.w r3, [r8, #8] would fault.
        emit_thumb(&mut not_matching, 0x3008);
        emit_thumb(&mut not_matching, 0xf8c9); // str.w r3, [r9, #0x84] would fault.
        emit_thumb(&mut not_matching, 0x3084);
        emit_movs(&mut not_matching, 7, 1);
        emit_thumb(&mut not_matching, 0xdf00);
        let image = make_elf(BASE | 1, &not_matching);
        let report = run_elf(&image, &mut broker, 12).unwrap();
        assert_eq!(report.instructions_executed, 6);
        assert_eq!(report.exit_code, 7);

        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb_bl_push_pop_and_stack_adjust_restore_a_call_frame() {
        let (base, mut broker) = test_broker("thumb-call-frame");
        let halfwords = [
            0x240b_u16, // movs r4, #11
            0x2516,     // movs r5, #22
            0x2621,     // movs r6, #33
            0x272c,     // movs r7, #44
            0xf000,     // bl prefix
            0xf80a,     // bl suffix -> function at byte offset 32
            0x2c0b,     // cmp r4, #11 (return address)
            0xd110,     // bne failure
            0x2d16,     // cmp r5, #22
            0xd10e,     // bne failure
            0x2e21,     // cmp r6, #33
            0xd10c,     // bne failure
            0x2f2c,     // cmp r7, #44
            0xd10a,     // bne failure
            0x2701,     // movs r7, #1 (exit)
            0xdf00,     // svc #0
            0xb5f0,     // function: push {r4-r7, lr}
            0xb082,     // sub sp, #8
            0x2400,     // clobber saved callee registers
            0x2500, 0x2600, 0x2700, 0x2009, // movs r0, #9
            0xb002, // add sp, #8
            0xbdf0, // pop {r4-r7, pc}
            0x2001, // failure: movs r0, #1
            0x2701, 0xdf00,
        ];
        let code: Vec<u8> = halfwords.into_iter().flat_map(u16::to_le_bytes).collect();
        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 32).unwrap();

        assert_eq!(report.instruction_set, InstructionSet::Thumb);
        assert_eq!(report.instructions_executed, 24);
        assert_eq!(report.exit_code, 9);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_elf_runs_a32_instructions_and_brokers_identity_syscall() {
        let (base, mut broker) = test_broker("arm");
        let words = [
            0xe59f_0008u32, // ldr r0, [pc, #8] (literal at BASE + 16)
            0xe3a0_7014,    // mov r7, #20 (getpid)
            0xef00_0000,    // svc #0
            0xea00_0000,    // b past the literal
            0xdec0_adde,    // literal loaded into r0
            0xe3a0_0000,    // mov r0, #0
            0xe3a0_7001,    // mov r7, #1 (exit)
            0xef00_0000,    // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 32).unwrap();
        assert_eq!(report.instruction_set, InstructionSet::Arm);
        assert_eq!(report.exit_code, 0);
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].syscall.name(), "getpid");
        assert_eq!(report.events[0].result, Ok(BrokerValue::Identity(29)));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_elf_executes_word_exclusive_load_and_store() {
        let (base, mut broker) = test_broker("arm-exclusive");
        let words = [
            0xe1a0_100d_u32, // mov r1, sp
            0xe3a0_0029,     // mov r0, #41
            0xe581_0000,     // str r0, [r1]
            0xe191_2f9f,     // ldrex r2, [r1]
            0xe282_2001,     // add r2, r2, #1
            0xe181_3f92,     // strex r3, r2, [r1]
            0xe353_0000,     // cmp r3, #0
            0x1a00_0005,     // bne failure
            0xe591_0000,     // ldr r0, [r1]
            0xe350_002a,     // cmp r0, #42
            0x1a00_0002,     // bne failure
            0xe3a0_0000,     // success: mov r0, #0
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
            0xe3a0_0001,     // failure: mov r0, #1
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 32).unwrap();

        assert_eq!(report.exit_code, 0);
        assert_eq!(report.instructions_executed, 14);
        assert_eq!(report.syscall_trace.len(), 1);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn bionic_open_accepts_arm_largefile_flag_without_changing_guest_access_mode() {
        const O_LARGEFILE: u32 = 0x20000;
        assert_eq!(linux_open_flags(O_LARGEFILE), Some(OpenFlags::READ_ONLY));
        assert_eq!(
            linux_open_flags(O_LARGEFILE | 1 | 0x40 | 0x200),
            Some(OpenFlags::WRITE_CREATE_TRUNCATE)
        );
        assert_eq!(linux_open_flags(O_LARGEFILE | 0x4000_0000), None);
    }

    #[test]
    fn arm_guest_can_install_and_read_the_bionic_thread_pointer() {
        let (base, mut broker) = test_broker("arm-tls");
        let tls_address = BASE + 100;
        let words = [
            0xe59f_004c_u32, // ldr r0, [pc, #76] -> TLS-area literal
            0xe59f_704c,     // ldr r7, [pc, #76] -> ARM_set_tls literal
            0xef00_0000,     // svc #0: install r0 as the thread pointer
            0xe350_0000,     // cmp r0, #0: set_tls succeeded
            0x1a00_000c,     // bne fail
            0xe3a0_7014,     // mov r7, #20 (Bionic linker immediately calls getpid)
            0xef00_0000,     // svc #0: getpid through the guest broker
            0xe350_0000,     // cmp r0, #0
            0x0a00_0008,     // beq fail (a process id must be positive)
            0xee1d_1f70,     // mrc p15, 0, r1, c13, c0, 3 (TPIDRURO)
            0xe59f_202c,     // ldr r2, [pc, #44] -> TLS-area literal
            0xe151_0002,     // cmp r1, r2
            0x1a00_0004,     // bne fail
            0xe591_3000,     // ldr r3, [r1] -> TLS_SLOT_SELF
            0xe153_0002,     // cmp r3, r2
            0x1a00_0001,     // bne fail
            0xe3a0_0000,     // mov r0, #0
            0xea00_0000,     // b exit
            0xe3a0_0001,     // fail: mov r0, #1
            0xe3a0_7001,     // exit: mov r7, #1
            0xef00_0000,     // svc #0: exit
            tls_address,     // literal for r0
            ARM_NR_SET_TLS,  // literal for r7
            tls_address,     // literal for r2
            0,               // literal-pool padding
        ];
        let mut payload: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        payload.extend_from_slice(&tls_address.to_le_bytes()); // slot 0 points to itself
        payload.resize(payload.len() + (BIONIC_TLS_SLOTS - 1) * 4, 0);
        let image = make_elf(BASE, &payload);
        let report = run_elf(&image, &mut broker, 32).unwrap();

        assert_eq!(report.instruction_set, InstructionSet::Arm);
        assert_eq!(report.exit_code, 0);
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].syscall, GuestSyscall::GetPid);
        assert_eq!(report.events[0].result, Ok(BrokerValue::Identity(29)));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn pt_interp_emulates_arm_linux_kuser_get_tls_with_movw_movt() {
        let (base, mut broker) = test_broker("pt-interp-kuser-get-tls");
        let linker_path = "/system/bin/test-linker";
        let linker_host_path = broker.rootfs().map_absolute(linker_path).unwrap();
        fs::create_dir_all(linker_host_path.parent().unwrap()).unwrap();
        let words = [
            0xe300_3fe0_u32, // movw r3, #0xfe0
            0xe34f_3fff,     // movt r3, #0xffff -> __kuser_get_tls
            0xe12f_ff33,     // blx r3
            0xe350_0000,     // cmp r0, #0 (unset TP returns zero)
            0x13a0_0001,     // movne r0, #1
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        let linker_code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let mut linker = make_elf(0, &linker_code);
        put_u16_at(&mut linker, 16, ET_DYN);
        put_u32_at(&mut linker, ELF_HEADER_SIZE + 8, 0);
        put_u32_at(&mut linker, ELF_HEADER_SIZE + 12, 0);
        fs::write(linker_host_path, linker).unwrap();

        let main = make_pt_interp_elf(linker_path, &[0xef, 0, 0, 0]);
        let report = run_elf(&main, &mut broker, 32).unwrap();

        assert_eq!(report.entry, DYN_INTERPRETER_BASE);
        assert_eq!(report.instruction_set, InstructionSet::Arm);
        assert_eq!(report.exit_code, 0);
        assert_eq!(report.instructions_executed, 9);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn static_arm_elf_emulates_arm_linux_kuser_get_tls_with_movw_movt() {
        let (base, mut broker) = test_broker("static-kuser-get-tls");
        let words = [
            0xe300_3fe0_u32, // movw r3, #0xfe0
            0xe34f_3fff,     // movt r3, #0xffff -> __kuser_get_tls
            0xe12f_ff33,     // blx r3
            0xe350_0000,     // cmp r0, #0 (unset TP returns zero)
            0x13a0_0001,     // movne r0, #1
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 32).unwrap();

        assert_eq!(report.instruction_set, InstructionSet::Arm);
        assert_eq!(report.exit_code, 0);
        assert_eq!(report.instructions_executed, 9);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_vfp_vpush_vpop_preserve_double_register_stack_frame() {
        let (base, mut broker) = test_broker("vfp-push-pop");
        let words = [
            0xed2d_8b04_u32, // vpush {d8-d9}
            0xecbd_8b04,     // vpop {d8-d9}
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();

        assert_eq!(report.exit_code, 0);
        assert_eq!(report.instructions_executed, words.len() as u64);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_vfp_vldr_loads_a_double_register_from_pc_relative_memory() {
        let (base, mut broker) = test_broker("vfp-vldr-literal");
        let words = [
            0xed9f_9b00_u32, // vldr d9, [pc]
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
            0,               // complete the eight-byte literal range
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();

        assert_eq!(report.exit_code, 0);
        assert_eq!(report.instructions_executed, 3);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_virtual_clock_advances_on_nanosleep_without_host_sleeping() {
        let (base, mut broker) = test_broker("virtual-clock");
        let words = [
            0xe3a0_1001_u32, // mov r1, #1 (timespec.tv_sec)
            0xe58d_1000,     // str r1, [sp]
            0xe3a0_1000,     // mov r1, #0 (timespec.tv_nsec)
            0xe58d_1004,     // str r1, [sp, #4]
            0xe1a0_000d,     // mov r0, sp (nanosleep request)
            0xe3a0_70a2,     // mov r7, #162 (nanosleep)
            0xef00_0000,     // svc #0
            0xe3a0_0001,     // mov r0, #1 (CLOCK_MONOTONIC)
            0xe1a0_100d,     // mov r1, sp (clock_gettime output)
            0xe300_7107,     // movw r7, #263 (clock_gettime)
            0xef00_0000,     // svc #0
            0xe59d_2000,     // ldr r2, [sp] -> seconds
            0xe352_0001,     // cmp r2, #1
            0x13a0_0001,     // movne r0, #1
            0xe59d_2004,     // ldr r2, [sp, #4] -> nanoseconds
            0xe352_0000,     // cmp r2, #0
            0x13a0_0001,     // movne r0, #1
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 32).unwrap();

        assert_eq!(report.exit_code, 0);
        assert_eq!(report.instructions_executed, words.len() as u64);
        assert_eq!(report.syscall_trace.len(), 3);
        assert_eq!(report.syscall_trace[0].number, 162);
        assert_eq!(report.syscall_trace[1].number, 263);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_poll_idle_yields_and_finite_timeout_advances_guest_time() {
        let (idle_base, mut idle_broker) = test_broker("poll-idle");
        let idle_words = [
            0xe3a0_0000_u32, // mov r0, #0 (no pollfd array)
            0xe3a0_1000,     // mov r1, #0 (nfds)
            0xe3e0_2000,     // mvn r2, #0 (infinite timeout)
            0xe3a0_70a8,     // mov r7, #168 (poll)
            0xef00_0000,     // svc #0
        ];
        let idle_code: Vec<u8> = idle_words.into_iter().flat_map(u32::to_le_bytes).collect();
        let idle_report = run_elf(&make_elf(BASE, &idle_code), &mut idle_broker, 16).unwrap();
        assert_eq!(idle_report.stop_reason, ElfStopReason::WaitingForEvents);
        assert_eq!(idle_report.instructions_executed, idle_words.len() as u64);
        assert_eq!(idle_report.syscall_trace.len(), 1);
        assert_eq!(idle_report.syscall_trace[0].number, 168);
        assert!(idle_report.syscall_trace[0].blocked);
        let _ = fs::remove_dir_all(idle_base);

        let (timeout_base, mut timeout_broker) = test_broker("poll-timeout");
        let timeout_words = [
            0xe3a0_0000_u32, // mov r0, #0 (no pollfd array)
            0xe3a0_1000,     // mov r1, #0 (nfds)
            0xe300_25dc,     // movw r2, #1500 (finite timeout in ms)
            0xe3a0_70a8,     // mov r7, #168 (poll)
            0xef00_0000,     // svc #0
            0xe3a0_0001,     // mov r0, #1 (CLOCK_MONOTONIC)
            0xe1a0_100d,     // mov r1, sp (clock_gettime output)
            0xe300_7107,     // movw r7, #263 (clock_gettime)
            0xef00_0000,     // svc #0
            0xe59d_2000,     // ldr r2, [sp] (seconds)
            0xe352_0001,     // cmp r2, #1
            0x13a0_0001,     // movne r0, #1
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        let timeout_code: Vec<u8> = timeout_words
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect();
        let timeout_report =
            run_elf(&make_elf(BASE, &timeout_code), &mut timeout_broker, 24).unwrap();
        assert_eq!(timeout_report.stop_reason, ElfStopReason::GuestExited);
        assert_eq!(timeout_report.exit_code, 0);
        assert_eq!(
            timeout_report.instructions_executed,
            timeout_words.len() as u64
        );
        assert_eq!(timeout_report.syscall_trace[0].number, 168);
        assert!(!timeout_report.syscall_trace[0].blocked);
        let _ = fs::remove_dir_all(timeout_base);
    }

    #[test]
    fn arm_elf_executes_clz_for_nonzero_and_zero_operands() {
        let (base, mut broker) = test_broker("arm-clz");
        let words = [
            0xe3a0_1001_u32, // mov r1, #1
            0xe16f_2f11,     // clz r2, r1 -> 31
            0xe352_001f,     // cmp r2, #31
            0x13a0_0001,     // movne r0, #1
            0xe3a0_1000,     // mov r1, #0
            0xe16f_2f11,     // clz r2, r1 -> 32
            0xe352_0020,     // cmp r2, #32
            0x13a0_0001,     // movne r0, #1
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 32).unwrap();

        assert_eq!(report.exit_code, 0);
        assert_eq!(report.instructions_executed, words.len() as u64);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_elf_executes_bfi_bfc_and_ubfx_bitfield_instructions() {
        let (base, mut broker) = test_broker("arm-bitfield");
        let words = [
            0xe3e0_5000_u32, // mvn r5, #0
            0xe3a0_2015,     // mov r2, #0x15
            0xe7c7_5092,     // bfi r5, r2, #1, #7
            0xe7e6_30d5,     // ubfx r3, r5, #1, #7 -> 0x15
            0xe353_0015,     // cmp r3, #0x15
            0x13a0_0001,     // movne r0, #1
            0xe3a0_c003,     // mov r12, #3
            0xe7c0_c01f,     // bfc r12, #0, #1
            0xe35c_0002,     // cmp r12, #2
            0x13a0_0001,     // movne r0, #1
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 32).unwrap();

        assert_eq!(report.exit_code, 0);
        assert_eq!(report.instructions_executed, words.len() as u64);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_elf_executes_unsigned_byte_and_halfword_extend_family() {
        let (base, mut broker) = test_broker("arm-unsigned-extend");
        let words = [
            0xe305_1678_u32, // movw r1, #0x5678
            0xe341_1234,     // movt r1, #0x1234 -> 0x12345678
            0xe6ef_2471,     // uxtb r2, r1, ror #8 -> 0x56
            0xe352_0056,     // cmp r2, #0x56
            0x13a0_0001,     // movne r0, #1
            0xe6ff_3871,     // uxth r3, r1, ror #16 -> 0x1234
            0xe301_4234,     // movw r4, #0x1234
            0xe153_0004,     // cmp r3, r4
            0x13a0_0001,     // movne r0, #1
            0xe30a_2bcd,     // movw r2, #0xabcd
            0xe6e1_5072,     // uxtab r5, r1, r2 -> r1 + 0xcd
            0xe3a0_60cd,     // mov r6, #0xcd
            0xe081_6006,     // add r6, r1, r6
            0xe155_0006,     // cmp r5, r6
            0x13a0_0001,     // movne r0, #1
            0xe6f1_7072,     // uxtah r7, r1, r2 -> r1 + 0xabcd
            0xe30a_8bcd,     // movw r8, #0xabcd
            0xe081_9008,     // add r9, r1, r8
            0xe157_0009,     // cmp r7, r9
            0x13a0_0001,     // movne r0, #1
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 32).unwrap();

        assert_eq!(report.exit_code, 0);
        assert_eq!(report.instructions_executed, words.len() as u64);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_elf_executes_ldrd_strd_immediate_and_register_offsets() {
        let (base, mut broker) = test_broker("arm-doubleword-transfer");
        const DATA_OFFSET: usize = 0x200;
        let words = [
            0xe300_1200_u32, // movw r1, #0x0200
            0xe340_1001,     // movt r1, #1 -> BASE + DATA_OFFSET
            0xe301_2234,     // movw r2, #0x1234
            0xe345_2678,     // movt r2, #0x5678
            0xe30a_3bcd,     // movw r3, #0xabcd
            0xe34e_3f01,     // movt r3, #0xef01
            0xe1c1_20f8,     // strd r2, r3, [r1, #8]
            0xe1c1_40d8,     // ldrd r4, r5, [r1, #8]
            0xe154_0002,     // cmp r4, r2
            0x13a0_0001,     // movne r0, #1
            0xe155_0003,     // cmp r5, r3
            0x13a0_0001,     // movne r0, #1
            0xe1c1_20f0,     // strd r2, r3, [r1]
            0xe3a0_6010,     // mov r6, #0x10
            0xe181_20f6,     // strd r2, r3, [r1, r6]
            0xe181_80d6,     // ldrd r8, r9, [r1, r6]
            0xe158_0002,     // cmp r8, r2
            0x13a0_0001,     // movne r0, #1
            0xe159_0003,     // cmp r9, r3
            0x13a0_0001,     // movne r0, #1
            0xe1c1_a0d0,     // ldrd r10, r11, [r1]
            0xe15a_0002,     // cmp r10, r2
            0x13a0_0001,     // movne r0, #1
            0xe15b_0003,     // cmp r11, r3
            0x13a0_0001,     // movne r0, #1
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        let mut payload: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        payload.resize(DATA_OFFSET + 0x18, 0);
        let image = make_elf(BASE, &payload);
        let report = run_elf(&image, &mut broker, 64).unwrap();

        assert_eq!(report.exit_code, 0);
        assert_eq!(report.instructions_executed, words.len() as u64);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_elf_stores_original_lowest_base_on_stmdb_writeback() {
        let (base, mut broker) = test_broker("arm-stmdb-base-in-list");
        let words = [
            0xe305_e678_u32, // movw lr, #0x5678
            0xe341_e234,     // movt lr, #0x1234
            0xe92d_6000,     // stmdb sp!, {sp, lr} (push {sp, lr})
            0xe59d_4000,     // ldr r4, [sp] -> original SP
            0xe28d_5008,     // add r5, sp, #8 -> original SP
            0xe154_0005,     // cmp r4, r5
            0x13a0_0001,     // movne r0, #1
            0xe59d_6004,     // ldr r6, [sp, #4] -> saved LR
            0xe156_000e,     // cmp r6, lr
            0x13a0_0001,     // movne r0, #1
            0xe28d_d008,     // add sp, sp, #8 (restore SP)
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 32).unwrap();

        assert_eq!(report.exit_code, 0);
        assert_eq!(report.instructions_executed, words.len() as u64);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_elf_executes_halfword_signed_loads_and_indexing_modes() {
        let (base, mut broker) = test_broker("arm-halfword-transfer");
        const DATA_OFFSET: usize = 0x200;
        let words = [
            0xe300_1200_u32, // movw r1, #0x0200
            0xe340_1001,     // movt r1, #1 -> BASE + DATA_OFFSET
            0xe301_2234,     // movw r2, #0x1234
            0xe1c1_20b2,     // strh r2, [r1, #2]
            0xe1d1_30b2,     // ldrh r3, [r1, #2]
            0xe301_4234,     // movw r4, #0x1234
            0xe153_0004,     // cmp r3, r4
            0x13a0_0001,     // movne r0, #1
            0xe3a0_6004,     // mov r6, #4
            0xe181_20b6,     // strh r2, [r1, r6]
            0xe191_30b6,     // ldrh r3, [r1, r6]
            0xe153_0004,     // cmp r3, r4
            0x13a0_0001,     // movne r0, #1
            0xe0c1_20b6,     // strh r2, [r1], #6
            0xe151_30b6,     // ldrh r3, [r1, #-6]
            0xe153_0004,     // cmp r3, r4
            0x13a0_0001,     // movne r0, #1
            0xe3a0_4002,     // mov r4, #2
            0xe241_6002,     // sub r6, r1, #2
            0xe350_0000,     // cmp r0, #0 (set Z for conditional STRH)
            0x0001_10b4,     // strheq r1, [r1], -r4
            0xe151_0006,     // cmp r1, r6
            0x13a0_0001,     // movne r0, #1
            0xe300_5206,     // movw r5, #0x0206
            0xe1d1_30b2,     // ldrh r3, [r1, #2]
            0xe153_0005,     // cmp r3, r5
            0x13a0_0001,     // movne r0, #1
            0xe281_7002,     // add r7, r1, #2
            0xe091_30f4,     // ldrsh r3, [r1], r4
            0xe153_0002,     // cmp r3, r2
            0x13a0_0001,     // movne r0, #1
            0xe151_0007,     // cmp r1, r7
            0x13a0_0001,     // movne r0, #1
            0xe308_2001,     // movw r2, #0x8001
            0xe1c1_20b0,     // strh r2, [r1]
            0xe1d1_30f0,     // ldrsh r3, [r1] -> 0xffff8001
            0xe308_5001,     // movw r5, #0x8001
            0xe34f_5fff,     // movt r5, #0xffff
            0xe153_0005,     // cmp r3, r5
            0x13a0_0001,     // movne r0, #1
            0xe308_2080,     // movw r2, #0x8080
            0xe1c1_20b2,     // strh r2, [r1, #2]
            0xe1d1_30d2,     // ldrsb r3, [r1, #2] -> 0xffffff80
            0xe3e0_507f,     // mvn r5, #0x7f
            0xe153_0005,     // cmp r3, r5
            0x13a0_0001,     // movne r0, #1
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        let mut payload: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        payload.resize(DATA_OFFSET + 0x20, 0);
        let image = make_elf(BASE, &payload);
        let report = run_elf(&image, &mut broker, 64).unwrap();

        assert_eq!(report.exit_code, 0);
        assert_eq!(report.instructions_executed, words.len() as u64);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_elf_executes_shifted_register_alu_and_condition_flags() {
        let (base, mut broker) = test_broker("arm-alu");
        let words = [
            0xe3a0_0005u32, // mov r0, #5
            0xe3a0_1003,    // mov r1, #3
            0xe080_2101,    // add r2, r0, r1, lsl #2 -> 17
            0xe352_0011,    // cmp r2, #17 -> Z=1, C=1
            0x03a0_0007,    // moveq r0, #7
            0x13a0_0063,    // movne r0, #99 (must be skipped)
            0xe3a0_7001,    // mov r7, #1 (exit)
            0xef00_0000,    // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 32).unwrap();

        assert_eq!(report.instruction_set, InstructionSet::Arm);
        assert_eq!(report.instructions_executed, words.len() as u64);
        assert_eq!(report.exit_code, 7);
        assert!(report.events.is_empty());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_elf_executes_short_and_signed_unsigned_long_multiply_families() {
        let (base, mut broker) = test_broker("arm-multiply");
        let words = [
            0xe3a0_0000_u32, // mov r0, #0 (exit status)
            0xe3a0_4007,     // mov r4, #7
            0xe3a0_5009,     // mov r5, #9
            0xe3a0_3005,     // mov r3, #5
            0xe006_0594,     // mul r6, r4, r5 -> 63
            0xe356_003f,     // cmp r6, #63
            0x13a0_0001,     // movne r0, #1
            0xe027_3594,     // mla r7, r4, r5, r3 -> 68
            0xe357_0044,     // cmp r7, #68
            0x13a0_0001,     // movne r0, #1
            0xe089_8594,     // umull r8, r9, r4, r5 -> high:low = 0:63
            0xe358_003f,     // cmp r8, #63
            0x13a0_0001,     // movne r0, #1
            0xe359_0000,     // cmp r9, #0
            0x13a0_0001,     // movne r0, #1
            0xe3e0_4001,     // mvn r4, #1 -> -2
            0xe3a0_5003,     // mov r5, #3
            0xe0c9_8594,     // smull r8, r9, r4, r5 -> -6
            0xe3e0_6005,     // mvn r6, #5 -> -6
            0xe158_0006,     // cmp r8, r6
            0x13a0_0001,     // movne r0, #1
            0xe3e0_6000,     // mvn r6, #0 -> -1
            0xe159_0006,     // cmp r9, r6
            0x13a0_0001,     // movne r0, #1
            0xe3a0_8006,     // mov r8, #6 (UMLAL accumulator)
            0xe3a0_9000,     // mov r9, #0
            0xe0a9_8594,     // umlal r8, r9, r4, r5 -> 0x00000003:0
            0xe358_0000,     // cmp r8, #0
            0x13a0_0001,     // movne r0, #1
            0xe359_0003,     // cmp r9, #3
            0x13a0_0001,     // movne r0, #1
            0xe3a0_8006,     // mov r8, #6 (SMLAL accumulator)
            0xe3a0_9000,     // mov r9, #0
            0xe0e9_8594,     // smlal r8, r9, r4, r5 -> 0
            0xe358_0000,     // cmp r8, #0
            0x13a0_0001,     // movne r0, #1
            0xe359_0000,     // cmp r9, #0
            0x13a0_0001,     // movne r0, #1
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 64).unwrap();

        assert_eq!(report.instruction_set, InstructionSet::Arm);
        assert_eq!(report.instructions_executed, words.len() as u64);
        assert_eq!(report.exit_code, 0);
        assert!(report.events.is_empty());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_elf_supports_shifted_register_offset_word_and_byte_load_store() {
        let (base, mut broker) = test_broker("arm-register-offset");
        let words = [
            0xe3a0_602a_u32, // mov r6, #42
            0xe3a0_0000,     // mov r0, #0 (exit status)
            0xe3a0_1004,     // mov r1, #4
            0xe70d_6101,     // str r6, [sp, -r1, lsl #2]
            0xe71d_2101,     // ldr r2, [sp, -r1, lsl #2]
            0xe352_002a,     // cmp r2, #42
            0x13a0_0001,     // movne r0, #1
            0xe3a0_1020,     // mov r1, #32
            0xe71d_20a1,     // ldr r2, [sp, -r1, lsr #1]
            0xe352_002a,     // cmp r2, #42
            0x13a0_0001,     // movne r0, #1
            0xe3a0_1004,     // mov r1, #4
            0xe24d_300c,     // sub r3, sp, #12
            0xe713_2001,     // ldr r2, [r3, -r1]
            0xe352_002a,     // cmp r2, #42
            0x13a0_0001,     // movne r0, #1
            0xe24d_3010,     // sub r3, sp, #16
            0xe613_2001,     // ldr r2, [r3], -r1 (post-index/writeback)
            0xe352_002a,     // cmp r2, #42
            0x13a0_0001,     // movne r0, #1
            0xe793_2001,     // ldr r2, [r3, r1] (post-index updated base)
            0xe352_002a,     // cmp r2, #42
            0x13a0_0001,     // movne r0, #1
            0xe3a0_40ab,     // mov r4, #0xab
            0xe74d_4081,     // strb r4, [sp, -r1, lsl #1]
            0xe75d_5081,     // ldrb r5, [sp, -r1, lsl #1]
            0xe355_00ab,     // cmp r5, #0xab
            0x13a0_0001,     // movne r0, #1
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 64).unwrap();

        assert_eq!(report.instruction_set, InstructionSet::Arm);
        assert_eq!(report.instructions_executed, words.len() as u64);
        assert_eq!(report.exit_code, 0);
        assert!(report.events.is_empty());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_bl_and_bx_lr_return_to_the_link_address() {
        let (base, mut broker) = test_broker("arm-bl-bx");
        let words = [
            0xeb00_0001_u32, // bl function
            0xe3a0_7001,     // return address: mov r7, #1
            0xef00_0000,     // svc #0
            0xe3a0_0007,     // function: mov r0, #7
            0xe12f_ff1e,     // bx lr
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();

        assert_eq!(report.instructions_executed, 5);
        assert_eq!(report.exit_code, 7);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_blx_register_interworks_to_thumb_and_returns_to_arm() {
        let (base, mut broker) = test_broker("arm-blx-register");
        let words = [
            0xe28f_3008_u32, // add r3, pc, #8 -> Thumb function at BASE + 16
            0xe383_3001,     // orr r3, r3, #1 (Thumb state bit)
            0xe12f_ff33,     // blx r3
            0xea00_0000,     // b over inline Thumb code after return
            0x4770_2007,     // Thumb: movs r0, #7; bx lr
            0xe3a0_7001,     // mov r7, #1
            0xef00_0000,     // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();

        assert_eq!(report.instructions_executed, 8);
        assert_eq!(report.exit_code, 7);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_blx_immediate_interworks_to_thumb_and_returns_to_arm() {
        let (base, mut broker) = test_broker("arm-blx-immediate");
        let words = [
            0xfa00_0002_u32, // blx Thumb entry at BASE + 16
            0xea00_0003,     // return path: branch to ARM code after Thumb body
            0xe1a0_0000,     // skipped padding
            0xe1a0_0000,     // skipped padding
            0x4770_2007,     // Thumb: movs r0, #7; bx lr
            0xe1a0_0000,     // skipped padding
            0xe3a0_7001,     // mov r7, #1
            0xef00_0000,     // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();

        assert_eq!(report.instructions_executed, 6);
        assert_eq!(report.exit_code, 7);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_blx_immediate_h_bit_selects_halfword_aligned_thumb_target() {
        let (base, mut broker) = test_broker("arm-blx-immediate-h");
        let words = [
            0xfb00_0002_u32, // blx Thumb entry at BASE + 18 (H=1)
            0xea00_0003,     // return path: branch to ARM code after Thumb body
            0xe1a0_0000,     // skipped padding
            0xe1a0_0000,     // skipped padding
            0x2007_46c0,     // padding halfword, then Thumb movs r0, #7
            0x46c0_4770,     // Thumb bx lr, then padding
            0xe3a0_7001,     // mov r7, #1
            0xef00_0000,     // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();

        assert_eq!(report.instructions_executed, 6);
        assert_eq!(report.exit_code, 7);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_stmdb_and_ldmia_save_restore_multiple_registers_with_writeback() {
        let (base, mut broker) = test_broker("arm-block-transfer");
        let words = [
            0xe3a0_0000_u32, // mov r0, #0 (exit status)
            0xe3a0_400b,     // mov r4, #11
            0xe3a0_5016,     // mov r5, #22
            0xe3a0_6021,     // mov r6, #33
            0xe3a0_702c,     // mov r7, #44
            0xe92d_00f0,     // stmdb sp!, {r4-r7}
            0xe3a0_4000,     // clear r4-r7 to prove they are loaded
            0xe3a0_5000,
            0xe3a0_6000,
            0xe3a0_7000,
            0xe8bd_00f0, // ldmia sp!, {r4-r7}
            0xe354_000b, // cmp r4, #11
            0x13a0_0001, // movne r0, #1
            0xe355_0016, // cmp r5, #22
            0x13a0_0001, // movne r0, #1
            0xe356_0021, // cmp r6, #33
            0x13a0_0001, // movne r0, #1
            0xe357_002c, // cmp r7, #44
            0x13a0_0001, // movne r0, #1
            0xe3a0_7001, // mov r7, #1 (exit)
            0xef00_0000, // svc #0
        ];
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let image = make_elf(BASE, &code);
        let report = run_elf(&image, &mut broker, 32).unwrap();

        assert_eq!(report.instructions_executed, words.len() as u64);
        assert_eq!(report.exit_code, 0);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_block_transfer_rejects_empty_user_bank_and_writeback_base_lists() {
        let (base, mut broker) = test_broker("arm-block-transfer-invalid");
        for instruction in [0xe8bd_0000_u32, 0xe8fd_0001, 0xe92d_3000] {
            let code = instruction.to_le_bytes();
            let image = make_elf(BASE, &code);
            let result = run_elf(&image, &mut broker, 4);
            assert!(matches!(
                result,
                Err(ElfError::InvalidInstruction {
                    instruction: actual,
                    thumb: false,
                    ..
                }) if actual == instruction
            ));
        }
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn arm_elf_rejects_register_offset_shift_by_register_encoding() {
        let (base, mut broker) = test_broker("arm-register-offset-invalid");
        let code = 0xe79d_2111_u32.to_le_bytes(); // invalid LDR address shift by register
        let image = make_elf(BASE, &code);
        let error = run_elf(&image, &mut broker, 4).unwrap_err();

        assert!(matches!(
            error,
            ElfError::InvalidInstruction {
                pc: BASE,
                instruction: 0xe79d_2111,
                thumb: false
            }
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn denied_guest_syscall_returns_linux_errno_without_forwarding_to_host() {
        let (base, mut broker) = test_broker("deny");
        // Thumb: r7=pivot_root(218), svc #0; r0=0, r7=exit, svc #0.
        let mut code = Vec::new();
        emit_movs(&mut code, 7, 218);
        emit_thumb(&mut code, 0xdf00);
        emit_movs(&mut code, 0, 0);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);
        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].syscall.name(), "pivot_root");
        assert_eq!(report.events[0].result, Err(1)); // EPERM
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn et_dyn_applies_arm_relative_relocation_before_running_entry() {
        let (base, mut broker) = test_broker("et-dyn-relative");
        let image = make_relative_dyn_elf();
        let report = run_elf(&image, &mut broker, 16).unwrap();
        assert_eq!(report.entry, DYN_IMAGE_BASE);
        assert_eq!(report.instruction_set, InstructionSet::Arm);
        assert_eq!(report.instructions_executed, 7);
        assert_eq!(report.exit_code, 0);
        assert!(report.events.is_empty());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn gingerbread_loader_rejects_native_pt_tls_instead_of_ignoring_it() {
        let mut image = make_elf(BASE, &[0; 8]);
        put_u16_at(&mut image, 44, 2);
        let tls = ELF_HEADER_SIZE + ELF_PROGRAM_HEADER_SIZE;
        put_u32_at(&mut image, tls, PT_TLS);
        put_u32_at(&mut image, tls + 4, 0x100);
        put_u32_at(&mut image, tls + 8, BASE);
        put_u32_at(&mut image, tls + 12, BASE);
        put_u32_at(&mut image, tls + 16, 4);
        put_u32_at(&mut image, tls + 20, 8);
        put_u32_at(&mut image, tls + 24, PF_R);
        put_u32_at(&mut image, tls + 28, 4);

        assert!(matches!(
            load_elf_image(&image, DYN_IMAGE_BASE, true, true, true),
            Err(ElfError::Unsupported(
                "native PT_TLS is unsupported; Gingerbread Bionic uses emulated TLS"
            ))
        ));
    }

    #[test]
    fn pt_interp_loads_guest_linker_and_provides_linux_arm_auxv() {
        let (base, mut broker) = test_broker("pt-interp-startup");
        let linker_path = "/system/bin/test-linker";
        let linker_host_path = broker.rootfs().map_absolute(linker_path).unwrap();
        fs::create_dir_all(linker_host_path.parent().unwrap()).unwrap();
        let linker_code = [
            0xe59d_0000_u32, // ldr r0, [sp] (argc must be zero)
            0xe350_0000,     // cmp r0, #0
            0x13a0_0001,     // movne r0, #1
            0xe59d_1010,     // ldr r1, [sp, #16] (AT_PHDR)
            0xe3a0_2001,     // mov r2, #1
            0xe1a0_2802,     // lsl r2, r2, #16
            0xe282_2034,     // add r2, r2, #52
            0xe151_0002,     // cmp r1, r2
            0x13a0_0002,     // movne r0, #2
            0xe59d_1030,     // ldr r1, [sp, #48] (AT_BASE)
            0xe3a0_2020,     // mov r2, #32
            0xe1a0_2c02,     // lsl r2, r2, #24
            0xe151_0002,     // cmp r1, r2
            0x13a0_0003,     // movne r0, #3
            0xe59d_1040,     // ldr r1, [sp, #64] (AT_ENTRY)
            0xe3a0_2001,     // mov r2, #1
            0xe1a0_2802,     // lsl r2, r2, #16
            0xe282_2c01,     // add r2, r2, #256
            0xe151_0002,     // cmp r1, r2
            0x13a0_0004,     // movne r0, #4
            0xe3a0_7001,     // mov r7, #1 (exit)
            0xef00_0000,     // svc #0
        ];
        let linker_code: Vec<u8> = linker_code.into_iter().flat_map(u32::to_le_bytes).collect();
        let mut linker = make_elf(0, &linker_code);
        put_u16_at(&mut linker, 16, ET_DYN);
        put_u32_at(&mut linker, ELF_HEADER_SIZE + 8, 0);
        put_u32_at(&mut linker, ELF_HEADER_SIZE + 12, 0);
        fs::write(linker_host_path, linker).unwrap();

        let main = make_pt_interp_elf(linker_path, &[0xef, 0, 0, 0]);
        let report = run_elf(&main, &mut broker, 32).unwrap();

        assert_eq!(report.entry, DYN_INTERPRETER_BASE);
        assert_eq!(report.instruction_set, InstructionSet::Arm);
        assert_eq!(report.instructions_executed, 22);
        assert_eq!(report.exit_code, 0);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn pt_interp_requires_linker_file_inside_guest_rootfs() {
        let (base, mut broker) = test_broker("pt-interp-missing-linker");
        let image = make_pt_interp_elf("/system/bin/missing-linker", &[0xef, 0, 0, 0]);
        let error = run_elf(&image, &mut broker, 16).unwrap_err();

        assert!(
            matches!(error, ElfError::InterpreterLoad(message) if message.contains("/system/bin/missing-linker"))
        );
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn initial_stack_preserves_guest_arguments_environment_and_execfn() {
        let argv = vec!["/system/bin/app".to_owned(), "hello world".to_owned()];
        let env = vec!["MODE=test".to_owned()];
        let info = InitialStackInfo {
            phdr_address: 0x10100,
            phent: ELF_PROGRAM_HEADER_SIZE as u32,
            phnum: 3,
            interpreter_base: 0x2000_0000,
            program_entry: 0x10201,
            identity: VirtualIdentity {
                uid: 10042,
                gid: 10043,
                pid: 29,
            },
        };
        let (stack_pointer, stack) = build_initial_stack(info, &argv, &env).unwrap();
        let word = |index: usize| {
            let offset = (stack_pointer - STACK_BASE) as usize + index * 4;
            u32::from_le_bytes(stack[offset..offset + 4].try_into().unwrap())
        };
        let c_string = |address: u32| {
            let offset = (address - STACK_BASE) as usize;
            let bytes = &stack[offset..];
            let end = bytes.iter().position(|byte| *byte == 0).unwrap();
            std::str::from_utf8(&bytes[..end]).unwrap().to_owned()
        };

        assert_eq!(word(0), 2);
        assert_eq!(c_string(word(1)), argv[0]);
        assert_eq!(c_string(word(2)), argv[1]);
        assert_eq!(word(3), 0); // argv terminator
        assert_eq!(c_string(word(4)), env[0]);
        assert_eq!(word(5), 0); // envp terminator
        let auxv = 6;
        assert_eq!(word(auxv), AT_PHDR);
        assert_eq!(word(auxv + 1), info.phdr_address);
        assert_eq!(word(auxv + 2 * 6 + 1), info.program_entry);
        let execfn = auxv + 2 * 16;
        assert_eq!(word(execfn), AT_EXECFN);
        assert_eq!(word(execfn + 1), word(1));

        let nul_argument = vec!["bad\0argument".to_owned()];
        assert!(matches!(
            build_initial_stack(info, &nul_argument, &[]),
            Err(ElfError::Invalid(
                "guest argv/env string contains a NUL byte"
            ))
        ));
        let oversized = vec!["x".repeat(STACK_SIZE)];
        assert!(matches!(
            build_initial_stack(info, &oversized, &[]),
            Err(ElfError::Bounds("guest argv/env exceed the stack limit"))
        ));
    }

    #[test]
    fn et_dyn_rejects_symbol_relocations_and_library_dependencies() {
        let (base, mut broker) = test_broker("et-dyn-unsupported-relocations");
        let mut image = make_relative_dyn_elf();
        put_u32_at(&mut image, 0x100 + 100, (1 << 8) | R_ARM_RELATIVE);
        assert!(matches!(
            run_elf(&image, &mut broker, 16),
            Err(ElfError::Unsupported(
                "R_ARM_RELATIVE relocation has a non-zero symbol index"
            ))
        ));

        let mut image = make_relative_dyn_elf();
        put_u32_at(&mut image, 0x100 + 64, DT_NEEDED);
        assert!(matches!(
            run_elf(&image, &mut broker, 16),
            Err(ElfError::Unsupported(
                "DT_NEEDED shared-library dependencies require an ELF interpreter"
            ))
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn needed_library_lookup_uses_guest_library_directories_and_rejects_traversal() {
        let (base, broker) = test_broker("needed-library-paths");
        let root = broker.rootfs().clone();
        let expected = root.map_absolute("/system/lib/libprobe.so").unwrap();
        fs::create_dir_all(expected.parent().unwrap()).unwrap();
        fs::write(&expected, b"guest library").unwrap();
        assert_eq!(
            resolve_library_path(&root, "libprobe.so").unwrap(),
            expected
        );
        assert!(matches!(
            resolve_library_path(&root, "../outside.so"),
            Err(ElfError::Unsupported(
                "relative DT_NEEDED names must be plain shared-library filenames"
            ))
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[cfg(unix)]
    #[test]
    fn needed_library_lookup_rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let (base, broker) = test_broker("needed-library-symlink-escape");
        let root = broker.rootfs().clone();
        let outside = base.join("outside-library.so");
        fs::write(&outside, b"outside").unwrap();
        let guest_link = root.map_absolute("/system/lib/libescape.so").unwrap();
        fs::create_dir_all(guest_link.parent().unwrap()).unwrap();
        symlink(&outside, &guest_link).unwrap();
        assert!(matches!(
            resolve_library_path(&root, "libescape.so"),
            Err(ElfError::LibraryLoad(_))
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn rejects_non_arm_and_malformed_pt_interp_images() {
        let code = [0u8; 8];
        let mut image = make_elf(BASE, &code);
        put_u16_at(&mut image, 18, 3);
        let (base, mut broker) = test_broker("machine");
        assert!(matches!(
            run_elf(&image, &mut broker, 1),
            Err(ElfError::Unsupported(_))
        ));

        let mut image = make_elf(BASE, &code);
        put_u32_at(&mut image, ELF_HEADER_SIZE, PT_INTERP);
        assert!(matches!(
            run_elf(&image, &mut broker, 1),
            Err(ElfError::Invalid(_))
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn instruction_budget_stops_guest_loops() {
        let (base, mut broker) = test_broker("loop");
        let image = make_elf(BASE | 1, &0xe7feu16.to_le_bytes());
        assert!(matches!(
            run_elf(&image, &mut broker, 7),
            Err(ElfError::StepLimit { limit: 7 })
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb_add_sub_register_and_immediate_forms_update_flags_and_branch() {
        let (base, mut broker) = test_broker("thumb-add-sub");
        let halfwords = [
            0x2007u16, // movs r0, #7
            0x2105,    // movs r1, #5
            0x1840,    // adds r0, r0, r1 -> 12
            0x1a40,    // subs r0, r0, r1 -> 7
            0x3001,    // adds r0, #1 -> 8
            0x3801,    // subs r0, #1 -> 7
            0x2807,    // cmp r0, #7
            0xd002,    // beq over the failure exit
            0x2001, 0x2701, 0xdf00, // failure: exit(1)
            0x2000, 0x2701, 0xdf00, // success: exit(0)
        ];
        let code: Vec<u8> = halfwords.into_iter().flat_map(u16::to_le_bytes).collect();
        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();

        assert_eq!(report.exit_code, 0);
        assert_eq!(report.instructions_executed, 11);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn thumb_reserved_conditional_branch_code_is_rejected() {
        let (base, mut broker) = test_broker("thumb-reserved-cond");
        let image = make_elf(BASE | 1, &0xde00u16.to_le_bytes());
        assert!(matches!(
            run_elf(&image, &mut broker, 4),
            Err(ElfError::InvalidInstruction {
                pc: BASE,
                instruction: 0xde00,
                thumb: true
            })
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn unsupported_thumb_instruction_stops_without_forwarding() {
        let (base, mut broker) = test_broker("unsupported-instruction");
        let image = make_elf(BASE | 1, &0xffffu16.to_le_bytes());
        assert!(matches!(
            run_elf(&image, &mut broker, 4),
            Err(ElfError::InvalidInstruction { thumb: true, .. })
        ));
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn malformed_elf_is_rejected_before_execution() {
        let (base, mut broker) = test_broker("malformed");
        assert!(matches!(
            run_elf(b"not elf", &mut broker, 10),
            Err(ElfError::Bounds(_))
        ));
        let mut image = make_elf(BASE, &[0; 8]);
        put_u16_at(&mut image, 40, 0);
        assert!(matches!(
            run_elf(&image, &mut broker, 10),
            Err(ElfError::Invalid("invalid ELF32 header size"))
        ));
        let _ = fs::remove_dir_all(base);
    }
}
