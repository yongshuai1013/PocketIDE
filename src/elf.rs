use std::error::Error;
use std::fmt;

use crate::broker::{
    BrokerError, BrokerValue, GuestSyscall, OpenFlags, SyscallBroker, MAX_TRANSFER_BYTES,
};
use crate::rootfs::RootFsError;

const ELF_HEADER_SIZE: usize = 52;
const ELF_PROGRAM_HEADER_SIZE: usize = 32;
const ELFCLASS32: u8 = 1;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_ARM: u16 = 40;
const PT_LOAD: u32 = 1;
const PT_INTERP: u32 = 3;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const MAX_IMAGE_BYTES: usize = 32 * 1024 * 1024;
const STACK_BASE: u32 = 0x7ff0_0000;
const STACK_SIZE: usize = 64 * 1024;
const MAX_PATH_BYTES: usize = 4096;

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
    pub exit_code: i32,
    pub events: Vec<ElfSyscallEvent>,
}

#[derive(Debug)]
pub enum ElfError {
    Invalid(&'static str),
    Unsupported(&'static str),
    Bounds(&'static str),
    MemoryAccess {
        address: u32,
        access: &'static str,
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
            Self::MemoryAccess { address, access } => {
                write!(f, "guest memory {access} fault at 0x{address:08x}")
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

    fn locate(
        &self,
        address: u32,
        length: usize,
        permission: u32,
    ) -> Result<(&Segment, usize), ElfError> {
        let end = address as u64 + length as u64;
        for segment in &self.segments {
            if address >= segment.start
                && end <= segment.end()
                && segment.flags & permission == permission
            {
                return Ok((segment, (address - segment.start) as usize));
            }
        }
        Err(ElfError::MemoryAccess {
            address,
            access: permission_name(permission),
        })
    }

    fn read(&self, address: u32, length: usize) -> Result<Vec<u8>, ElfError> {
        if length == 0 {
            return Ok(Vec::new());
        }
        let (segment, offset) = self.locate(address, length, PF_R)?;
        Ok(segment.bytes[offset..offset + length].to_vec())
    }

    fn write(&mut self, address: u32, bytes: &[u8]) -> Result<(), ElfError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let (segment, offset) = self.locate_mut(address, bytes.len(), PF_W)?;
        segment.bytes[offset..offset + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    fn check_write(&self, address: u32, length: usize) -> Result<(), ElfError> {
        if length == 0 {
            return Ok(());
        }
        self.locate(address, length, PF_W).map(|_| ())
    }

    fn fetch(&self, address: u32, length: usize) -> Result<Vec<u8>, ElfError> {
        if length == 0 {
            return Ok(Vec::new());
        }
        let (segment, offset) = self.locate(address, length, PF_X)?;
        Ok(segment.bytes[offset..offset + length].to_vec())
    }

    fn locate_mut(
        &mut self,
        address: u32,
        length: usize,
        permission: u32,
    ) -> Result<(&mut Segment, usize), ElfError> {
        let end = address as u64 + length as u64;
        for segment in &mut self.segments {
            if address >= segment.start
                && end <= segment.end()
                && segment.flags & permission == permission
            {
                let offset = (address - segment.start) as usize;
                return Ok((segment, offset));
            }
        }
        Err(ElfError::MemoryAccess {
            address,
            access: permission_name(permission),
        })
    }
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
    instruction_set: InstructionSet,
    stack_pointer: u32,
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

fn load_elf(bytes: &[u8]) -> Result<LoadedImage, ElfError> {
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
    if u16_at(bytes, 16)? != ET_EXEC {
        return Err(ElfError::Unsupported(
            "only statically linked ET_EXEC images are supported (not PIE/ET_DYN)",
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

    let mut segments = Vec::new();
    let mut mapped_bytes = 0usize;
    let mut has_interpreter = false;
    for index in 0..phnum {
        let offset = phoff + index * phentsize;
        let kind = u32_at(bytes, offset)?;
        if kind == PT_INTERP {
            has_interpreter = true;
        }
        if kind != PT_LOAD {
            continue;
        }
        let file_offset = u32_at(bytes, offset + 4)? as usize;
        let virtual_address = u32_at(bytes, offset + 8)?;
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
        });
    }
    if has_interpreter {
        return Err(ElfError::Unsupported(
            "dynamic ELF interpreters and shared-library loading are not implemented",
        ));
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

    let thumb = raw_entry & 1 != 0;
    let entry = raw_entry & !1;
    if (!thumb && entry & 3 != 0) || (thumb && entry & 1 != 0) {
        return Err(ElfError::Invalid(
            "entry point has invalid instruction alignment",
        ));
    }
    if !segments.iter().any(|segment| {
        entry >= segment.start && (entry as u64) < segment.end() && segment.flags & PF_X != 0
    }) {
        return Err(ElfError::Invalid(
            "entry point is not in an executable PT_LOAD segment",
        ));
    }

    let stack_end = STACK_BASE as u64 + STACK_SIZE as u64;
    if segments
        .iter()
        .any(|segment| (segment.start as u64) < stack_end && segment.end() > STACK_BASE as u64)
    {
        return Err(ElfError::Unsupported(
            "guest image overlaps the reserved stack region",
        ));
    }
    segments.push(Segment {
        start: STACK_BASE,
        bytes: vec![0; STACK_SIZE],
        flags: PF_R | PF_W,
    });

    Ok(LoadedImage {
        memory: GuestMemory::new(segments),
        entry,
        instruction_set: if thumb {
            InstructionSet::Thumb
        } else {
            InstructionSet::Arm
        },
        stack_pointer: (STACK_BASE + STACK_SIZE as u32) & !7,
    })
}

/// Load and execute one static ELF32 ARM guest under a small ARMv7/Thumb
/// interpreter. EABI `svc #0` file/identity calls are routed only through the
/// supplied broker; no host syscall is forwarded directly.
///
/// This is a host-side compatibility prototype, not a general ARM emulator,
/// Linux kernel, Android runtime, or security boundary. Unsupported guest
/// instructions stop execution explicitly. Use static ET_EXEC probes built for
/// ARM EABI; dynamic linking, VFP/NEON, MMU, signals, threads, and Android
/// framework services are outside this runner's scope.
pub fn run_elf(
    image: &[u8],
    broker: &mut SyscallBroker,
    max_steps: u64,
) -> Result<ElfExecutionReport, ElfError> {
    let loaded = load_elf(image)?;
    let mut cpu = Cpu {
        regs: [0; 16],
        pc: loaded.entry,
        thumb: loaded.instruction_set == InstructionSet::Thumb,
        n: false,
        z: false,
        c: false,
        v: false,
        memory: loaded.memory,
        events: Vec::new(),
        instructions: 0,
    };
    cpu.regs[13] = loaded.stack_pointer;

    let exit_code = loop {
        if cpu.instructions >= max_steps {
            return Err(ElfError::StepLimit { limit: max_steps });
        }
        cpu.instructions += 1;
        let instruction_pc = cpu.pc;
        let flow = if cpu.thumb {
            cpu.step_thumb(broker, instruction_pc)?
        } else {
            cpu.step_arm(broker, instruction_pc)?
        };
        if let Some(status) = flow {
            break status;
        }
    };

    Ok(ElfExecutionReport {
        entry: loaded.entry,
        instruction_set: loaded.instruction_set,
        instructions_executed: cpu.instructions,
        exit_code,
        events: cpu.events,
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
    memory: GuestMemory,
    events: Vec<ElfSyscallEvent>,
    instructions: u64,
}

impl Cpu {
    fn step_thumb(
        &mut self,
        broker: &mut SyscallBroker,
        instruction_pc: u32,
    ) -> Result<Option<i32>, ElfError> {
        let bytes = self.memory.fetch(instruction_pc, 2)?;
        let instruction = u16::from_le_bytes([bytes[0], bytes[1]]);
        self.pc = instruction_pc.wrapping_add(2);
        self.regs[15] = instruction_pc.wrapping_add(4);

        if instruction & 0xff00 == 0xdf00 {
            return self.handle_svc(broker, instruction_pc);
        }
        if instruction == 0xbf00 {
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
                old.wrapping_sub(immediate)
            } else {
                old.wrapping_add(immediate)
            };
            self.set_nz(self.regs[rd]);
            return Ok(None);
        }
        if instruction & 0xf800 == 0x2800 {
            let rd = ((instruction >> 8) & 7) as usize;
            let result = self.regs[rd].wrapping_sub((instruction & 0xff) as u32);
            self.set_nz(result);
            self.c = self.regs[rd] >= (instruction & 0xff) as u32;
            return Ok(None);
        }
        if instruction & 0xfc00 == 0x4400 {
            let operation = (instruction >> 8) & 3;
            let rd = ((instruction & 7) | ((instruction >> 4) & 8)) as usize;
            let rm = ((instruction >> 3) & 0xf) as usize;
            match operation {
                0 => self.regs[rd] = self.regs[rd].wrapping_add(self.regs[rm]),
                1 => {
                    let result = self.regs[rd].wrapping_sub(self.regs[rm]);
                    self.set_nz(result);
                    self.c = self.regs[rd] >= self.regs[rm];
                    return Ok(None);
                }
                2 => self.regs[rd] = self.regs[rm],
                3 => {
                    let target = self.regs[rm];
                    self.thumb = target & 1 != 0;
                    self.pc = target & if self.thumb { !1 } else { !3 };
                    self.regs[15] = self.pc;
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
        if instruction & 0xf000 == 0xd000 && instruction & 0x0f00 != 0x0f00 {
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
        if instruction & 0xfe00 == 0x1800 {
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
                self.regs[rn].wrapping_sub(operand)
            } else {
                self.regs[rn].wrapping_add(operand)
            };
            self.set_nz(self.regs[rd]);
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
        if !self.condition_passed(condition) {
            return Ok(None);
        }
        if instruction & 0x0f00_0000 == 0x0f00_0000 {
            return self.handle_svc(broker, instruction_pc);
        }
        if instruction & 0x0e00_0000 == 0x0a00_0000 {
            let immediate = sign_extend(instruction & 0x00ff_ffff, 24) << 2;
            self.pc = instruction_pc
                .wrapping_add(8)
                .wrapping_add(immediate as u32);
            self.regs[15] = self.pc;
            return Ok(None);
        }
        if instruction & 0x0c00_0000 == 0x0400_0000 {
            if instruction & (1 << 25) != 0 {
                return Err(ElfError::InvalidInstruction {
                    pc: instruction_pc,
                    instruction,
                    thumb: false,
                });
            }
            let load = instruction & (1 << 20) != 0;
            let pre_index = instruction & (1 << 24) != 0;
            let up = instruction & (1 << 23) != 0;
            let byte = instruction & (1 << 22) != 0;
            let writeback = instruction & (1 << 21) != 0;
            let rn = ((instruction >> 16) & 0xf) as usize;
            let rd = ((instruction >> 12) & 0xf) as usize;
            let offset = instruction & 0xfff;
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
        if instruction & 0x0c00_0000 == 0x0000_0000 && instruction & (1 << 25) != 0 {
            let opcode = (instruction >> 21) & 0xf;
            let set_flags = instruction & (1 << 20) != 0;
            let rn = ((instruction >> 16) & 0xf) as usize;
            let rd = ((instruction >> 12) & 0xf) as usize;
            let rotate = ((instruction >> 8) & 0xf) * 2;
            let immediate = (instruction & 0xff).rotate_right(rotate);
            let left = self.regs[rn];
            let result = match opcode {
                0 => left & immediate,
                1 => left ^ immediate,
                2 => left.wrapping_sub(immediate),
                4 => left.wrapping_add(immediate),
                10 => left.wrapping_sub(immediate),
                12 => left | immediate,
                13 => immediate,
                14 => left & !immediate,
                15 => !immediate,
                _ => {
                    return Err(ElfError::InvalidInstruction {
                        pc: instruction_pc,
                        instruction,
                        thumb: false,
                    })
                }
            };
            if opcode != 10 {
                self.regs[rd] = result;
            }
            if set_flags || opcode == 10 {
                self.set_nz(result);
                if matches!(opcode, 2 | 10) {
                    self.c = left >= immediate;
                }
            }
            return Ok(None);
        }

        Err(ElfError::InvalidInstruction {
            pc: instruction_pc,
            instruction,
            thumb: false,
        })
    }

    fn handle_svc(
        &mut self,
        broker: &mut SyscallBroker,
        instruction_pc: u32,
    ) -> Result<Option<i32>, ElfError> {
        let number = self.regs[7];
        if number == 1 || number == 252 {
            return Ok(Some(self.regs[0] as i32));
        }

        let args = [self.regs[0], self.regs[1], self.regs[2], self.regs[3]];
        let operation: GuestSyscall = match number {
            3 => {
                let fd = args[0] as i32;
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
            20 | 224 => GuestSyscall::GetPid,
            24 | 49 | 199 => GuestSyscall::GetUid,
            47 | 50 | 200 => GuestSyscall::GetGid,
            322 => {
                if args[0] as i32 != -100 {
                    self.record_errno(
                        instruction_pc,
                        GuestSyscall::Control {
                            name: "openat".into(),
                        },
                        9,
                    );
                    self.regs[0] = negative_errno(9);
                    return Ok(None);
                }
                match self.read_c_string(args[1]) {
                    Ok(path) => match linux_open_flags(args[2]) {
                        Some(flags) => GuestSyscall::Open { path, flags },
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
                }
            }
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
                                    "read destination is not writable",
                                ),
                            })?;
                        bytes.len() as u32
                    }
                    BrokerValue::Count(count) => *count as u32,
                    BrokerValue::Identity(identity) => *identity,
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

    fn record_errno(&mut self, pc: u32, syscall: GuestSyscall, errno: i32) {
        self.events.push(ElfSyscallEvent {
            step: self.instructions,
            pc,
            syscall,
            result: Err(errno),
        });
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

    fn read_u32(&self, address: u32) -> Result<u32, ElfError> {
        let bytes = self.memory.read(address, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn set_nz(&mut self, value: u32) {
        self.n = value & 0x8000_0000 != 0;
        self.z = value == 0;
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

fn sign_extend(value: u32, bits: u32) -> i32 {
    ((value << (32 - bits)) as i32) >> (32 - bits)
}

fn linux_open_flags(flags: u32) -> Option<OpenFlags> {
    const O_ACCMODE: u32 = 3;
    const O_CREAT: u32 = 0x40;
    const O_TRUNC: u32 = 0x200;
    const SUPPORTED: u32 = O_ACCMODE | O_CREAT | O_TRUNC;
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
    })
}

fn syscall_name(number: u32) -> String {
    match number {
        3 => "read".into(),
        4 => "write".into(),
        5 => "open".into(),
        6 => "close".into(),
        20 => "getpid".into(),
        21 => "mount".into(),
        24 | 199 => "getuid".into(),
        26 => "ptrace".into(),
        47 | 200 => "getgid".into(),
        49 => "geteuid".into(),
        50 => "getegid".into(),
        52 => "umount2".into(),
        88 => "reboot".into(),
        224 => "gettid".into(),
        252 => "exit_group".into(),
        322 => "openat".into(),
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
            match error.kind() {
                std::io::ErrorKind::NotFound => 2,          // ENOENT
                std::io::ErrorKind::PermissionDenied => 13, // EACCES
                std::io::ErrorKind::AlreadyExists => 17,    // EEXIST
                std::io::ErrorKind::InvalidInput => 22,     // EINVAL
                _ => 5,                                     // EIO
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
    fn denied_guest_syscall_returns_linux_errno_without_forwarding_to_host() {
        let (base, mut broker) = test_broker("deny");
        // Thumb: r7=mount(21), svc #0; r0=0, r7=exit, svc #0.
        let mut code = Vec::new();
        emit_movs(&mut code, 7, 21);
        emit_thumb(&mut code, 0xdf00);
        emit_movs(&mut code, 0, 0);
        emit_movs(&mut code, 7, 1);
        emit_thumb(&mut code, 0xdf00);
        let image = make_elf(BASE | 1, &code);
        let report = run_elf(&image, &mut broker, 16).unwrap();
        assert_eq!(report.events.len(), 1);
        assert_eq!(report.events[0].syscall.name(), "mount");
        assert_eq!(report.events[0].result, Err(1)); // EPERM
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn rejects_non_arm_and_dynamic_elf_images() {
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
            Err(ElfError::Unsupported(_))
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
