//! A32 data-processing decoder and ALU helpers used by the restricted ELF runner.
//!
//! This module deliberately implements one well-defined ARM instruction family
//! rather than pretending to be a complete ARM emulator. Keeping operand decode,
//! barrel-shifter edge cases, and arithmetic flags here makes it possible to add
//! and test more instruction families without growing the ELF loader's dispatch.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Flags {
    pub n: bool,
    pub z: bool,
    pub c: bool,
    pub v: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DataProcessingResult {
    pub destination: usize,
    pub result: u32,
    pub writes_destination: bool,
    pub flags: Option<Flags>,
}

#[derive(Debug, Clone, Copy)]
enum ShiftType {
    Lsl,
    Lsr,
    Asr,
    Ror,
}

#[derive(Debug, Clone, Copy)]
enum ShiftAmount {
    Immediate(u8),
    Register(u8),
}

#[derive(Debug, Clone, Copy)]
struct ShiftedOperand {
    value: u32,
    carry: Option<bool>,
}

/// Decode and evaluate an A32 data-processing instruction.
///
/// `None` means the encoding is not part of the supported data-processing
/// subset (including encodings reserved for multiply, status-register, or
/// extension instructions). The caller supplies architectural register values,
/// with r15 already set to the instruction's visible PC value.
pub(crate) fn execute_data_processing(
    instruction: u32,
    registers: &[u32; 16],
    flags: Flags,
) -> Option<DataProcessingResult> {
    if instruction & 0x0c00_0000 != 0 {
        return None;
    }
    // CLZ uses the same broad primary opcode class but a reserved Operand2
    // pattern; do not reinterpret it as RSB with Rn=PC.
    if instruction & 0x0fff_0ff0 == 0x016f_0f10 {
        return None;
    }

    let immediate_operand = instruction & (1 << 25) != 0;
    let opcode = ((instruction >> 21) & 0xf) as u8;
    let encoded_set_flags = instruction & (1 << 20) != 0;
    let rn = ((instruction >> 16) & 0xf) as usize;
    let destination = ((instruction >> 12) & 0xf) as usize;
    let test_operation = matches!(opcode, 8..=11);

    // TST/TEQ/CMP/CMN have no destination write and require S=1 with Rd=0.
    if test_operation && (!encoded_set_flags || destination != 0) {
        return None;
    }
    let set_flags = encoded_set_flags || test_operation;
    // Writing PC while setting flags would restore CPSR from SPSR, which is not
    // modeled in this user-mode prototype.
    if destination == 15 && set_flags && !test_operation {
        return None;
    }

    let operand = if immediate_operand {
        let rotate = ((instruction >> 8) & 0xf) * 2;
        let value = (instruction & 0xff).rotate_right(rotate);
        ShiftedOperand {
            value,
            carry: (rotate != 0).then_some(value & 0x8000_0000 != 0),
        }
    } else {
        decode_register_operand(instruction, registers, flags.c)?
    };

    let left = registers[rn];
    let (result, carry, overflow) = match opcode {
        0 => (
            left & operand.value,
            operand.carry.unwrap_or(flags.c),
            flags.v,
        ), // AND
        1 => (
            left ^ operand.value,
            operand.carry.unwrap_or(flags.c),
            flags.v,
        ), // EOR
        2 => sub_with_carry(left, operand.value, true), // SUB
        3 => sub_with_carry(operand.value, left, true), // RSB
        4 => add_with_carry(left, operand.value, false), // ADD
        5 => add_with_carry(left, operand.value, flags.c), // ADC
        6 => sub_with_carry(left, operand.value, flags.c), // SBC
        7 => sub_with_carry(operand.value, left, flags.c), // RSC
        8 => (
            left & operand.value,
            operand.carry.unwrap_or(flags.c),
            flags.v,
        ), // TST
        9 => (
            left ^ operand.value,
            operand.carry.unwrap_or(flags.c),
            flags.v,
        ), // TEQ
        10 => sub_with_carry(left, operand.value, true), // CMP
        11 => add_with_carry(left, operand.value, false), // CMN
        12 => (
            left | operand.value,
            operand.carry.unwrap_or(flags.c),
            flags.v,
        ), // ORR
        13 => (operand.value, operand.carry.unwrap_or(flags.c), flags.v), // MOV
        14 => (
            left & !operand.value,
            operand.carry.unwrap_or(flags.c),
            flags.v,
        ), // BIC
        15 => (!operand.value, operand.carry.unwrap_or(flags.c), flags.v), // MVN
        _ => return None,
    };

    Some(DataProcessingResult {
        destination,
        result,
        writes_destination: !test_operation,
        flags: set_flags.then_some(Flags {
            n: result & 0x8000_0000 != 0,
            z: result == 0,
            c: carry,
            v: overflow,
        }),
    })
}

fn decode_register_operand(
    instruction: u32,
    registers: &[u32; 16],
    carry_in: bool,
) -> Option<ShiftedOperand> {
    let rm = (instruction & 0xf) as usize;
    // PC operands and PC-specified shift amounts have special pipeline values;
    // defer those less-common encodings rather than silently compute the wrong one.
    if rm == 15 {
        return None;
    }
    let shift_type = match (instruction >> 5) & 3 {
        0 => ShiftType::Lsl,
        1 => ShiftType::Lsr,
        2 => ShiftType::Asr,
        _ => ShiftType::Ror,
    };
    let by_register = instruction & (1 << 4) != 0;
    let amount = if by_register {
        if instruction & (1 << 7) != 0 {
            return None;
        }
        let rs = ((instruction >> 8) & 0xf) as usize;
        if rs == 15 {
            return None;
        }
        ShiftAmount::Register((registers[rs] & 0xff) as u8)
    } else {
        ShiftAmount::Immediate(((instruction >> 7) & 0x1f) as u8)
    };
    Some(shift(registers[rm], shift_type, amount, carry_in))
}

fn shift(
    value: u32,
    kind: ShiftType,
    encoded_amount: ShiftAmount,
    carry_in: bool,
) -> ShiftedOperand {
    let (amount, by_register) = match encoded_amount {
        ShiftAmount::Immediate(amount) => (amount as u32, false),
        ShiftAmount::Register(amount) => (amount as u32, true),
    };
    if by_register && amount == 0 {
        return ShiftedOperand { value, carry: None };
    }

    match kind {
        ShiftType::Lsl => match amount {
            0 => ShiftedOperand { value, carry: None },
            1..=31 => ShiftedOperand {
                value: value << amount,
                carry: Some((value >> (32 - amount)) & 1 != 0),
            },
            32 => ShiftedOperand {
                value: 0,
                carry: Some(value & 1 != 0),
            },
            _ => ShiftedOperand {
                value: 0,
                carry: Some(false),
            },
        },
        ShiftType::Lsr => {
            let amount = if !by_register && amount == 0 {
                32
            } else {
                amount
            };
            match amount {
                1..=31 => ShiftedOperand {
                    value: value >> amount,
                    carry: Some((value >> (amount - 1)) & 1 != 0),
                },
                32 => ShiftedOperand {
                    value: 0,
                    carry: Some(value & 0x8000_0000 != 0),
                },
                _ => ShiftedOperand {
                    value: 0,
                    carry: Some(false),
                },
            }
        }
        ShiftType::Asr => {
            let amount = if !by_register && amount == 0 {
                32
            } else {
                amount
            };
            if amount >= 32 {
                let sign = value & 0x8000_0000 != 0;
                ShiftedOperand {
                    value: if sign { u32::MAX } else { 0 },
                    carry: Some(sign),
                }
            } else {
                ShiftedOperand {
                    value: ((value as i32) >> amount) as u32,
                    carry: Some((value >> (amount - 1)) & 1 != 0),
                }
            }
        }
        ShiftType::Ror => {
            if !by_register && amount == 0 {
                ShiftedOperand {
                    value: ((carry_in as u32) << 31) | (value >> 1),
                    carry: Some(value & 1 != 0),
                }
            } else {
                let rotation = amount % 32;
                if rotation == 0 {
                    ShiftedOperand {
                        value,
                        carry: Some(value & 0x8000_0000 != 0),
                    }
                } else {
                    let result = value.rotate_right(rotation);
                    ShiftedOperand {
                        value: result,
                        carry: Some(result & 0x8000_0000 != 0),
                    }
                }
            }
        }
    }
}

fn add_with_carry(left: u32, right: u32, carry_in: bool) -> (u32, bool, bool) {
    let sum = left as u64 + right as u64 + u64::from(carry_in);
    let result = sum as u32;
    let carry = sum >> 32 != 0;
    let overflow = (!(left ^ right) & (left ^ result) & 0x8000_0000) != 0;
    (result, carry, overflow)
}

fn sub_with_carry(left: u32, right: u32, carry_in: bool) -> (u32, bool, bool) {
    add_with_carry(left, !right, carry_in)
}

#[cfg(test)]
mod tests {
    use super::*;

    const INITIAL_FLAGS: Flags = Flags {
        n: false,
        z: false,
        c: false,
        v: false,
    };

    fn instruction(opcode: u8, set_flags: bool, rn: u8, rd: u8, operand2: u32) -> u32 {
        0xe000_0000
            | ((opcode as u32) << 21)
            | ((set_flags as u32) << 20)
            | ((rn as u32) << 16)
            | ((rd as u32) << 12)
            | operand2
    }

    fn execute(instruction: u32, registers: [u32; 16], flags: Flags) -> DataProcessingResult {
        execute_data_processing(instruction, &registers, flags).unwrap()
    }

    #[test]
    fn register_operand_supports_shifted_add_and_register_shift_amount() {
        let mut registers = [0; 16];
        registers[0] = 5;
        registers[1] = 3;
        // ADD r2, r0, r1, LSL #2
        let result = execute(instruction(4, false, 0, 2, 0x101), registers, INITIAL_FLAGS);
        assert_eq!(result.result, 17);
        assert!(result.writes_destination);

        registers[1] = 0x8000_0001;
        registers[3] = 1;
        // MOVS r4, r1, LSR r3
        let movs = instruction(13, true, 0, 4, (1 << 4) | (3 << 8) | (1 << 5) | 1);
        let result = execute(movs, registers, INITIAL_FLAGS);
        assert_eq!(result.result, 0x4000_0000);
        assert!(result.flags.unwrap().c);
    }

    #[test]
    fn barrel_shifter_covers_zero_shift_rrx_and_large_register_shifts() {
        let rrx = shift(3, ShiftType::Ror, ShiftAmount::Immediate(0), true);
        assert_eq!(rrx.value, 0x8000_0001);
        assert_eq!(rrx.carry, Some(true));

        let by_zero = shift(0x8000_0001, ShiftType::Lsl, ShiftAmount::Register(0), false);
        assert_eq!(by_zero.value, 0x8000_0001);
        assert_eq!(by_zero.carry, None);

        let by_32 = shift(
            0x8000_0001,
            ShiftType::Lsl,
            ShiftAmount::Register(32),
            false,
        );
        assert_eq!(by_32.value, 0);
        assert_eq!(by_32.carry, Some(true));
    }

    #[test]
    fn all_sixteen_data_processing_opcodes_produce_the_expected_result() {
        let mut registers = [0; 16];
        registers[0] = 15;
        registers[1] = 3;
        let flags = Flags {
            c: true,
            ..INITIAL_FLAGS
        };
        let expected = [
            3,
            12,
            12,
            0xffff_fff4,
            18,
            19,
            12,
            0xffff_fff4,
            3,
            12,
            12,
            18,
            15,
            3,
            12,
            0xffff_fffc,
        ];

        for (opcode, expected_result) in expected.into_iter().enumerate() {
            let test_operation = matches!(opcode, 8..=11);
            let instruction = instruction(
                opcode as u8,
                test_operation,
                0,
                if test_operation { 0 } else { 2 },
                1,
            );
            let result = execute(instruction, registers, flags);
            assert_eq!(result.result, expected_result, "opcode {opcode}");
            assert_eq!(
                result.writes_destination, !test_operation,
                "opcode {opcode}"
            );
        }
    }

    #[test]
    fn arithmetic_flags_report_unsigned_carry_and_signed_overflow() {
        let mut registers = [0; 16];
        registers[0] = 0x7fff_ffff;
        registers[1] = 1;
        // ADDS r2, r0, r1
        let adds = instruction(4, true, 0, 2, 1);
        let result = execute(adds, registers, INITIAL_FLAGS);
        assert_eq!(result.result, 0x8000_0000);
        assert_eq!(
            result.flags,
            Some(Flags {
                n: true,
                z: false,
                c: false,
                v: true
            })
        );

        registers[0] = 0;
        registers[1] = 1;
        // SUBS r2, r0, r1 -> borrow, no signed overflow.
        let subs = instruction(2, true, 0, 2, 1);
        let result = execute(subs, registers, INITIAL_FLAGS);
        assert_eq!(result.result, u32::MAX);
        assert_eq!(
            result.flags,
            Some(Flags {
                n: true,
                z: false,
                c: false,
                v: false
            })
        );
    }

    #[test]
    fn compare_updates_flags_without_writing_destination() {
        let mut registers = [0; 16];
        registers[0] = 42;
        registers[1] = 42;
        // CMP r0, r1
        let cmp = instruction(10, true, 0, 0, 1);
        let result = execute(cmp, registers, INITIAL_FLAGS);
        assert!(!result.writes_destination);
        assert_eq!(result.result, 0);
        assert_eq!(
            result.flags,
            Some(Flags {
                n: false,
                z: true,
                c: true,
                v: false
            })
        );
    }

    #[test]
    fn logical_operations_preserve_overflow_and_use_shifter_carry_when_present() {
        let mut registers = [0; 16];
        registers[0] = u32::MAX;
        let flags = Flags {
            n: false,
            z: false,
            c: true,
            v: true,
        };
        // MOVS r1, #1 (no rotate): C/V are preserved.
        let movs = instruction(13, true, 0, 1, (1 << 25) | 1);
        assert_eq!(
            execute(movs, registers, flags).flags,
            Some(Flags {
                n: false,
                z: false,
                c: true,
                v: true
            })
        );

        // MOVS r1, #0x80000000 (ROR #2): shifter updates C.
        let rotated = instruction(13, true, 0, 1, (1 << 25) | (1 << 8) | 2);
        let result = execute(rotated, registers, flags);
        assert_eq!(result.result, 0x8000_0000);
        assert_eq!(
            result.flags,
            Some(Flags {
                n: true,
                z: false,
                c: true,
                v: true
            })
        );
    }

    #[test]
    fn reserved_or_privileged_encodings_are_not_misdecoded_as_alu_operations() {
        let registers = [0; 16];
        let bx_r0 = 0xe12f_ff10;
        assert!(execute_data_processing(bx_r0, &registers, INITIAL_FLAGS).is_none());
        let clz_r0_r1 = 0xe16f_0f11;
        assert!(execute_data_processing(clz_r0_r1, &registers, INITIAL_FLAGS).is_none());
        let multiply = 0xe000_0090;
        assert!(execute_data_processing(multiply, &registers, INITIAL_FLAGS).is_none());
        // CMP without S and test opcode with nonzero Rd are unpredictable encodings.
        assert!(execute_data_processing(
            instruction(10, false, 0, 0, 1),
            &registers,
            INITIAL_FLAGS
        )
        .is_none());
        assert!(
            execute_data_processing(instruction(8, true, 0, 1, 1), &registers, INITIAL_FLAGS)
                .is_none()
        );
    }
}
