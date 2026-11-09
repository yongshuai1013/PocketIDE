//! A32 data-processing and multiply decoders used by the restricted ELF runner.
//!
//! This module deliberately implements selected, well-defined ARM instruction
//! families rather than pretending to be a complete ARM emulator. Keeping operand
//! decode, barrel-shifter edge cases, multiply operations, and flags here makes it
//! possible to test them without growing the ELF loader's dispatch.

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct A32MultiplyResult {
    pub low_destination: usize,
    pub low_result: u32,
    pub high_result: Option<(usize, u32)>,
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
        decode_register_operand(instruction, registers, flags.c, true)?
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

/// Decode A32 MUL/MLA and the signed or unsigned long multiply family.
///
/// `None` covers non-multiply encodings and reserved register combinations.
/// The current flags are passed through because multiply only updates N and Z
/// when S is set; the carry and overflow flags remain unchanged.
pub(crate) fn execute_multiply(
    instruction: u32,
    registers: &[u32; 16],
    flags: Flags,
) -> Option<A32MultiplyResult> {
    if instruction & 0x0ff0_00f0 == 0x0060_0090 {
        let destination = ((instruction >> 16) & 0xf) as usize;
        let accumulator = ((instruction >> 12) & 0xf) as usize;
        let left = ((instruction >> 8) & 0xf) as usize;
        let right = (instruction & 0xf) as usize;
        if destination == 15 || accumulator == 15 || left == 15 || right == 15 {
            return None;
        }
        return Some(A32MultiplyResult {
            low_destination: destination,
            low_result: registers[accumulator]
                .wrapping_sub(registers[left].wrapping_mul(registers[right])),
            high_result: None,
            flags: None,
        });
    }

    if instruction & 0x0fc0_00f0 == 0x0000_0090 {
        let accumulate = instruction & (1 << 21) != 0;
        let set_flags = instruction & (1 << 20) != 0;
        let rd = ((instruction >> 16) & 0xf) as usize;
        let rn = ((instruction >> 12) & 0xf) as usize;
        let rs = ((instruction >> 8) & 0xf) as usize;
        let rm = (instruction & 0xf) as usize;
        if rd == 15 || rs == 15 || rm == 15 || (accumulate && rn == 15) || (!accumulate && rn != 0)
        {
            return None;
        }
        let product = registers[rm].wrapping_mul(registers[rs]);
        let result = if accumulate {
            product.wrapping_add(registers[rn])
        } else {
            product
        };
        return Some(A32MultiplyResult {
            low_destination: rd,
            low_result: result,
            high_result: None,
            flags: set_flags.then_some(Flags {
                n: result & 0x8000_0000 != 0,
                z: result == 0,
                c: flags.c,
                v: flags.v,
            }),
        });
    }

    if instruction & 0x0f80_00f0 == 0x0080_0090 {
        // A32 uses U=0 for the unsigned family and U=1 for signed products.
        let unsigned = instruction & (1 << 22) == 0;
        let accumulate = instruction & (1 << 21) != 0;
        let set_flags = instruction & (1 << 20) != 0;
        let rd_hi = ((instruction >> 16) & 0xf) as usize;
        let rd_lo = ((instruction >> 12) & 0xf) as usize;
        let rs = ((instruction >> 8) & 0xf) as usize;
        let rm = (instruction & 0xf) as usize;
        if rd_hi == rd_lo || rd_hi == 15 || rd_lo == 15 || rs == 15 || rm == 15 {
            return None;
        }
        let product = if unsigned {
            (registers[rm] as u64) * (registers[rs] as u64)
        } else {
            ((registers[rm] as i32 as i64) * (registers[rs] as i32 as i64)) as u64
        };
        let result = if accumulate {
            let accumulator = ((registers[rd_hi] as u64) << 32) | registers[rd_lo] as u64;
            product.wrapping_add(accumulator)
        } else {
            product
        };
        return Some(A32MultiplyResult {
            low_destination: rd_lo,
            low_result: result as u32,
            high_result: Some((rd_hi, (result >> 32) as u32)),
            flags: set_flags.then_some(Flags {
                n: result & (1_u64 << 63) != 0,
                z: result == 0,
                c: flags.c,
                v: flags.v,
            }),
        });
    }
    None
}

/// Decode the immediate-shifted register used by A32 single data transfers.
/// Register-specified shifts and PC as the offset register are intentionally
/// rejected until their transfer-specific behavior is modeled.
pub(crate) fn decode_single_transfer_register_offset(
    instruction: u32,
    registers: &[u32; 16],
    carry_in: bool,
) -> Option<u32> {
    if instruction & (1 << 4) != 0 {
        return None;
    }
    decode_register_operand(instruction, registers, carry_in, false).map(|operand| operand.value)
}

fn decode_register_operand(
    instruction: u32,
    registers: &[u32; 16],
    carry_in: bool,
    allow_pc: bool,
) -> Option<ShiftedOperand> {
    let rm = (instruction & 0xf) as usize;
    let by_register = instruction & (1 << 4) != 0;
    // A32 data-processing callers supply the visible PC value in r15. Register-
    // shifted PC operands and transfer offsets remain deferred as unpredictable
    // or instruction-family-specific cases.
    if rm == 15 && (!allow_pc || by_register) {
        return None;
    }
    let shift_type = match (instruction >> 5) & 3 {
        0 => ShiftType::Lsl,
        1 => ShiftType::Lsr,
        2 => ShiftType::Asr,
        _ => ShiftType::Ror,
    };
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
    fn single_transfer_offsets_reuse_immediate_barrel_shifts_and_reject_bad_forms() {
        let mut registers = [0; 16];
        registers[1] = 4;
        assert_eq!(
            decode_single_transfer_register_offset(0x101, &registers, false),
            Some(16)
        );

        registers[1] = 32;
        assert_eq!(
            decode_single_transfer_register_offset(0xa1, &registers, false),
            Some(16)
        );

        registers[1] = 6;
        assert_eq!(
            decode_single_transfer_register_offset(0x61, &registers, true),
            Some(0x8000_0003)
        );
        assert_eq!(
            decode_single_transfer_register_offset(0x11, &registers, false),
            None
        );
        assert_eq!(
            decode_single_transfer_register_offset(0xf, &registers, false),
            None
        );
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
    fn data_processing_reads_pipeline_pc_for_mov_lr_pc() {
        let mut registers = [0; 16];
        registers[15] = 0x1008;
        let result = execute_data_processing(0xe1a0_e00f, &registers, INITIAL_FLAGS).unwrap();

        assert_eq!(result.destination, 14);
        assert_eq!(result.result, 0x1008);
        assert!(result.writes_destination);
        assert_eq!(result.flags, None);
        assert_eq!(
            decode_single_transfer_register_offset(0x0000_000f, &registers, false),
            None
        );
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

    fn multiply_instruction(
        accumulate: bool,
        set_flags: bool,
        rd: u8,
        rn: u8,
        rs: u8,
        rm: u8,
    ) -> u32 {
        0xe000_0090
            | ((accumulate as u32) << 21)
            | ((set_flags as u32) << 20)
            | ((rd as u32) << 16)
            | ((rn as u32) << 12)
            | ((rs as u32) << 8)
            | rm as u32
    }

    fn long_multiply_instruction(
        unsigned: bool,
        accumulate: bool,
        set_flags: bool,
        rd_hi: u8,
        rd_lo: u8,
        rs: u8,
        rm: u8,
    ) -> u32 {
        0xe080_0090
            | ((!unsigned as u32) << 22)
            | ((accumulate as u32) << 21)
            | ((set_flags as u32) << 20)
            | ((rd_hi as u32) << 16)
            | ((rd_lo as u32) << 12)
            | ((rs as u32) << 8)
            | rm as u32
    }

    #[test]
    fn a32_multiply_and_multiply_accumulate_return_low_word_and_nz_flags() {
        let flags = Flags {
            c: true,
            v: true,
            ..INITIAL_FLAGS
        };
        let mut registers = [0; 16];
        registers[0] = u32::MAX;
        registers[1] = 3;
        registers[3] = 9;

        let mul = execute_multiply(
            multiply_instruction(false, true, 2, 0, 1, 0),
            &registers,
            flags,
        )
        .unwrap();
        assert_eq!(mul.low_destination, 2);
        assert_eq!(mul.low_result, 0xffff_fffd);
        assert_eq!(mul.high_result, None);
        assert_eq!(
            mul.flags,
            Some(Flags {
                n: true,
                z: false,
                c: true,
                v: true
            })
        );

        registers[0] = 10;
        registers[1] = 3;
        let mla = execute_multiply(
            multiply_instruction(true, false, 2, 3, 1, 0),
            &registers,
            flags,
        )
        .unwrap();
        assert_eq!(mla.low_result, 39);
        assert_eq!(mla.flags, None);
    }

    #[test]
    fn a32_multiply_subtract_uses_accumulator_minus_wrapping_product() {
        let mut registers = [0; 16];
        registers[0] = 1000;
        registers[2] = 3;
        registers[3] = 4;

        let result = execute_multiply(0xe063_0392, &registers, INITIAL_FLAGS).unwrap();

        assert_eq!(result.low_destination, 3);
        assert_eq!(result.low_result, 988);
        assert_eq!(result.high_result, None);
        assert_eq!(result.flags, None);
    }

    #[test]
    fn a32_signed_unsigned_long_products_and_accumulates_cover_full_64_bit_results() {
        let flags = Flags {
            c: true,
            v: true,
            ..INITIAL_FLAGS
        };
        let mut registers = [0; 16];
        registers[0] = (-2_i32) as u32;
        registers[1] = 3;

        let smull = execute_multiply(
            long_multiply_instruction(false, false, true, 5, 4, 1, 0),
            &registers,
            flags,
        )
        .unwrap();
        assert_eq!(smull.low_result, 0xffff_fffa);
        assert_eq!(smull.high_result, Some((5, u32::MAX)));
        assert_eq!(
            smull.flags,
            Some(Flags {
                n: true,
                z: false,
                c: true,
                v: true
            })
        );

        let umull = execute_multiply(
            long_multiply_instruction(true, false, false, 5, 4, 1, 0),
            &registers,
            flags,
        )
        .unwrap();
        assert_eq!(umull.low_result, 0xffff_fffa);
        assert_eq!(umull.high_result, Some((5, 2)));
        assert_eq!(umull.flags, None);

        registers[4] = 6;
        registers[5] = 0;
        let umlal = execute_multiply(
            long_multiply_instruction(true, true, true, 5, 4, 1, 0),
            &registers,
            flags,
        )
        .unwrap();
        assert_eq!(umlal.low_result, 0);
        assert_eq!(umlal.high_result, Some((5, 3)));
        assert!(!umlal.flags.unwrap().z);

        let smlal = execute_multiply(
            long_multiply_instruction(false, true, true, 5, 4, 1, 0),
            &registers,
            flags,
        )
        .unwrap();
        assert_eq!(smlal.low_result, 0);
        assert_eq!(smlal.high_result, Some((5, 0)));
        assert_eq!(
            smlal.flags.unwrap(),
            Flags {
                n: false,
                z: true,
                c: true,
                v: true
            }
        );
    }

    #[test]
    fn multiply_decoder_rejects_pc_and_invalid_accumulate_encodings() {
        let registers = [0; 16];
        assert!(execute_multiply(0xe000_0090, &registers, INITIAL_FLAGS).is_some());
        assert!(execute_multiply(
            multiply_instruction(false, false, 2, 1, 3, 4),
            &registers,
            INITIAL_FLAGS
        )
        .is_none());
        assert!(execute_multiply(
            multiply_instruction(true, false, 15, 1, 3, 4),
            &registers,
            INITIAL_FLAGS
        )
        .is_none());
        assert!(execute_multiply(
            long_multiply_instruction(true, false, false, 4, 4, 3, 2),
            &registers,
            INITIAL_FLAGS
        )
        .is_none());
        assert!(execute_multiply(
            long_multiply_instruction(true, false, false, 15, 4, 3, 2),
            &registers,
            INITIAL_FLAGS
        )
        .is_none());
        assert!(execute_multiply(0xe3a0_0001, &registers, INITIAL_FLAGS).is_none());
    }

    #[test]
    fn multiply_families_allow_architecturally_valid_source_destination_overlap() {
        let mut registers = [0; 16];
        registers[0] = 7;
        registers[1] = 3;
        registers[2] = 5;
        let mla = execute_multiply(
            multiply_instruction(true, false, 0, 2, 1, 0),
            &registers,
            INITIAL_FLAGS,
        )
        .unwrap();
        assert_eq!(mla.low_result, 26); // Rd == Rm is valid for MLA.

        registers[3] = 11;
        registers[4] = 7;
        let umull = execute_multiply(
            long_multiply_instruction(true, false, false, 3, 5, 4, 3),
            &registers,
            INITIAL_FLAGS,
        )
        .unwrap();
        assert_eq!(umull.low_result, 77); // RdHi == Rm is valid; inputs are read before writes.
        assert_eq!(umull.high_result, Some((3, 0)));
    }
}
