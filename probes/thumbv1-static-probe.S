.syntax unified
.arch armv5t
.thumb
.set fail_id, 1
.macro expect_eq
    beq 1f
    movs r0, #fail_id
    b fail
1:
    .set fail_id, fail_id + 1
.endm
.macro expect_ne
    bne 1f
    movs r0, #fail_id
    b fail
1:
    .set fail_id, fail_id + 1
.endm
.macro expect_lt
    blt 1f
    movs r0, #fail_id
    b fail
1:
    .set fail_id, fail_id + 1
.endm
.section .text.boot,"ax",%progbits
.global _start
.type _start,%function
.thumb_func
_start:
    @ Immediate/register shifts, arithmetic flags, and conditional branches.
    movs r0, #2
    lsls r0, r0, #3
    cmp r0, #16
    expect_eq
    movs r1, #3
    movs r2, r0
    lsls r2, r1
    cmp r2, #128
    expect_eq
    movs r2, #0x80
    lsrs r2, r2, #1
    cmp r2, #64
    expect_eq
    movs r2, #0x80
    asrs r2, r2, #1
    cmp r2, #64
    expect_eq

    @ Register ALU instructions and immediate compare/update.
    movs r0, #0x0f
    movs r1, #0x33
    ands r0, r1
    cmp r0, #3
    expect_eq
    eors r0, r1
    cmp r0, #0x30
    expect_eq
    movs r0, #7
    movs r1, #5
    adds r0, r1
    cmp r0, #12
    expect_eq
    subs r0, r1
    cmp r0, #7
    expect_eq
    movs r0, #0
    cmp r0, #1                    @ Clear carry before the ADC case.
    movs r0, #0x80
    movs r1, #1
    adcs r0, r1
    cmp r0, #0x81
    expect_eq
    sbcs r0, r1
    cmp r0, #0x80
    expect_eq
    movs r0, #0x55
    movs r1, #0x0f
    orrs r0, r1
    cmp r0, #0x5f
    expect_eq
    bics r0, r1
    cmp r0, #0x50
    expect_eq
    mvns r0, r1
    cmp r0, #0
    expect_lt
    negs r0, r1
    cmp r0, #0
    expect_lt
    movs r0, #3
    movs r1, #4
    muls r0, r1
    cmp r0, #12
    expect_eq

    @ ADR and byte/halfword/word load-store forms, including signed loads.
    adr r0, adr_target
    cmp r0, #0
    expect_ne
    ldr r4, =data
    movs r0, #0x34
    strb r0, [r4, #0]
    ldrb r1, [r4, #0]
    cmp r1, r0
    expect_eq
    movs r0, #0x56
    strh r0, [r4, #2]
    ldrh r1, [r4, #2]
    cmp r1, r0
    expect_eq
    movs r5, #4
    strb r0, [r4, r5]
    ldrb r1, [r4, r5]
    cmp r1, r0
    expect_eq
    movs r0, #0xff
    strb r0, [r4, #5]
    movs r5, #5
    ldrsb r1, [r4, r5]
    cmp r1, #0
    expect_lt
    movs r0, #0x80
    lsls r0, r0, #8
    strh r0, [r4, #6]
    movs r5, #6
    ldrsh r1, [r4, r5]
    cmp r1, #0
    expect_lt
    movs r0, #0x78
    str r0, [r4, #8]
    ldr r1, [r4, #8]
    cmp r1, r0
    expect_eq

    @ STMIA/LDMIA register lists and their base writeback.
    ldr r3, =block
    movs r0, #7
    movs r1, #9
    movs r2, #11
    stmia r3!, {r0-r2}
    ldr r3, =block
    ldmia r3!, {r4-r6}
    cmp r4, #7
    expect_eq
    cmp r5, #9
    expect_eq
    cmp r6, #11
    expect_eq

    @ SP-relative word access, stack adjustment, and high-register moves.
    sub sp, #8
    movs r0, #42
    str r0, [sp, #0]
    movs r0, #0
    ldr r1, [sp, #0]
    add sp, #8
    cmp r1, #42
    expect_eq
    mov r8, r1
    mov r0, r8
    cmp r0, #42
    expect_eq

    @ Thumb BL, BLX register, PUSH/POP and BX return behavior.
    bl worker
    cmp r0, #42
    expect_eq
    ldr r3, =worker
    blx r3
    cmp r0, #42
    expect_eq

    movs r0, #0
    movs r7, #1                    @ Linux EABI exit(0)
    svc #0
fail:
    movs r7, #1
    svc #0

.thumb_func
worker:
    push {r4, lr}
    movs r0, #42
    pop {r4, pc}
.align 2
adr_target:
    nop

.align 2
.data
.align 2
data:
    .space 16
block:
    .space 12
