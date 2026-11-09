.syntax unified
.arch armv7-a
.arm

.section .text
.global _start
.type _start, %function
_start:
    ldr r4, .Lslot_delta
.Ladd_slot:
    add r4, pc, r4
    ldr r4, [r4]
    ldr r2, [r4]
    cmp r2, #42
    movne r0, #1
    mov r7, #1
    svc #0
    .align 2
.Lslot_delta:
    .word probe_pointer_slot - (.Ladd_slot + 8)
.size _start, . - _start

.section .data
.align 2
.type probe_pointer_slot, %object
probe_pointer_slot:
    .word probe_value
.size probe_pointer_slot, . - probe_pointer_slot
.type probe_value, %object
probe_value:
    .word 42
.size probe_value, . - probe_value
