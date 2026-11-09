.syntax unified
.arch armv7-a
.arm

.equ ARM_NR_SET_TLS, 0x000f0005

.text
.global _start
.type _start, %function
_start:
    ldr r0, =tls_area
    ldr r7, =ARM_NR_SET_TLS
    svc #0
    cmp r0, #0
    bne .Lfail

    mov r7, #20              @ Bionic linker calls getpid just after __set_tls.
    svc #0
    cmp r0, #0
    beq .Lfail

    mrc p15, 0, r1, c13, c0, 3
    ldr r2, =tls_area
    cmp r1, r2
    bne .Lfail

    ldr r3, [r1, #0]       @ Bionic TLS_SLOT_SELF must point to the TLS area.
    cmp r3, r2
    bne .Lfail

    mov r0, #0
    b .Lexit
.Lfail:
    mov r0, #1
.Lexit:
    mov r7, #1              @ Linux ARM exit
    svc #0
.size _start, .-_start
.ltorg

.data
.balign 4
tls_area:
    .word tls_area          @ TLS_SLOT_SELF
    .word 0                 @ TLS_SLOT_THREAD_ID (unused by this single-thread probe)
    .zero (64 * 4) - 8      @ Remaining Bionic TLS slots
