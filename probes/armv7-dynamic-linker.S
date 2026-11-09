.syntax unified
.arm
.text
.global _start
.type _start, %function
_start:
    ldr r4, [sp]
    cmp r4, #1
    movne r0, #1

    ldr r1, [sp, #4]
    cmp r1, #0
    moveq r0, #2

    ldr r1, [sp, #12]
    cmp r1, #0
    movne r0, #3

    ldr r1, [sp, #52]     @ AT_BASE value
    cmp r1, #0
    moveq r0, #4

    ldr r1, [sp, #68]     @ AT_ENTRY value
    cmp r1, #0
    moveq r0, #5
    bx r1
.size _start, .-_start
