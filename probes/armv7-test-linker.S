.syntax unified
.arm
.text
.global _start
.type _start, %function
_start:
    ldr r4, [sp]          @ CLI supplies argv[0]
    cmp r4, #1
    movne r0, #1

    ldr r1, [sp, #4]      @ argv[0] pointer must be present
    cmp r1, #0
    moveq r0, #2

    ldr r1, [sp, #12]     @ envp terminator (empty environment)
    cmp r1, #0
    movne r0, #3

    ldr r1, [sp, #52]     @ AT_BASE value must identify this mapped interpreter
    cmp r1, #0
    moveq r0, #4

    ldr r1, [sp, #68]     @ AT_ENTRY value must identify the main program
    cmp r1, #0
    moveq r0, #5

    mov r7, #1            @ ARM EABI exit
    svc #0
.size _start, .-_start
