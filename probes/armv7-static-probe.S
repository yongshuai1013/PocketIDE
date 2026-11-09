.syntax unified
.arch armv7-a
.arm

.section .text.boot,"ax",%progbits
.global _start
.type _start,%function
_start:
    @ Create and write the source file through ARM EABI open/write/close.
    ldr r0, =source_path
    mov r1, #1                    @ O_WRONLY
    orr r1, r1, #0x240            @ O_CREAT | O_TRUNC
    mov r2, #0
    mov r7, #5                    @ __NR_open
    svc #0
    cmp r0, #0
    bmi fail
    ldr r1, =fd_slot
    str r0, [r1]

    ldr r0, =fd_slot
    ldr r0, [r0]
    ldr r1, =payload
    ldr r2, =PAYLOAD_LEN
    mov r7, #4                    @ __NR_write
    svc #0
    cmp r0, #51
    bne fail

    ldr r0, =fd_slot
    ldr r0, [r0]
    mov r7, #6                    @ __NR_close
    svc #0
    cmp r0, #0
    bne fail

    @ Reopen and read the bytes written above into guest writable memory.
    ldr r0, =source_path
    mov r1, #0                    @ O_RDONLY
    mov r2, #0
    mov r7, #5                    @ __NR_open
    svc #0
    cmp r0, #0
    bmi fail
    ldr r1, =fd_slot
    str r0, [r1]

    ldr r0, =fd_slot
    ldr r0, [r0]
    ldr r1, =read_buffer
    ldr r2, =PAYLOAD_LEN
    mov r7, #3                    @ __NR_read
    svc #0
    cmp r0, #51
    bne fail

    ldr r0, =fd_slot
    ldr r0, [r0]
    mov r7, #6                    @ __NR_close
    svc #0
    cmp r0, #0
    bne fail

    @ Persist the bytes read back under a second guest path for host-side cmp.
    ldr r0, =copy_path
    mov r1, #1                    @ O_WRONLY
    orr r1, r1, #0x240            @ O_CREAT | O_TRUNC
    mov r2, #0
    mov r7, #5                    @ __NR_open
    svc #0
    cmp r0, #0
    bmi fail
    ldr r1, =fd_slot
    str r0, [r1]

    ldr r0, =fd_slot
    ldr r0, [r0]
    ldr r1, =read_buffer
    ldr r2, =PAYLOAD_LEN
    mov r7, #4                    @ __NR_write
    svc #0
    cmp r0, #51
    bne fail

    ldr r0, =fd_slot
    ldr r0, [r0]
    mov r7, #6                    @ __NR_close
    svc #0
    cmp r0, #0
    bne fail

    @ Check the broker's default virtual identity values.
    mov r7, #24                   @ __NR_getuid
    svc #0
    cmp r0, #1000
    bne fail

    mov r7, #47                   @ __NR_getgid
    svc #0
    cmp r0, #1000
    bne fail

    mov r7, #20                   @ __NR_getpid
    svc #0
    cmp r0, #1
    bne fail

    mov r0, #0
    mov r7, #1                    @ __NR_exit
    svc #0

fail:
    mov r0, #1
    mov r7, #1                    @ __NR_exit
    svc #0

.size _start, .-_start

.section .rodata,"a",%progbits
.align 2
source_path:
    .asciz "/tmp/gingervm-arm-source.txt"
copy_path:
    .asciz "/tmp/gingervm-arm-copy.txt"
payload:
    .ascii "GingerVM ARM EABI static probe: file round-trip OK\n"
.equ PAYLOAD_LEN, . - payload

.section .bss,"aw",%nobits
.align 2
fd_slot:
    .space 4
read_buffer:
    .space 128
