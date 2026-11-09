.syntax unified
.arm
.text
.global _start
.type _start, %function
_start:
    mov r0, #0
    mov r7, #1
    svc #0
.size _start, .-_start
