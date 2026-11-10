.text
.globl _start
.type _start, @function
_start:
    mov $39, %rax              # x86_64 __NR_getpid
    syscall
    mov $60, %rax              # x86_64 __NR_exit
    xor %rdi, %rdi
    syscall
.size _start, .-_start
