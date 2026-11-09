.syntax unified
.arch armv7-a
.arm

.global _start
.type _start, %function
_start:
    @ mmap2(NULL, 4096, PROT_READ|PROT_WRITE,
    @        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    mov r0, #0
    mov r1, #4096
    mov r2, #3
    mov r3, #0x22
    mvn r4, #0
    mov r5, #0
    mov r7, #192
    svc #0
    mov r8, r0
    cmp r8, #0
    bmi failure

    mov r9, #0x5a
    str r9, [r8]
    ldr r10, [r8]
    cmp r9, r10
    bne failure

    @ Replace the same page with MAP_FIXED and confirm its old contents vanish.
    mov r0, r8
    mov r1, #4096
    mov r2, #3
    mov r3, #0x32
    mvn r4, #0
    mov r5, #0
    mov r7, #192
    svc #0
    cmp r0, r8
    bne failure
    ldr r10, [r8]
    cmp r10, #0
    bne failure
    mov r9, #0x5a
    str r9, [r8]

    @ Restrict to read-only, verify reads, then restore read/write.
    mov r0, r8
    mov r1, #4096
    mov r2, #1
    mov r7, #125
    svc #0
    cmp r0, #0
    bne failure
    ldr r10, [r8]
    cmp r9, r10
    bne failure

    mov r0, r8
    mov r1, #4096
    mov r2, #3
    mov r7, #125
    svc #0
    cmp r0, #0
    bne failure
    mov r9, #0x6b
    str r9, [r8, #4]
    ldr r10, [r8, #4]
    cmp r9, r10
    bne failure

    @ Install a tiny returning ARM function, switch to read/execute, and call it.
    ldr r9, =0xe3a00007
    str r9, [r8, #8]
    ldr r9, =0xe12fff1e
    str r9, [r8, #12]
    mov r0, r8
    mov r1, #4096
    mov r2, #5
    mov r7, #125
    svc #0
    cmp r0, #0
    bne failure
    add r10, r8, #8
    blx r10
    cmp r0, #7
    bne failure

    @ munmap, then map again and verify fresh anonymous pages are zeroed.
    mov r0, r8
    mov r1, #4096
    mov r7, #91
    svc #0
    cmp r0, #0
    bne failure
    mov r0, #0
    mov r1, #4096
    mov r2, #3
    mov r3, #0x22
    mvn r4, #0
    mov r5, #0
    mov r7, #192
    svc #0
    mov r8, r0
    cmp r8, #0
    bmi failure
    ldr r9, [r8]
    cmp r9, #0
    bne failure
    mov r0, r8
    mov r1, #4096
    mov r7, #91
    svc #0
    cmp r0, #0
    bne failure

    @ brk(0), grow by 256 bytes, use the heap, then shrink back.
    mov r0, #0
    mov r7, #45
    svc #0
    mov r11, r0
    add r12, r11, #256
    mov r0, r12
    mov r7, #45
    svc #0
    cmp r0, r12
    bne failure
    mov r9, #0x33
    str r9, [r11]
    ldr r10, [r11]
    cmp r9, r10
    bne failure
    mov r0, r11
    mov r7, #45
    svc #0
    cmp r0, r11
    bne failure

    @ Invalid protection of a hole returns -ENOMEM (-12).
    ldr r0, =0x20000000
    mov r1, #4096
    mov r2, #1
    mov r7, #125
    svc #0
    mvn r12, #11
    cmp r0, r12
    bne failure

    @ A file-backed mapping with fd=-1 must fail with EBADF (-9).
    mov r0, #0
    mov r1, #4096
    mov r2, #1
    mov r3, #2
    mvn r4, #0
    mov r5, #0
    mov r7, #192
    svc #0
    mvn r12, #8
    cmp r0, r12
    bne failure

    @ Open a guest file, read its header, and privately map its second page.
    ldr r0, =mmap_path
    mov r1, #0
    mov r2, #0
    mov r7, #5
    svc #0
    mov r4, r0
    cmp r4, #3
    blt failure
    sub r1, sp, #16
    mov r0, r4
    mov r2, #4
    mov r7, #3
    svc #0
    cmp r0, #4
    bne failure
    ldr r10, [r1]
    ldr r11, =0x44414548
    cmp r10, r11
    bne failure

    mov r0, #0
    mov r1, #4096
    mov r2, #3
    mov r3, #2
    mov r5, #1
    mov r7, #192
    svc #0
    mov r8, r0
    cmp r8, #0
    bmi failure
    ldr r10, [r8]
    ldr r11, =0x3250414d
    cmp r10, r11
    bne failure
    mov r9, #0x5a
    str r9, [r8]
    ldr r10, [r8]
    cmp r9, r10
    bne failure

    @ mmap2's positioned read must leave the sequential FD cursor at byte four.
    sub r1, sp, #16
    mov r0, r4
    mov r2, #4
    mov r7, #3
    svc #0
    cmp r0, #4
    bne failure
    ldr r10, [r1]
    ldr r11, =0x41414141
    cmp r10, r11
    bne failure
    mov r0, r4
    mov r7, #6
    svc #0
    cmp r0, #0
    bne failure
    mov r0, r8
    mov r1, #4096
    mov r7, #91
    svc #0
    cmp r0, #0
    bne failure

    mov r0, #0
    mov r7, #1
    svc #0

failure:
    mov r0, #1
    mov r7, #1
    svc #0

.ltorg
mmap_path:
    .asciz "/tmp/gingervm-mmap-fixture.bin"
.size _start, . - _start
