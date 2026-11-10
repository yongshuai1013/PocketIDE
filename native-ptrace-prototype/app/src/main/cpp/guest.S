.syntax unified
.arch armv7-a
.arm

.section .text
.global _start
.type _start, %function
_start:
    @ Mark that the guest reached its native entry point.
    mov     r0, #1
    ldr     r1, =marker_begin
    mov     r2, #1
    movw    r7, #4              @ __NR_write (ARM EABI)
    svc     #0

    @ Deterministic 50,000,000-iteration arithmetic loop for native CPU timing.
    mov     r5, #0
    movw    r4, #0xF080
    movt    r4, #0x02FA          @ 0x02FAF080 = 50,000,000
1:
    add     r5, r5, #1
    subs    r4, r4, #1
    bne     1b
    movw    r6, #0xF080
    movt    r6, #0x02FA
    cmp     r5, r6
    bne     fail

    mov     r0, #1
    ldr     r1, =marker_cpu_done
    mov     r2, #1
    movw    r7, #4
    svc     #0

    @ Repeated getpid syscalls are intercepted and return a guest-only PID.
    movw    r4, #1000
2:
    movw    r7, #20             @ __NR_getpid (ARM EABI)
    svc     #0
    cmp     r0, #1
    bne     fail
    subs    r4, r4, #1
    bne     2b

    @ Emulate mount("tmpfs", "/mnt", "tmpfs", 0, NULL) in software only.
    ldr     r0, =tmpfs_source
    ldr     r1, =mount_target
    ldr     r2, =tmpfs_type
    mov     r3, #0
    mov     r4, #0
    movw    r7, #21             @ __NR_mount (ARM EABI)
    svc     #0
    cmp     r0, #0
    bne     fail

    @ Read a known file through the broker's guest-to-private-path mapping.
    mvn     r0, #99             @ AT_FDCWD = -100
    ldr     r1, =guest_file
    mov     r2, #0              @ O_RDONLY
    mov     r3, #0
    movw    r7, #322            @ __NR_openat (ARM EABI)
    svc     #0
    cmp     r0, #0
    blt     fail
    mov     r8, r0              @ preserve file descriptor across read

    mov     r0, r8
    ldr     r1, =read_buffer
    mov     r2, #8
    movw    r7, #3              @ __NR_read (ARM EABI)
    svc     #0
    cmp     r0, #8
    bne     fail

    ldr     r4, =read_buffer
    ldr     r5, =expected_data
    mov     r6, #0
3:
    ldrb    r0, [r4, r6]
    ldrb    r1, [r5, r6]
    cmp     r0, r1
    bne     fail
    add     r6, r6, #1
    cmp     r6, #8
    blt     3b

    mov     r0, r8
    movw    r7, #6              @ __NR_close (ARM EABI)
    svc     #0
    cmp     r0, #0
    bne     fail

    mov     r0, #1
    ldr     r1, =marker_pass
    mov     r2, #11
    movw    r7, #4
    svc     #0

    mov     r0, #0
    movw    r7, #1              @ __NR_exit (ARM EABI)
    svc     #0

fail:
    mov     r0, #1
    movw    r7, #1
    svc     #0

.size _start, .-_start

.section .rodata
marker_begin:    .ascii "B"
marker_cpu_done: .ascii "C"
marker_pass:     .ascii "PROBE_PASS\n"
tmpfs_source:    .asciz "tmpfs"
mount_target:    .asciz "/mnt"
tmpfs_type:      .asciz "tmpfs"
guest_file:      .asciz "/mnt/marker.txt"
expected_data:   .ascii "VIRTUAL\n"

.section .bss
.balign 4
read_buffer:     .space 8
