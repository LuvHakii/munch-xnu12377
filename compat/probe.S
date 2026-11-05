.text
.p2align 2
.globl _start
_start:
    mov x9, sp
    and sp, x9, #0xfffffffffffffff0
    sub sp, sp, #64
    mov x19, #1
    adrp x0, Lconsole@PAGE
    add x0, x0, Lconsole@PAGEOFF
    mov x1, #2
    mov x2, #0
    mov x16, #5
    svc #0x80
    mov x21, x0
    adr x9, Lcallee
    mov x10, sp
    pacia x9, x10
    autia x9, x10
    blraa x9, x10
    cmp x0, #0x123
    b.ne Lfail

    mov x19, #2
    adrp x9, Lvalues@PAGE
    add x9, x9, Lvalues@PAGEOFF
    mov x20, x9
    mov x10, #123
    pacda x9, x10
    autda x9, x10
    cmp x9, x20
    b.ne Lfail
    ldraa x0, [x9, #8]!
    cmp x0, #0x456
    b.ne Lfail
    add x20, x20, #8
    cmp x9, x20
    b.ne Lfail
    ldrab x0, [x9, #-8]
    cmp x0, #0x123
    b.ne Lfail

    mov x19, #3
    adr x9, Lcallee
    mov x20, x9
    mov x10, #0x55
    lsl x10, x10, #48
    orr x9, x9, x10
    xpaci x9
    cmp x9, x20
    b.ne Lfail
    mov x9, x20
    paciza x9
    blraaz x9
    cmp x0, #0x123
    b.ne Lfail

    mov x19, #4
    str x0, [sp, #16]
    mov x20, sp
    ldraa x9, [sp, #16]!
    cmp x9, #0x123
    b.ne Lfail
    add x20, x20, #16
    mov x10, sp
    cmp x10, x20
    b.ne Lfail
    sub sp, sp, #16
    mov x0, x21
    adr x1, Lpass
    mov x2, #Lpass_end-Lpass
    mov x16, #4
    svc #0x80
    // PID 1 must remain alive so the loader can collect its log.
Lwait:
    mov x0, #1
    stp x0, xzr, [sp]
    mov x0, #0
    mov x1, #0
    mov x2, #0
    mov x3, #0
    mov x4, sp
    mov x16, #93
    svc #0x80
    b Lwait

Lfail:
    mov x0, x21
    adr x1, Lfailure
    mov x2, #Lfailure_end-Lfailure
    mov x16, #4
    svc #0x80
    add w9, w19, #'0'
    strb w9, [sp]
    mov w9, #10
    strb w9, [sp, #1]
    mov x0, x21
    mov x1, sp
    mov x2, #2
    mov x16, #4
    svc #0x80
    mov x0, x19
    mov x16, #1
    svc #0x80
    b Lwait

Lcallee:
    pacibsp
    mov x0, #0x123
    retab

Lpass:
    .ascii "arm64e probe: PASS signing, auth, indirect calls, returns, data loads, SP writeback\n"
Lpass_end:
Lfailure:
    .ascii "arm64e probe: FAIL (exit status identifies stage)\n"
Lfailure_end:

.data
Lconsole:
    .asciz "/dev/console"
.p2align 3
Lvalues:
    .quad 0x123, 0x456
