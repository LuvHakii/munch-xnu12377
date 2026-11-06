#!/usr/bin/env python3
"""Execute the PAC fault adapter, native XNU abort handler and signal mapping.

Usage: python3 test-pac-faults.py <xnu-root>
Only VM resolution and unrelated kernel services are replaced by host fixtures.
"""
import runpy
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
extract = runpy.run_path(str(HERE / "test-fixups.py"))["extract_func"]

PREFIX = r"""
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define T0SZ_BOOT 26
#include "pac-emu.h"
#define ARM64_BOARD_CONFIG_BCM2837 1
#define __improbable(x) (x)
#define assertf(x, ...) assert(x)
#define TRUE 1
#define FALSE 0
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_EXECUTE 4
#define VM_USER_STRIP_TBI(x) ((x) & UINT64_C(0x00ffffffffffffff))
#define ESR_EC_SHIFT 26
#define ESR_EC_MASK (UINT64_C(0x3f) << ESR_EC_SHIFT)
#define ESR_EC_DABORT_EL0 0x24
#define ESR_ISS(x) ((x) & 0x1ffffff)
#define ISS_DA_FSC(x) ((x) & 0x3f)
#define ISS_DA_WNR (1 << 6)
#define ISS_DA_CM (1 << 8)
#define FSC_ACCESS_FLAG_FAULT_L3 0xb
#define KERN_SUCCESS 0
#define KERN_INVALID_ADDRESS 1
#define KERN_PROTECTION_FAILURE 2
#define KERN_FAILURE 5
#define KERN_ABORTED 14
#define KERN_INVALID_GUARD_OBJECT_SLOT 51
#define VM_KERN_MEMORY_NONE 0
#define THREAD_ABORTSAFE 0
#define THROTTLE_LEVEL_NONE 0
#define TRR_FAULT_NONE 0
#define SELF_RESTRICT_NONE 0
#define OS_REASON_MTE_FAIL 0
#define OS_REASON_SELF_RESTRICT 0
#define PX_KTRIAGE 0
#define SPSR_INTERRUPTS_ENABLED(x) 1
#define EXC_BAD_ACCESS 1
#define EXC_BAD_INSTRUCTION 2
#define EXC_ARITHMETIC 3
#define EXC_EMULATION 4
#define EXC_SOFTWARE 5
#define EXC_BREAKPOINT 6
#define EXC_SYSCALL 7
#define EXC_UNIX_BAD_SYSCALL 0x10000
#define EXC_UNIX_BAD_PIPE 0x10001
#define EXC_UNIX_ABORT 0x10002
#define EXC_SOFT_SIGNAL 0x10003
#define EXC_ARM_DA_ALIGN 0x101
#define SIGEMT 7

typedef uint64_t vm_offset_t;
typedef uint64_t mach_exception_data_type_t;
typedef uint64_t mach_exception_code_t;
typedef uint64_t mach_exception_subcode_t;
typedef int exception_type_t, mach_msg_type_number_t, fault_status_t;
typedef int vm_prot_t, kern_return_t, self_restrict_mode_t;
typedef void *pmap_t;
typedef void *expected_fault_handler_t;
typedef struct { uint64_t esr, far, pc; } arm_saved_state_t;
typedef struct { pmap_t pmap; } *vm_map_t;
static struct { pmap_t pmap; } user_map;
static vm_map_t kernel_map;
static struct {
    struct { uint64_t recover_esr, recover_far; arm_saved_state_t *upcb; } machine;
    struct { int trr_fault_state; } t_rr_state;
    vm_map_t map;
    int iotier_override;
} thread_storage;
typedef typeof(&thread_storage) thread_t;
static thread_t current_thread(void) { return &thread_storage; }
static struct { struct { int data_ex_cnt; } cpu_stat; } cpu;
#define getCpuDatap() (&cpu)
static bool is_permission_fault(int f) { return (f & ~3) == 12; }
static bool is_translation_fault(int f) { return (f & ~3) == 4; }
static bool is_vm_fault(int f) { return f >= 4 && f <= 15; }
static bool is_alignment_fault(int f) { return f == 0x21; }
static bool is_parity_error(int f) { return false; }
static bool is_servicible_fault(int f, uint64_t e, uint64_t a, pmap_t p) { return true; }
static void thread_reset_pcs_done_faulting(thread_t t) { t->t_rr_state.trr_fault_state = 0; }
static void thread_reset_pcs_will_fault(thread_t t) { t->t_rr_state.trr_fault_state = 1; }
static uint64_t get_saved_state_cpsr(arm_saved_state_t *s) { return 0; }
static void set_saved_state_esr(arm_saved_state_t *s, uint64_t e) { s->esr = e; }
static void set_saved_state_far(arm_saved_state_t *s, uint64_t a) { s->far = a; }
#define panic(...) abort()
#define panic_with_thread_kernel_state(...) abort()
#define current_proc() NULL
#define get_threadtask(t) NULL
#define task_is_jit_exception_fatal(t) false
#define user_fault_in_self_restrict_mode(t) SELF_RESTRICT_NONE
#define exit_with_fatal_exception_and_notify(...) abort()
#define thread_exception_return() abort()
static int handle_alignment_fault_from_user(arm_saved_state_t *s, int *r) { return -1; }
static int arm_fast_fault(pmap_t p, uint64_t a, int t, bool f, bool u) { return KERN_FAILURE; }

/* A load straddles two pages; only the second page can fail or be paged in. */
static int page_result;
static uint64_t vm_address;
static int vm_fault(vm_map_t m, uint64_t a, int prot, bool w, int tag, int intr,
    void *p, uint64_t pa) {
    assert(prot == VM_PROT_READ);
    vm_address = a;
    return a == 0x104000 ? page_result : KERN_INVALID_ADDRESS;
}
static int copyin(uint64_t addr, char *dst, size_t n) {
    if (addr == 0x105000) return EFAULT;
    assert(addr == 0x103ffc && n == 8);
    if (page_result == KERN_SUCCESS) {
        uint64_t value = 0x123456789abcdef0;
        memcpy(dst, &value, n);
        return 0;
    }
    thread_storage.machine.recover_esr = (UINT64_C(0x25) << ESR_EC_SHIFT) |
        (page_result == KERN_PROTECTION_FAILURE ? 0xf : 7);
    thread_storage.machine.recover_far = 0x104000;
    return EFAULT;
}
static jmp_buf exception_return;
static int delivered_exception;
static uint64_t delivered_code, delivered_address;
static void exception_triage(int exc, uint64_t *codes, int count) {
    assert(count == 2);
    delivered_exception = exc;
    delivered_code = codes[0];
    delivered_address = codes[1];
    longjmp(exception_return, 1);
}
static int send_sigsys;
static int machine_exception(int e, uint64_t c, uint64_t s) { return 0; }
typedef void (*abort_inspector_t)(uint32_t, fault_status_t *, vm_prot_t *);
typedef void (*abort_handler_t)(arm_saved_state_t *, uint64_t, vm_offset_t,
    fault_status_t, vm_prot_t, expected_fault_handler_t);
"""

DRIVER = r"""
int main(void) {
    uint64_t x[29] = {0}, fp = 0, lr = 0, sp = 0, pc = 0x500000;
    static arm_saved_state_t state = {.pc = 0x500000};
    munch_pac_state_t mps = {x, &fp, &lr, &sp, &pc, munch_pac_copyin64, NULL};
    thread_storage.map = (vm_map_t)&user_map;
    x[1] = 0x103ffc;
    x[0] = 0xdead;
    const int outcomes[] = {KERN_PROTECTION_FAILURE, KERN_INVALID_ADDRESS};
    const int signals[] = {SIGBUS, SIGSEGV};
    for (unsigned i = 0; i < 2; ++i) {
        page_result = outcomes[i];
        assert(munch_pac_emulate(&mps, 0xf8200420, pc) == MUNCH_PAC_FAULT);
        assert(x[0] == 0xdead && pc == 0x500000);
        if (setjmp(exception_return) == 0) {
            munch_pac_handle_data_abort(&state, &mps, 0xf8200420);
            abort();
        }
        assert(ux_exception(delivered_exception, delivered_code, delivered_address) == signals[i]);
        assert(delivered_address == 0x104000 && vm_address == 0x104000);
        assert((state.esr >> ESR_EC_SHIFT) == ESR_EC_DABORT_EL0 && state.far == 0x104000);
    }
    /* A sanity rejection must not reuse the preceding fault's ESR/FAR. */
    x[1] = 0x105000;
    assert(munch_pac_emulate(&mps, 0xf8200420, pc) == MUNCH_PAC_FAULT);
    if (setjmp(exception_return) == 0) {
        munch_pac_handle_data_abort(&state, &mps, 0xf8200420);
        abort();
    }
    assert(ux_exception(delivered_exception, delivered_code, delivered_address) == SIGSEGV);
    assert(delivered_address == 0x105000 && x[0] == 0xdead && pc == 0x500000);
    x[1] = 0x103ffc;
    /* VM can resolve a failed copy; retry the original instruction, not the next PC. */
    page_result = KERN_PROTECTION_FAILURE;
    assert(munch_pac_emulate(&mps, 0xf8200420, pc) == MUNCH_PAC_FAULT);
    page_result = KERN_SUCCESS;
    munch_pac_handle_data_abort(&state, &mps, 0xf8200420);
    assert(pc == 0x500000 && x[0] == 0xdead && vm_address == 0x104000);
    assert(munch_pac_emulate(&mps, 0xf8200420, pc) == MUNCH_PAC_OK);
    assert(x[0] == 0x123456789abcdef0 && pc == 0x500004);
    assert(thread_storage.machine.recover_esr == 0 && thread_storage.machine.recover_far == 0);
    puts("PAC_FAULT_TEST_PASS: SIGBUS, SIGSEGV, cross-page FAR, resolved-fault retry");
}
"""


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    root = Path(sys.argv[1])
    sleh = (root / "osfmk/arm64/sleh.c").read_text()
    ux = (root / "bsd/uxkern/ux_exception.c").read_text()
    parts = [PREFIX]
    for name in ("handle_user_abort", "inspect_data_abort", "handle_abort"):
        parts.append(extract(sleh, "static void\n" + name + "(", name))
    for name, result in (("munch_pac_copyin64", "uint64_t"),
                         ("munch_pac_handle_data_abort", "void")):
        parts.append(extract(sleh, "static " + result + "\n" + name + "(", name))
    parts.append(extract(ux, "static int\nux_exception(", "ux_exception"))
    parts.append(DRIVER)
    with tempfile.TemporaryDirectory(prefix="pac-fault-test-") as tmp:
        source = Path(tmp) / "faults.c"
        binary = Path(tmp) / "faults"
        source.write_text("\n".join(parts))
        subprocess.run(["clang", "-std=gnu11", "-O1", "-I", str(HERE),
                        str(source), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    main()
