#!/usr/bin/env python3
"""Insert the unsigned PAC instruction emulator into an XNU source tree.

Usage: python3 apply-instructions.py <xnu-root>

Copies kernel-ci/compat/pac-emu.h to <xnu-root>/osfmk/arm64/munch_pac_emu.h
and inserts a narrow hook into handle_uncategorized() in
<xnu-root>/osfmk/arm64/sleh.c, AFTER the instruction COPYIN and BEFORE the
generic DTrace/debug/exception triage. Fails closed: every anchor must match
exactly once or nothing is written.
"""

import shutil
import sys
from pathlib import Path

COMPAT = Path(__file__).resolve().parent
HEADER_SRC = COMPAT / "pac-emu.h"
HEADER_DST = Path("osfmk/arm64/munch_pac_emu.h")
SLEH = Path("osfmk/arm64/sleh.c")

INCLUDE_ANCHOR = "#include <arm64/instructions.h>\n"
INCLUDE_NEW = "#include <arm64/instructions.h>\n#include <arm64/munch_pac_emu.h>\n"

HOOK_ANCHOR = "\tCOPYIN(get_saved_state_pc(state), (char *)&instr, sizeof(instr));\n\n#if CONFIG_DTRACE\n"
HOOK_NEW = """\tCOPYIN(get_saved_state_pc(state), (char *)&instr, sizeof(instr));

#if defined(ARM64_BOARD_CONFIG_BCM2837) && !defined(HAS_APPLE_PAC)
\t/*
\t * Unsigned PAC compatibility (munch/non-PAC): real PAC opcodes trap
\t * as undefined instructions on this CPU. Emulate them with unsigned
\t * semantics for 64-bit EL0 threads only; kernel faults, 32-bit
\t * state, DTrace probes, and debugger traps keep their exact old
\t * behavior. PACGA is recognized but unsupported and falls through
\t * to SIGILL; a faulting LDRA access triages EXC_BAD_ACCESS.
\t * (The DTrace fast-trap opcodes never match the PAC decoder, so no
\t * special-case is needed here; the CONFIG_DTRACE block below runs
\t * for anything the emulator does not consume.)
\t */
\tif (is_saved_state64(state) && PSR64_IS_USER64(get_saved_state_cpsr(state))) {
\t\tarm_saved_state64_t *ss64 = saved_state64(state);
\t\tmunch_pac_state_t mps;
\t\tuint64_t mpc = ss64->pc;
\t\tint mrc;

\t\tmps.x = ss64->x;
\t\tmps.fp = &ss64->fp;
\t\tmps.lr = &ss64->lr;
\t\tmps.sp = &ss64->sp;
\t\tmps.pc = &ss64->pc;
\t\tmps.load64 = munch_pac_copyin64;
\t\tmps.mem_ctx = NULL;

\t\tmrc = munch_pac_emulate(&mps, instr, mpc);
\t\tif (mrc == MUNCH_PAC_OK) {
\t\t\treturn;
\t\t} else if (mrc == MUNCH_PAC_FAULT) {
\t\t\tmunch_pac_bad_access(&mps, instr);
\t\t\t__builtin_unreachable();
\t\t}
\t\t/* UNKNOWN and SIGILL fall through to triage below. */
\t}
#endif /* BCM2837 && !HAS_APPLE_PAC */

#if CONFIG_DTRACE
"""

HELPER_ANCHOR = "/*\n * Uncategorized exceptions are a catch-all for general execution errors."
HELPER_NEW = """#if defined(ARM64_BOARD_CONFIG_BCM2837) && !defined(HAS_APPLE_PAC)
static uint64_t
munch_pac_copyin64(uint64_t addr, void *ctx, int *err)
{
\tuint64_t val = 0;
\tint rc;

\t(void)ctx;
\trc = copyin(VM_USER_STRIP_TBI(addr), (char *)&val, sizeof(val));
\tif (err) {
\t\t*err = rc;
\t}
\treturn val;
}

/*
 * EXC_BAD_ACCESS for a faulting LDRA access. copyin already paged in
 * everything it could, so a failure here is a genuine bad address, not
 * a retry: report KERN_INVALID_ADDRESS with the faulting effective
 * address. Never advances pc.
 */
static void
munch_pac_bad_access(munch_pac_state_t *mps, uint32_t instr)
{
\texception_type_t exc = EXC_BAD_ACCESS;
\tmach_exception_data_type_t codes[2];
\tmach_msg_type_number_t numcodes = 2;

\tcodes[0] = KERN_INVALID_ADDRESS;
\tcodes[1] = (mach_exception_data_type_t)munch_pac_ldra_addr(mps, instr);
\texception_triage(exc, codes, numcodes);
\t__builtin_unreachable();
}
#endif /* BCM2837 && !HAS_APPLE_PAC */

/*
 * Uncategorized exceptions are a catch-all for general execution errors."""


def fail(msg):
    print(f"apply-instructions: {msg}", file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        fail(f"usage: {Path(sys.argv[0]).name} <xnu-root>")
    root = Path(sys.argv[1])
    if not (root / "osfmk/arm64/sleh.c").is_file():
        fail(f"not an XNU tree (no osfmk/arm64/sleh.c under {root})")
    if not HEADER_SRC.is_file():
        fail(f"missing {HEADER_SRC}")

    sleh_path = root / SLEH
    text = sleh_path.read_text()

    if "munch_pac_emu.h" in text or "munch_pac_emulate" in text:
        fail(f"{sleh_path} already contains a PAC hook; refusing to double-apply")

    if text.count(INCLUDE_ANCHOR) != 1:
        fail(f"include anchor matches {text.count(INCLUDE_ANCHOR)}x, want exactly 1")
    if text.count(HOOK_ANCHOR) != 1:
        fail(f"hook anchor matches {text.count(HOOK_ANCHOR)}x, want exactly 1")
    if text.count(HELPER_ANCHOR) != 1:
        fail(f"helper anchor matches {text.count(HELPER_ANCHOR)}x, want exactly 1")

    new = text.replace(INCLUDE_ANCHOR, INCLUDE_NEW, 1)
    new = new.replace(HOOK_ANCHOR, HOOK_NEW, 1)
    new = new.replace(HELPER_ANCHOR, HELPER_NEW, 1)
    assert new != text

    dst = root / HEADER_DST
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(HEADER_SRC, dst)
    sleh_path.write_text(new)
    print(f"copied {HEADER_SRC.name} -> {dst}")
    print(f"patched {sleh_path} (include + hook + helpers)")


if __name__ == "__main__":
    main()
