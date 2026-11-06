#!/usr/bin/env python3
"""Behavior test for the unsigned PAC emulator.

Usage: python3 test-pac-emu.py

Compiles kernel-ci/compat/pac-emu.h with the host clang into a small C
driver (kept in a temp dir, never in the repo) and runs it. The driver
exercises real header behavior: sign no-ops, auth strips, branch/link
aliases, LDRA offsets/writeback/faults, reserved-opcode rejection, and
null/tag canonicalization. Prints PASS/FAIL per case and exits nonzero on
any failure.
"""

import subprocess
import sys
import tempfile
from pathlib import Path

COMPAT = Path(__file__).resolve().parent
HEADER = COMPAT / "pac-emu.h"
CC = "clang"

DRIVER = r"""
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "pac-emu.h"

static int fails = 0;
static int count = 0;
#define CHECK(cond, ...) do { count++; if (!(cond)) { fails++; printf("FAIL: " __VA_ARGS__); printf("\n"); } } while (0)

// Fake memory: three mapped pages; the second page's low half is an
// unmapped hole. MEM_BASE+addr arithmetic below matches real offsets.
#define MEM_BASE 0x100000ull
#define MEM_SIZE 0x3000ull
#define HOLE_LO (MEM_BASE + 0x1000ull)
#define HOLE_HI (MEM_BASE + 0x1800ull)
static uint8_t mem[MEM_SIZE];
static unsigned load_calls;
static uint64_t
t_load(uint64_t addr, void *ctx, int *err)
{
	uint64_t v = 0;
	(void)ctx;
	load_calls++;
	if (addr < MEM_BASE || addr > MEM_BASE + MEM_SIZE - 8 ||
	    (addr < HOLE_HI && addr + 8 > HOLE_LO)) {
		*err = 1;
		return 0;
	}
	memcpy(&v, &mem[addr - MEM_BASE], 8);
	*err = 0;
	return v;
}

typedef struct {
	uint64_t x[29];
	uint64_t fp, lr, sp, pc;
	munch_pac_state_t s;
} regs;

static void
init(regs *r, uint64_t pc)
{
	memset(r, 0, sizeof(*r));
	load_calls = 0;
	r->pc = pc;
	r->s.x = r->x;
	r->s.fp = &r->fp;
	r->s.lr = &r->lr;
	r->s.sp = &r->sp;
	r->s.pc = &r->pc;
	r->s.load64 = t_load;
	r->s.mem_ctx = NULL;
}

// All words confirmed with: llvm-mc --triple=aarch64 -mattr=+pauth.
#define I_PACIA_X9_X10  0xdac10149u
#define I_PACDA_X9_X10  0xdac10949u
#define I_AUTIA_X9_X10  0xdac11149u
#define I_AUTDA_X9_X10  0xdac11949u
#define I_PACIZA_X8     0xdac123e8u
#define I_AUTIZA_X8     0xdac133e8u
#define I_AUTDZA_X8     0xdac13be8u
#define I_XPACI_X12     0xdac143ecu
#define I_XPACD_X13     0xdac147edu
#define I_BRAA_X0_X1    0xd71f0801u
#define I_BRAAZ_X4      0xd61f089fu
#define I_BLRAB_X8_X9   0xd73f0d09u
#define I_BLRAAZ_X10    0xd63f095fu
#define I_BLRAA_X30_X16 0xd73f0bd0u
#define I_RETAA         0xd65f0bffu
#define I_RETAB         0xd65f0fffu
#define I_LDRAA_X0_X1_8 0xf8201420u
#define I_LDRAA_X0_X1_N4096 0xf8600420u
#define I_LDRAA_X0_X1_P4088 0xf83ff420u
#define I_LDRAB_X2_X3_M16 0xf8ffe462u
#define I_LDRAA_X4_X5_8W 0xf8201ca4u
#define I_LDRAA_X9_SP16W 0xf8202fe9u
#define I_LDRAB_X0_X9_M8 0xf8fff520u
#define I_PACGA         0x9ac23020u
#define I_ERETAA        0xd69f0bffu
#define I_ERETAB        0xd69f0fffu
#define I_RBIT          0xdac00020u
#define I_MADD          0x9b020c20u
#define I_BR_X9         0xd61f0120u
#define I_BLR_X9        0xd63f0120u
#define I_RET_X9        0xd65f0120u
#define I_NOP           0xd503201fu
#define I_LDR           0xf9400020u
#define I_LDAPR         0xf8bfc020u

// Synthetic signatures occupy the configured PAC field; bit 55 is the
// independent extent selector, and data tags remain in the top byte.
#define SC(hi, lo, va) ((((uint64_t)(hi)) << 56) | ((((uint64_t)(lo)) & ((1ull << (55 - MUNCH_PAC_VA_BITS)) - 1)) << MUNCH_PAC_VA_BITS) | (((lo) & 0x100u) ? (1ull << 55) : 0) | ((va) & MUNCH_PAC_VA_MASK))
#define SD(tag, lo, va) SC(tag, lo, va)

int
main(void)
{
	regs r;

	// 1. PACIA signs Rd, never copies the Rn modifier.
	init(&r, 0x1000);
	r.x[9] = 0x1111; r.x[10] = 0x2222;
	CHECK(munch_pac_emulate(&r.s, I_PACIA_X9_X10, 0x1000) == MUNCH_PAC_OK, "pacia rc");
	CHECK(r.x[9] == 0x1111, "pacia keeps Rd, got %llx", (unsigned long long)r.x[9]);
	CHECK(r.x[10] == 0x2222, "pacia keeps modifier");
	CHECK(r.pc == 0x1004, "pacia advances pc");

	// 2. PACDA with distinct values is also a pure no-op.
	init(&r, 0x2000);
	r.x[9] = 0xabcd; r.x[10] = 0x5555;
	CHECK(munch_pac_emulate(&r.s, I_PACDA_X9_X10, 0x2000) == MUNCH_PAC_OK, "pacda rc");
	CHECK(r.x[9] == 0xabcd && r.pc == 0x2004, "pacda no-op");

	// 3. AUTIA strips Rd (code semantics), ignores Rn.
	init(&r, 0x3000);
	r.x[9] = SC(0xd5, 0x6e, 0x1234); r.x[10] = 0x7777;
	CHECK(munch_pac_emulate(&r.s, I_AUTIA_X9_X10, 0x3000) == MUNCH_PAC_OK, "autia rc");
	CHECK(r.x[9] == 0x1234, "autia strips code, got %llx", (unsigned long long)r.x[9]);
	CHECK(r.x[10] == 0x7777, "autia keeps modifier");

	// 4. AUTDA strips PAC but preserves the TBI tag byte [63:56].
	init(&r, 0x4000);
	r.x[9] = SD(0x12, 0x6e, 0x1234);
	CHECK(munch_pac_emulate(&r.s, I_AUTDA_X9_X10, 0x4000) == MUNCH_PAC_OK, "autda rc");
	CHECK(r.x[9] == 0x1200000000001234ull, "autda keeps tag, got %llx", (unsigned long long)r.x[9]);

	// 5. Zero modifier forms: PACIZA no-op, AUTIZA/AUTDZA strip Rd.
	init(&r, 0x5000);
	r.x[8] = 0xdeadbeef;
	CHECK(munch_pac_emulate(&r.s, I_PACIZA_X8, 0x5000) == MUNCH_PAC_OK, "paciza rc");
	CHECK(r.x[8] == 0xdeadbeef && r.pc == 0x5004, "paciza no-op");
	r.x[8] = SC(0xab, 0x11, 0x4321);
	CHECK(munch_pac_emulate(&r.s, I_AUTIZA_X8, 0x5004) == MUNCH_PAC_OK, "autiza rc");
	CHECK(r.x[8] == 0x4321, "autiza strips");
	r.x[8] = SD(0x34, 0x1b, 0x9999);
	CHECK(munch_pac_emulate(&r.s, I_AUTDZA_X8, 0x5008) == MUNCH_PAC_OK, "autdza rc");
	CHECK(r.x[8] == 0x3400000000009999ull, "autdza keeps tag");

	// 6. XPACI clears PAC; XPACD preserves the top-byte tag.
	init(&r, 0x6000);
	r.x[12] = SC(0x70, 0x07, 0x1000);
	CHECK(munch_pac_emulate(&r.s, I_XPACI_X12, 0x6000) == MUNCH_PAC_OK, "xpaci rc");
	CHECK(r.x[12] == 0x1000, "xpaci strips");
	r.x[13] = SD(0x55, 0x77, 0x2000);
	CHECK(munch_pac_emulate(&r.s, I_XPACD_X13, 0x6004) == MUNCH_PAC_OK, "xpacd rc");
	CHECK(r.x[13] == 0x5500000000002000ull, "xpacd keeps tag, got %llx", (unsigned long long)r.x[13]);

	// 7. Register 31: reads zero, discards writes.
	init(&r, 0x7000);
	CHECK(munch_pac_reg(&r.s, 31) == 0, "x31 reads zero");
	munch_pac_set_reg(&r.s, 31, 0xffff);
	CHECK(munch_pac_reg(&r.s, 31) == 0, "x31 discards writes");
	// XPACI x31 must still advance pc and not crash.
	CHECK(munch_pac_emulate(&r.s, 0xdac143ffu, 0x7000) == MUNCH_PAC_OK, "xpaci xzr rc");
	CHECK(r.pc == 0x7004, "xpaci xzr advances");

	// 8. BRAA/zero forms branch to the stripped target.
	init(&r, 0x100000);
	r.x[0] = SC(0x40, 0x00, 0x100200); r.x[1] = 0x99;
	CHECK(munch_pac_emulate(&r.s, I_BRAA_X0_X1, 0x100000) == MUNCH_PAC_OK, "braa rc");
	CHECK(r.pc == 0x100200, "braa target, got %llx", (unsigned long long)r.pc);
	init(&r, 0x100000);
	r.x[4] = SC(0x41, 0x01, 0x100300);
	CHECK(munch_pac_emulate(&r.s, I_BRAAZ_X4, 0x100000) == MUNCH_PAC_OK, "braaz rc");
	CHECK(r.pc == 0x100300, "braaz target");

	// 9. BLRAB writes old pc+4 to LR, then branches.
	init(&r, 0x200000);
	r.x[8] = SC(0x42, 0x02, 0x200400); r.x[9] = 0x11; r.lr = 0x0;
	CHECK(munch_pac_emulate(&r.s, I_BLRAB_X8_X9, 0x200000) == MUNCH_PAC_OK, "blrab rc");
	CHECK(r.lr == 0x200004, "blrab link");
	CHECK(r.pc == 0x200400, "blrab target");
	// BLRAAZ zero-modifier form.
	init(&r, 0x200000);
	r.x[10] = SC(0x43, 0x03, 0x200500);
	CHECK(munch_pac_emulate(&r.s, I_BLRAAZ_X10, 0x200000) == MUNCH_PAC_OK, "blraaz rc");
	CHECK(r.lr == 0x200004 && r.pc == 0x200500, "blraaz link+target");

	// 10. Aliased BLRAA x30,x16: authenticate old LR first, then link.
	init(&r, 0x300000);
	r.lr = SC(0x44, 0x04, 0x300600); r.x[16] = 0x5;
	CHECK(munch_pac_emulate(&r.s, I_BLRAA_X30_X16, 0x300000) == MUNCH_PAC_OK, "blraa alias rc");
	CHECK(r.pc == 0x300600, "blraa alias branches old LR, got %llx", (unsigned long long)r.pc);
	CHECK(r.lr == 0x300004, "blraa alias link after");

	// 11. RETAA/RETAB return through stripped LR.
	init(&r, 0x400000);
	r.lr = SC(0x45, 0x05, 0x400700);
	CHECK(munch_pac_emulate(&r.s, I_RETAA, 0x400000) == MUNCH_PAC_OK, "retaa rc");
	CHECK(r.pc == 0x400700, "retaa target");
	init(&r, 0x400000);
	r.lr = SC(0x46, 0x06, 0x400800);
	CHECK(munch_pac_emulate(&r.s, I_RETAB, 0x400000) == MUNCH_PAC_OK, "retab rc");
	CHECK(r.pc == 0x400800, "retab target");

	// 12. LDRAA positive offset, no writeback. Loaded value is RAW.
	memset(mem, 0, sizeof(mem));
	*(uint64_t *)&mem[0x008] = 0xf00dcafef00dcafeull; // upper bits raw data
	init(&r, 0x500000);
	r.x[1] = SD(0x00, 0x6e, MEM_BASE); // strips to MEM_BASE
	CHECK(munch_pac_emulate(&r.s, I_LDRAA_X0_X1_8, 0x500000) == MUNCH_PAC_OK, "ldraa rc");
	CHECK(r.x[0] == 0xf00dcafef00dcafeull, "ldraa raw value, got %llx", (unsigned long long)r.x[0]);
	CHECK(r.x[1] == SD(0x00, 0x6e, MEM_BASE), "ldraa no writeback");
	CHECK(r.pc == 0x500004, "ldraa advances");

	// 13. LDRAB negative offset: ldrab x2,[x3,#-16].
	*(uint64_t *)&mem[0x000] = 0x123ull;
	init(&r, 0x500000);
	r.x[3] = MEM_BASE + 0x10;
	CHECK(munch_pac_emulate(&r.s, I_LDRAB_X2_X3_M16, 0x500000) == MUNCH_PAC_OK, "ldrab neg rc");
	CHECK(r.x[2] == 0x123, "ldrab neg value, got %llx", (unsigned long long)r.x[2]);

	// 14. LDRAA pre-indexed writeback after success.
	*(uint64_t *)&mem[0x208] = 0x777ull;
	init(&r, 0x500000);
	r.x[5] = MEM_BASE + 0x200;
	CHECK(munch_pac_emulate(&r.s, I_LDRAA_X4_X5_8W, 0x500000) == MUNCH_PAC_OK, "ldraa wb rc");
	CHECK(r.x[4] == 0x777, "ldraa wb value");
	CHECK(r.x[5] == MEM_BASE + 0x208, "ldraa wb base");

	// 15. LDRAA via SP with writeback: ldraa x9,[sp,#16]!.
	*(uint64_t *)&mem[0x310] = 0x123ull;
	init(&r, 0x500000);
	r.sp = MEM_BASE + 0x300;
	CHECK(munch_pac_emulate(&r.s, I_LDRAA_X9_SP16W, 0x500000) == MUNCH_PAC_OK, "ldraa sp rc");
	CHECK(r.x[9] == 0x123, "ldraa sp value");
	CHECK(r.sp == MEM_BASE + 0x310, "ldraa sp writeback, got %llx", (unsigned long long)r.sp);

	// Check the original SP, not the offset-adjusted effective address.
	const uint32_t misaligned_sp_ops[] = {0xf82007e0u, 0xf8a01fe0u};
	for (unsigned i = 0; i < sizeof(misaligned_sp_ops) / sizeof(misaligned_sp_ops[0]); ++i) {
		init(&r, 0x500000);
		r.sp = MEM_BASE + 8;
		r.x[0] = 0xdead;
		CHECK(munch_pac_emulate(&r.s, misaligned_sp_ops[i], r.pc) == MUNCH_PAC_SP_ALIGN,
		    "misaligned SP faults before load");
		CHECK(load_calls == 0, "misaligned SP performs no memory access");
		CHECK(r.x[0] == 0xdead && r.sp == MEM_BASE + 8 && r.pc == 0x500000,
		    "SP alignment fault preserves state");
	}
	*(uint64_t *)&mem[8] = 0x5678;
	init(&r, 0x500000);
	r.sp = MEM_BASE;
	CHECK(munch_pac_emulate(&r.s, 0xf8201fe0u, r.pc) == MUNCH_PAC_OK,
	    "aligned SP permits eight-byte pre-index offset");
	CHECK(r.x[0] == 0x5678 && r.sp == MEM_BASE + 8 && r.pc == 0x500004,
	    "successful SP writeback need not stay sixteen-byte aligned");

	// 16. Signed 10-bit offset extremes: -4096 and +4088.
	*(uint64_t *)&mem[0x000] = 0xaaaaull;
	init(&r, 0x500000);
	r.x[1] = MEM_BASE + 0x1000;
	CHECK(munch_pac_emulate(&r.s, I_LDRAA_X0_X1_N4096, 0x500000) == MUNCH_PAC_OK, "ldraa -4096 rc");
	CHECK(r.x[0] == 0xaaaa, "ldraa -4096 value");
	*(uint64_t *)&mem[0x2ff8] = 0xbbbbull;
	init(&r, 0x500000);
	r.x[1] = MEM_BASE + 0x2000;
	CHECK(munch_pac_emulate(&r.s, I_LDRAA_X0_X1_P4088, 0x500000) == MUNCH_PAC_OK, "ldraa +4088 rc");
	CHECK(r.x[0] == 0xbbbb, "ldraa +4088 value, got %llx", (unsigned long long)r.x[0]);

	// 17. Failed load preserves state: address inside the hole, no advance.
	init(&r, 0x600000);
	r.x[1] = HOLE_LO - 8; // +8 lands fully inside the hole
	r.x[0] = 0xdead;
	{
		int rc = munch_pac_emulate(&r.s, I_LDRAA_X0_X1_8, 0x600000);
		CHECK(rc == MUNCH_PAC_FAULT, "ldraa fault rc %d", rc);
	}
	CHECK(r.x[0] == 0xdead, "fault keeps Rt");
	CHECK(r.x[1] == HOLE_LO - 8, "fault keeps Rn");
	CHECK(r.pc == 0x600000, "fault keeps pc");
	CHECK(munch_pac_ldra_addr(&r.s, I_LDRAA_X0_X1_8) == HOLE_LO, "fault addr helper");
	// Pre-indexed fault must not write back either.
	init(&r, 0x600000);
	r.sp = HOLE_LO - 16; // +16 lands fully inside the hole
	{
		int rc = munch_pac_emulate(&r.s, I_LDRAA_X9_SP16W, 0x600000);
		CHECK(rc == MUNCH_PAC_FAULT, "ldraa sp fault rc %d", rc);
	}
	CHECK(r.sp == HOLE_LO - 16, "fault keeps sp");

	const uint64_t crossing_hole[] = {HOLE_LO - 4, HOLE_HI - 4};
	for (unsigned i = 0; i < sizeof(crossing_hole) / sizeof(crossing_hole[0]); ++i) {
		init(&r, 0x600000);
		r.x[1] = crossing_hole[i];
		r.x[0] = 0xdead;
		CHECK(munch_pac_emulate(&r.s, 0xf8200420u, r.pc) == MUNCH_PAC_FAULT,
		    "load crossing either hole boundary fails");
		CHECK(r.x[0] == 0xdead && r.x[1] == crossing_hole[i] && r.pc == 0x600000,
		    "crossing-hole failure preserves state");
	}

	// 18. Reserved/malformed encodings stay UNKNOWN (never consumed).
	init(&r, 0x700000);
	CHECK(munch_pac_emulate(&r.s, 0xdac1ffe3u, 0x700000) == MUNCH_PAC_UNKNOWN, "reserved keyop");
	CHECK(munch_pac_emulate(&r.s, 0xdac12148u, 0x700000) == MUNCH_PAC_UNKNOWN, "paciza bad Rn");
	CHECK(munch_pac_emulate(&r.s, 0xd61f0885u, 0x700000) == MUNCH_PAC_UNKNOWN, "braaz bad Rm");
	CHECK(munch_pac_emulate(&r.s, I_ERETAA, 0x700000) == MUNCH_PAC_UNKNOWN, "eretaa unknown");
	CHECK(munch_pac_emulate(&r.s, I_ERETAB, 0x700000) == MUNCH_PAC_UNKNOWN, "eretab unknown");
	CHECK(r.pc == 0x700000, "unknown keeps pc");

	// 19. Neighbors that must NOT decode as PAC.
	init(&r, 0x800000);
	CHECK(munch_pac_emulate(&r.s, I_RBIT, 0x800000) == MUNCH_PAC_UNKNOWN, "rbit unknown");
	CHECK(munch_pac_emulate(&r.s, I_MADD, 0x800000) == MUNCH_PAC_UNKNOWN, "madd unknown");
	CHECK(munch_pac_emulate(&r.s, I_BR_X9, 0x800000) == MUNCH_PAC_UNKNOWN, "br unknown");
	CHECK(munch_pac_emulate(&r.s, I_BLR_X9, 0x800000) == MUNCH_PAC_UNKNOWN, "blr unknown");
	CHECK(munch_pac_emulate(&r.s, I_RET_X9, 0x800000) == MUNCH_PAC_UNKNOWN, "ret unknown");
	CHECK(munch_pac_emulate(&r.s, I_NOP, 0x800000) == MUNCH_PAC_UNKNOWN, "nop unknown");
	CHECK(munch_pac_emulate(&r.s, I_LDR, 0x800000) == MUNCH_PAC_UNKNOWN, "ldr unknown");
	CHECK(munch_pac_emulate(&r.s, I_LDAPR, 0x800000) == MUNCH_PAC_UNKNOWN, "ldapr unknown");
	CHECK(munch_pac_emulate(&r.s, 0, 0x800000) == MUNCH_PAC_UNKNOWN, "zero word unknown");

	// 20. PACGA is explicit SIGILL, never zero/no-op.
	init(&r, 0x900000);
	r.x[0] = 0xaaaa;
	CHECK(munch_pac_emulate(&r.s, I_PACGA, 0x900000) == MUNCH_PAC_SIGILL, "pacga sigill");
	CHECK(r.x[0] == 0xaaaa && r.pc == 0x900000, "pacga untouched");

	// 21. Null and canonicalization boundaries.
	CHECK(munch_pac_strip_code(0) == 0, "code null");
	CHECK(munch_pac_strip_data(0) == 0, "data null");
	CHECK(munch_pac_strip_code(0x1234) == 0x1234, "code canonical passthrough");
	CHECK(munch_pac_strip_data(0x1200000000001234ull) == 0x1200000000001234ull, "data tag passthrough");
	CHECK(munch_pac_strip_code(0xfffffff007a73860ull) == 0xfffffff007a73860ull, "code kernel passthrough");
	CHECK(munch_pac_strip_data(0xfffffff007a73860ull) == 0xfffffff007a73860ull, "data kernel passthrough");
#if T0SZ_BOOT == 26
	CHECK(munch_pac_strip_code(0x1ffffffffffffull) == 0x3fffffffffull, "code va clamp");
	CHECK(munch_pac_strip_code(0x0080000000001000ull) == 0xffffffc000001000ull, "code extent selector");
	CHECK(munch_pac_strip_data(SD(0x34, 0x1ab, 0x9999)) == 0x34ffffc000009999ull, "data extent+tag");
#else
	CHECK(munch_pac_strip_code(0x1ffffffffffffull) == 0xffffffffffffull, "code va clamp");
	CHECK(munch_pac_strip_code(0x0080000000001000ull) == 0xffff000000001000ull, "code extent selector");
	CHECK(munch_pac_strip_data(SD(0x34, 0x1ab, 0x9999)) == 0x34ff000000009999ull, "data extent+tag");
#endif
	// PAC that sets the sign bit still decodes to the user VA.
	CHECK(munch_pac_strip_code(SC(0xd5, 0xcd, 0x1234)) == 0x1234, "code signbit PAC");

	if (fails == 0) {
		printf("PASS: %d checks\n", count);
		return 0;
	}
	printf("FAIL: %d/%d checks failed\n", fails, count);
	return 1;
}
"""


def main():
    if len(sys.argv) != 1:
        print(f"usage: {Path(sys.argv[0]).name}", file=sys.stderr)
        sys.exit(2)
    if not HEADER.is_file():
        print(f"test-pac-emu: missing {HEADER}", file=sys.stderr)
        sys.exit(2)
    with tempfile.TemporaryDirectory(prefix="pac-emu-test-") as td:
        tdir = Path(td)
        (tdir / "pac-emu.h").write_bytes(HEADER.read_bytes())
        (tdir / "test.c").write_text(DRIVER)
        exe = tdir / "test-pac-emu"
        for t0sz in (26, 16):
            cc = subprocess.run(
                [CC, "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1",
                 f"-DT0SZ_BOOT={t0sz}", "-o", str(exe), str(tdir / "test.c")],
                capture_output=True, text=True)
            if cc.returncode != 0:
                print(cc.stdout)
                print(cc.stderr, file=sys.stderr)
                sys.exit(cc.returncode)
            run = subprocess.run([str(exe)], capture_output=True, text=True)
            print(f"VA{64 - t0sz}: {run.stdout}", end="")
            sys.stderr.write(run.stderr)
            if run.returncode != 0:
                sys.exit(run.returncode)


if __name__ == "__main__":
    main()
