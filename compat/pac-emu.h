// Copyright (c) 2026. Unsigned PAC compatibility for plain-arm64 kernels
// running arm64e userland.
//
// A non-PAC CPU (SM8250) raises an undefined-instruction exception on every
// real PAC opcode. This header emulates them with unsigned semantics: signing
// is a no-op, authentication strips the PAC field instead of verifying it.
// The user explicitly accepts losing PAC security on this board; correctness
// of branches and loads is kept.
//
// HINT-form sign and auth instructions (pacibsp, autibsp, pacia1716, and
// friends) are architectural NOPs on this CPU and never trap, so they need
// no handling here. Only encodings that fault get decoded.
//
// Design: allocation-free, pure C, no key-register access, no PAC opcodes,
// no global state. Callers pass live register storage (the kernel hook
// passes saved-state pointers; the host test passes its own array) plus a
// 64-bit load callback used only by LDRAA and LDRAB.

#ifndef MUNCH_PAC_EMU_H
#define MUNCH_PAC_EMU_H

#include <stdint.h>

// Use the kernel's actual TTBR0 width. BCM2837 builds with T0SZ_BOOT=26
// (38-bit user VA), not the 47-bit width of a 16 KiB configuration.
// Standalone callers must define their platform's T0SZ_BOOT before inclusion.
#define MUNCH_PAC_VA_BITS (64u - T0SZ_BOOT)
#define MUNCH_PAC_VA_MASK ((1ull << MUNCH_PAC_VA_BITS) - 1u)
#define MUNCH_PAC_TAG_MASK (0xffull << 56)

// Emulator outcomes.
#define MUNCH_PAC_OK 0      // emulated; registers and pc already updated
#define MUNCH_PAC_UNKNOWN -1 // not a PAC opcode; caller must not consume it
#define MUNCH_PAC_FAULT -2   // LDRA memory access failed; state untouched
#define MUNCH_PAC_SIGILL -3  // recognized but unsupported (PACGA); SIGILL it

// Live register view. x points at contiguous x0..x28 storage; fp, lr, sp,
// and pc point at their own live cells. Register 31 reads as zero and
// discards writes. load64 reads faulting user memory; it sets *err nonzero
// on failure and its return value is ignored then. It may be NULL only
// when the caller guarantees no LDRA is decoded (host tests set it always).
typedef struct munch_pac_state {
	uint64_t *x; // x0..x28 contiguous
	uint64_t *fp; // x29
	uint64_t *lr; // x30
	uint64_t *sp;
	uint64_t *pc;
	uint64_t (*load64)(uint64_t addr, void *ctx, int *err);
	void *mem_ctx;
} munch_pac_state_t;

static inline uint64_t
munch_pac_reg(const munch_pac_state_t *s, unsigned r)
{
	if (r == 31) {
		return 0;
	}
	if (r == 29) {
		return *s->fp;
	}
	if (r == 30) {
		return *s->lr;
	}
	return s->x[r];
}

static inline void
munch_pac_set_reg(munch_pac_state_t *s, unsigned r, uint64_t v)
{
	if (r == 31) {
		return;
	}
	if (r == 29) {
		*s->fp = v;
		return;
	}
	if (r == 30) {
		*s->lr = v;
		return;
	}
	s->x[r] = v;
}

// ARM Strip uses bit 55 for sign extension; data keeps TBI bits [63:56].
static inline uint64_t
munch_pac_strip_code(uint64_t p)
{
	if (p == 0) {
		return 0;
	}
	if ((p >> 55) & 1u) {
		return (p & MUNCH_PAC_VA_MASK) | ~MUNCH_PAC_VA_MASK;
	}
	return p & MUNCH_PAC_VA_MASK;
}

static inline uint64_t
munch_pac_strip_data(uint64_t p)
{
	uint64_t out;

	if (p == 0) {
		return 0;
	}
	out = (p & MUNCH_PAC_VA_MASK) | (p & MUNCH_PAC_TAG_MASK);
	if ((p >> 55) & 1u) {
		out |= ~MUNCH_PAC_VA_MASK & ~MUNCH_PAC_TAG_MASK;
	}
	return out;
}

// Faulting effective address of an LDRAA/LDRAB, for the EXC_BAD_ACCESS
// path. The base authenticates (strip_data); the 10-bit signed offset is
// S(bit22)::imm9(bits20:12) scaled by 8. Call only for an LDRA insn.
static inline uint64_t
munch_pac_ldra_addr(const munch_pac_state_t *s, uint32_t insn)
{
	unsigned rn = (insn >> 5) & 0x1fu;
	int32_t mag = (int32_t)(((insn >> 12) & 0x1ffu) | ((insn >> 13) & 0x200u));
	int64_t off;
	uint64_t base;

	if (mag & 0x200) {
		mag -= 0x400;
	}
	off = (int64_t)mag * 8;
	if (rn == 31) {
		base = munch_pac_strip_data(*s->sp);
	} else {
		base = munch_pac_strip_data(munch_pac_reg(s, rn));
	}
	return base + (uint64_t)off;
}

// Decode one trapped instruction. Returns MUNCH_PAC_*; on OK the state is
// updated (destination register, writeback, pc). LDRA faults leave every
// register, sp, and pc untouched and return FAULT so the caller can run
// real EXC_BAD_ACCESS instead of silently advancing.
static inline int
munch_pac_emulate(munch_pac_state_t *s, uint32_t insn, uint64_t cur_pc)
{
	unsigned rd, rn, rm;
	uint64_t base, addr;
	int err;

	// PACIA/PACIB/PACDA/PACDB/AUTIA/AUTIB/AUTDA/AUTDB register forms,
	// PACIZA/PACIZB/PACDZA/PACDZB, AUTIZA/AUTIZB/AUTDZA/AUTDZB,
	// and XPACI/XPACD: 1101010110 00000001 keyop Rn Rd. The fixed top
	// half 0xdac1 separates this group from RBIT/REV/CLZ neighbors
	// (top half 0xdac0); field bits [15:10] selects the operation.
	// Zero-modifier forms (keyop >= 8) require Rn == 31; anything else
	// is a malformed encoding and stays UNKNOWN.
	if ((insn & 0xffff0000u) == 0xdac10000u) {
		unsigned keyop = (insn >> 10) & 0x3fu;
		rd = insn & 0x1fu;
		rn = (insn >> 5) & 0x1fu;
		rm = (insn >> 16) & 0x1fu;
		(void)rm;
		if (keyop >= 0x08u && rn != 31) {
			return MUNCH_PAC_UNKNOWN;
		}
		switch (keyop) {
		case 0x00u: // PACIA Rd, Rn/Rm
		case 0x01u: // PACIB
		case 0x02u: // PACDA
		case 0x03u: // PACDB
			// Signing is a no-op on Rd; the modifier only feeds
			// the dropped signature. Never copy the modifier
			// into Rd: PACIA Rd,Rn signs Rd.
			*s->pc = cur_pc + 4;
			return MUNCH_PAC_OK;
		case 0x04u: // AUTIA Rd, Rn/Rm
		case 0x05u: // AUTIB
			munch_pac_set_reg(s, rd, munch_pac_strip_code(munch_pac_reg(s, rd)));
			(void)rn;
			*s->pc = cur_pc + 4;
			return MUNCH_PAC_OK;
		case 0x06u: // AUTDA
		case 0x07u: // AUTDB
			munch_pac_set_reg(s, rd, munch_pac_strip_data(munch_pac_reg(s, rd)));
			(void)rn;
			*s->pc = cur_pc + 4;
			return MUNCH_PAC_OK;
		case 0x08u: // PACIZA
		case 0x09u: // PACIZB
		case 0x0au: // PACDZA
		case 0x0bu: // PACDZB
			*s->pc = cur_pc + 4;
			return MUNCH_PAC_OK;
		case 0x0cu: // AUTIZA
		case 0x0du: // AUTIZB
			munch_pac_set_reg(s, rd, munch_pac_strip_code(munch_pac_reg(s, rd)));
			*s->pc = cur_pc + 4;
			return MUNCH_PAC_OK;
		case 0x0eu: // AUTDZA
		case 0x0fu: // AUTDZB
			munch_pac_set_reg(s, rd, munch_pac_strip_data(munch_pac_reg(s, rd)));
			*s->pc = cur_pc + 4;
			return MUNCH_PAC_OK;
		case 0x10u: // XPACI
			munch_pac_set_reg(s, rd, munch_pac_strip_code(munch_pac_reg(s, rd)));
			*s->pc = cur_pc + 4;
			return MUNCH_PAC_OK;
		case 0x11u: // XPACD
			munch_pac_set_reg(s, rd, munch_pac_strip_data(munch_pac_reg(s, rd)));
			*s->pc = cur_pc + 4;
			return MUNCH_PAC_OK;
		default:
			return MUNCH_PAC_UNKNOWN;
		}
	}

	// Authenticated branches and returns.
	// RETAA/RETAB first: exact encodings 11010110010 11111 0000 op
	// 11111 11111. Plain RET (op 00, Rn variable) never matches.
	if (insn == 0xd65f0bffu || insn == 0xd65f0fffu) {
		*s->pc = munch_pac_strip_code(munch_pac_reg(s, 30));
		return MUNCH_PAC_OK;
	}

	// Authenticated branches: bit 24 selects the modifier form, bit 21
	// links, and bit 10 selects the key. Keep bit 22 to exclude RET.
	// Zero-modifier forms require Rm == 31.
	if ((insn & 0xffdff800u) == 0xd61f0800u ||
	    (insn & 0xffdff800u) == 0xd71f0800u) {
		rn = (insn >> 5) & 0x1fu;
		rm = insn & 0x1fu;
		if (((insn >> 24) & 1u) == 0 && rm != 31) {
			return MUNCH_PAC_UNKNOWN;
		}
		base = munch_pac_strip_code(munch_pac_reg(s, rn));
		if ((insn >> 21) & 1u) {
			// BLRA: link after reading Rn, so an Rn==30
			// alias still branches to the old LR, matching
			// hardware which authenticates Rn first.
			*s->lr = cur_pc + 4;
		}
		(void)rm; // modifier ignored under unsigned semantics
		*s->pc = base;
		return MUNCH_PAC_OK;
	}

	// LDRAA/LDRAB immediate, optionally pre-indexed with writeback:
	// 11 11100 M S imm9 W 1 Rn Rt. M selects A/B, S is the offset
	// sign, W is pre-index writeback. Mask ignores the key, sign,
	// offset, writeback, Rn, and Rt; bit 10 (=1) plus the fixed top
	// separates LDRA from LDR/LDAPR/PRFM neighbors. The offset is the
	// signed 10-bit S::imm9 value scaled by 8 (-4096..4088). Only the
	// BASE authenticates; the loaded 64-bit value is raw data and is
	// stored unstripped exactly like hardware X[t] = Mem64(address).
	if ((insn & 0xff200400u) == 0xf8200400u) {
		unsigned rt = insn & 0x1fu;
		uint64_t val;
		addr = munch_pac_ldra_addr(s, insn);
		if (s->load64 == 0) {
			return MUNCH_PAC_FAULT;
		}
		err = 0;
		val = s->load64(addr, s->mem_ctx, &err);
		if (err) {
			return MUNCH_PAC_FAULT; // state untouched
		}
		if (insn & 0x00000800u) { // [Rn, #off]!
			// Pre-indexed: writeback after a successful load
			// only. Rt==Rn is UNPREDICTABLE on hardware; keep
			// the loaded value, which is what the probe and
			// dyld sequences that avoid the alias expect.
			rn = (insn >> 5) & 0x1fu;
			munch_pac_set_reg(s, rt, val);
			if (rn == 31) {
				*s->sp = addr;
			} else if (rt != rn) {
				munch_pac_set_reg(s, rn, addr);
			}
		} else {
			munch_pac_set_reg(s, rt, val);
		}
		*s->pc = cur_pc + 4;
		return MUNCH_PAC_OK;
	}

	// PACGA: 10011010110 Rm 001100 Rn Rd. Recognized so a future
	// generic-hash implementation has a home, but unsupported: its
	// output feeds diversifiers and thread-state hashes, so a fake
	// zero or a no-op copy would corrupt later control flow instead
	// of failing fast. dyld/launchd scan shows PACGA count 0.
	if ((insn & 0xffe0fc00u) == 0x9ac03000u) {
		return MUNCH_PAC_SIGILL;
	}

	// Everything else, including reserved PAC-space encodings and the
	// privileged ERETAA/ERETAB pair, stays a real undefined fault.
	return MUNCH_PAC_UNKNOWN;
}

#endif // MUNCH_PAC_EMU_H
