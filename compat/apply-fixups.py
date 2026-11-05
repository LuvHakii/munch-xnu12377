#!/usr/bin/env python3
"""Unsigned arm64e fixup compatibility for plain-arm64 XNU.

Applied after the pinned dada patch and the existing CI source fix-ups:

    python3 kernel-ci/compat/apply-fixups.py <xnu-root>

Transforms (fail closed: any missing anchor aborts without writing):

1. osfmk/vm/vm_shared_region.c — v3/v5 authenticated rebase entries decode to
   the unsigned target and store it on non-ptrauth builds. The PAC branch
   previously compiled to nothing (no store), silently leaving the encoded
   chain word in place. Delta is read from the raw word before the overwrite,
   high8 applies to non-authenticated entries only. Range checking untouched.
2. osfmk/vm/vm_dyld_pager.c — enable the existing DYLD_CHAINED_PTR_ARM64E (1),
   ARM64E_USERLAND (9), ARM64E_USERLAND24 (12) and ARM64E_SHARED_CACHE (13)
   decoders on non-PAC builds WITHOUT defining HAS_APPLE_PAC globally:
   signPointer gains an #else definition that stores the decoded unsigned
   target (NULL passthrough and non-A-key rejection kept); the two decoder
   bodies and the four switch cases are ungated since their only PAC
   dependency was signPointer. No key material is read; dyld_a_key stays
   absent, pmap signing stays compiled out.

What this deliberately does NOT do: define HAS_APPLE_PAC or ptrauth_calls
anywhere, touch hardware CPU identity (hw.cpusubtype stays arm64 V8),
advertise real PAC, add instruction emulation, bypass exec/code-signing, or
change dada's real-PAC behaviour (the PAC branches are byte-identical).

munch scope notes: iOS 26's shipped cache uses slide version 5; v3 is kept
because the same broken pattern exists there and old caches/tools still
emit it. kern_exec.c needs no change (see the report to the parent).
"""

import re
import sys
from pathlib import Path

SR = "osfmk/vm/vm_shared_region.c"
PAGER = "osfmk/vm/vm_dyld_pager.c"


def fail(msg):
    raise SystemExit("apply-fixups: %s" % msg)


def read_root(path):
    root = Path(path)
    for rel in (SR, PAGER):
        if not (root / rel).is_file():
            fail("%s missing under %s" % (rel, path))
    return root


# ---------------------------------------------------------------------------
# vm_shared_region.c: store decoded unsigned targets for v3/v5 auth entries.
# ---------------------------------------------------------------------------
#
# Both functions share one exact pattern (dada's jop_key==0 behaviour change
# lives inside the guarded block, so the shared anchor covers both variants):
#
#               } else {
#                   memcpy(rebaseLocation, &value, sizeof(value));
#               }
#   #endif /* __has_feature(ptrauth_calls) */
#           } else {
#
# On ptrauth builds the inner else stores the unsigned value when signing is
# disabled and the outer else handles non-authenticated entries. On plain
# arm64 the whole #if body vanishes, so authenticated entries fall through
# with NO store: the encoded chain word (with the next-delta bits) is left in
# the page, the following delta was already consumed from it, and execution
# continues as if the fixup succeeded. Insert an #else that stores the
# already-decoded value. `value` at that point is exactly the unsigned
# target: v3 masks the low 32 bits plus value_add plus slide, v5 masks the
# low 34 bits plus value_add plus slide, matching the PAC path's input to
# pmap_sign_user_ptr.

SR_ANCHOR = (
    "\t\t\t} else {\n"
    "\t\t\t\tmemcpy(rebaseLocation, &value, sizeof(value));\n"
    "\t\t\t}\n"
    "#endif /* __has_feature(ptrauth_calls) */\n"
    "\t\t} else {\n"
)

SR_REPLACEMENT = (
    "\t\t\t} else {\n"
    "\t\t\t\tmemcpy(rebaseLocation, &value, sizeof(value));\n"
    "\t\t\t}\n"
    "#else /* !__has_feature(ptrauth_calls): no PAC hardware; keep the decoded unsigned target. */\n"
    "\t\t\tmemcpy(rebaseLocation, &value, sizeof(value));\n"
    "#endif /* __has_feature(ptrauth_calls) */\n"
    "\t\t} else {\n"
)


def transform_shared_region(text):
    if text.count(SR_ANCHOR) != 2:
        fail("vm_shared_region.c: expected 2 auth-store anchors (v3+v5), found %d"
             % text.count(SR_ANCHOR))
    return text.replace(SR_ANCHOR, SR_REPLACEMENT)


# ---------------------------------------------------------------------------
# vm_dyld_pager.c: reuse the auth decoders without HAS_APPLE_PAC.
# ---------------------------------------------------------------------------
#
# The guarded region spans signPointer + fixupPageAuth64 + fixupCachePageAuth64.
# Inside it the ONLY PAC-gated primitives are inside signPointer's body:
# ptrauth_key constants, arm_user_jop_disabled(), pmap_sign_user_ptr() and
# pager->dyld_a_key. Both fixup functions call signPointer; their own
# ptrauth_key uses are plain integer locals (one cast from bits 49-50, one
# ternary over asia/asda). So the region becomes:
#
#   #if defined(HAS_APPLE_PAC)
#   <original signPointer, verbatim>
#   #else
#   <compat key types + unsigned signPointer + undefs>
#   #endif
#   <compat key types, non-PAC only>
#   <both decoder bodies, byte-identical>
#   <undef compat macros, non-PAC only>
#
# and the four switch cases lose their gate (the callees now always exist).
# The struct dyld_a_key member, its initialiser, and the <ptrauth.h> include
# stay HAS_APPLE_PAC-gated; on real PAC hardware none of the compat code
# compiles in. The compat enum values match <ptrauth.h> (asia=0,asib=1,
# asda=2,asdb=3), the values XNU's `key & 0x3` decoding assumes.

PAGER_REGION_HEAD = (
    "#if defined(HAS_APPLE_PAC)\n"
    "/*\n"
    " * Sign a pointer needed for fixups.\n"
    " */\n"
    "static kern_return_t\n"
    "signPointer(\n"
)

# From the closing brace of fixupCachePageAuth64 through the next banner.
PAGER_REGION_TAIL = (
    "}\n"
    "#endif /* defined(HAS_APPLE_PAC) */\n"
    "\n\n/*\n"
    " * Handle dyld fixups for a page.\n"
    " */\n"
)

HANDLE_BANNER = (
    "\n\n/*\n"
    " * Handle dyld fixups for a page.\n"
    " */\n"
)

PAGER_SWITCH_HEAD = (
    "\tswitch (hdr->mwli_pointer_format) {\n"
    "#if defined(HAS_APPLE_PAC)\n"
)

PAGER_SWITCH_TAIL = (
    "#endif /* defined(HAS_APPLE_PAC) */\n"
    "\tcase DYLD_CHAINED_PTR_64:\n"
)

FIXUPAUTH_BANNER = (
    "/*\n"
    " * Apply fixups to a page used by a 64 bit process using pointer authentication.\n"
    " */\n"
    "static kern_return_t\n"
    "fixupPageAuth64(\n"
)

COMPAT_ELSE_HEAD = (
    "#else /* !defined(HAS_APPLE_PAC): munch compat (apply-fixups). No PAC\n"
    " * hardware; reuse the arm64e decoders with unsigned targets.\n"
    " * HAS_APPLE_PAC stays undefined so no other PAC behaviour changes. */\n"
)

COMPAT_TYPES = (
    "#ifndef DYLD_PAGER_COMPAT_KEY_DEFINED\n"
    "#define DYLD_PAGER_COMPAT_KEY_DEFINED\n"
    "typedef enum { compat_key_asia = 0, compat_key_asib = 1,\n"
    "               compat_key_asda = 2, compat_key_asdb = 3 } compat_ptrauth_key;\n"
    "#endif /* DYLD_PAGER_COMPAT_KEY_DEFINED */\n"
    "#define ptrauth_key compat_ptrauth_key\n"
    "#define ptrauth_key_asia compat_key_asia\n"
    "#define ptrauth_key_asib compat_key_asib\n"
    "#define ptrauth_key_asda compat_key_asda\n"
    "#define ptrauth_key_asdb compat_key_asdb\n"
)

COMPAT_UNDEFS = (
    "#undef ptrauth_key\n#undef ptrauth_key_asia\n#undef ptrauth_key_asib\n"
    "#undef ptrauth_key_asda\n#undef ptrauth_key_asdb\n"
)

UNSIGNED_SIGNPOINTER = """\
static kern_return_t
signPointer(
	uint64_t         unsignedAddr,
	__unused void    *loc,
	__unused bool    addrDiv,
	__unused uint16_t diversity,
	ptrauth_key      key,
	__unused dyld_pager_t pager,
	uint64_t         *signedAddr)
{
	// don't sign NULL
	if (unsignedAddr == 0) {
		*signedAddr = 0;
		return KERN_SUCCESS;
	}

	/* munch compat (apply-fixups): no key material exists on this CPU;
	 * store the decoded unsigned target. Only A keys are valid for the
	 * supported IA/DA formats; anything else is malformed input. */
	switch (key) {
	case ptrauth_key_asia:
	case ptrauth_key_asda:
		*signedAddr = unsignedAddr;
		break;

	default:
		ktriage_record(thread_tid(current_thread()), KDBG_TRIAGE_EVENTID(KDBG_TRIAGE_SUBSYS_DYLD_PAGER, KDBG_TRIAGE_RESERVED, KDBG_TRIAGE_DYLD_PAGER_INVALID_AUTH_KEY), (uintptr_t)unsignedAddr);
		printf("%s(): Invalid ptr auth key %d\\n", __func__, key);
		if (panic_on_dyld_issue) {
			panic("%s(): Invalid ptr auth key %d", __func__, key);
		}
		return KERN_FAILURE;
	}
	return KERN_SUCCESS;
}
"""


def transform_pager(text):
    for anchor, what in ((PAGER_REGION_HEAD, "signPointer region head"),
                         (PAGER_REGION_TAIL, "auth region tail"),
                         (PAGER_SWITCH_HEAD, "fixup switch head"),
                         (PAGER_SWITCH_TAIL, "fixup switch tail")):
        if text.count(anchor) != 1:
            fail("vm_dyld_pager.c: %s not found exactly once" % what)

    # The switch region must enable exactly the four arm64e formats, so the
    # ungating cannot smuggle in anything else.
    sw = text.split(PAGER_SWITCH_HEAD, 1)[1].split(PAGER_SWITCH_TAIL, 1)[0]
    for fmt in ("DYLD_CHAINED_PTR_ARM64E:",
                "DYLD_CHAINED_PTR_ARM64E_USERLAND:",
                "DYLD_CHAINED_PTR_ARM64E_USERLAND24:",
                "DYLD_CHAINED_PTR_ARM64E_SHARED_CACHE:"):
        if ("case %s" % fmt) not in sw:
            fail("vm_dyld_pager.c: switch region lost format %s" % fmt)
    if len(re.findall(r"^\tcase ", sw, re.M)) != 4:
        fail("vm_dyld_pager.c: switch region has unexpected case lines")

    # Split the auth region into signPointer | decoders, keeping the decoder
    # bodies byte-identical. Fail closed if any PAC-gated primitive other
    # than signPointer's own is present in the decoder half.
    head, rest = text.split(PAGER_REGION_HEAD, 1)
    region, tail = rest.split(PAGER_REGION_TAIL, 1)
    if region.count(FIXUPAUTH_BANNER) != 1:
        fail("vm_dyld_pager.c: fixupPageAuth64 banner not found exactly once")
    orig_sign, decoders = region.split(FIXUPAUTH_BANNER, 1)
    if not orig_sign.startswith("\tuint64_t         unsignedAddr,\n"):
        fail("vm_dyld_pager.c: unexpected signPointer signature")
    if not orig_sign.endswith("}\n\n"):
        fail("vm_dyld_pager.c: unexpected signPointer ending")
    if "pmap_sign_user_ptr" not in orig_sign or "dyld_a_key" not in orig_sign:
        fail("vm_dyld_pager.c: original signPointer lost its PAC body")
    for token in ("pmap_sign_user_ptr", "pmap_auth_user_ptr", "dyld_a_key",
                  "arm_user_jop_disabled", "ptrauth_blend",
                  "__builtin_ptrauth", "ptrauth_sign", "ptrauth_auth",
                  "ptrauth_strip"):
        if token in decoders:
            fail("vm_dyld_pager.c: decoder half uses PAC primitive %s" % token)
    if "fixupCachePageAuth64(" not in decoders:
        fail("vm_dyld_pager.c: fixupCachePageAuth64 missing from decoder half")
    if "signPointer(" not in decoders:
        fail("vm_dyld_pager.c: decoders no longer call signPointer")

    sign_head = PAGER_REGION_HEAD.split("#if defined(HAS_APPLE_PAC)\n", 1)[1]
    new_region = ("#if defined(HAS_APPLE_PAC)\n" + sign_head + orig_sign
                  + COMPAT_ELSE_HEAD + COMPAT_TYPES + UNSIGNED_SIGNPOINTER
                  + COMPAT_UNDEFS
                  + "#endif /* defined(HAS_APPLE_PAC) */\n"
                  + "#if !defined(HAS_APPLE_PAC)\n" + COMPAT_TYPES
                  + "#endif /* !defined(HAS_APPLE_PAC) */\n"
                  + FIXUPAUTH_BANNER + decoders + "}\n"
                  + "#if !defined(HAS_APPLE_PAC)\n" + COMPAT_UNDEFS
                  + "#undef DYLD_PAGER_COMPAT_KEY_DEFINED\n"
                  + "#endif /* !defined(HAS_APPLE_PAC) */\n")
    text = head + new_region + HANDLE_BANNER + tail

    # Ungate the four cases; the callees now always exist.
    text = text.replace(PAGER_SWITCH_HEAD,
                        "\tswitch (hdr->mwli_pointer_format) {\n", 1)
    text = text.replace(PAGER_SWITCH_TAIL, "\tcase DYLD_CHAINED_PTR_64:\n", 1)
    return text


def main(argv):
    if len(argv) != 2:
        fail("usage: apply-fixups.py <xnu-root>")
    root = read_root(argv[1])

    sr_path = root / SR
    sr_new = transform_shared_region(sr_path.read_text())

    pager_path = root / PAGER
    pager_new = transform_pager(pager_path.read_text())

    # Both transforms verified before either file is touched.
    sr_path.write_text(sr_new)
    pager_path.write_text(pager_new)
    print("apply-fixups: %s, %s" % (SR, PAGER))


if __name__ == "__main__":
    main(sys.argv)
