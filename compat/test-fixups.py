#!/usr/bin/env python3
"""Behavioral check for apply-fixups.py output.

Extracts the transformed v3/v5 shared-cache sliders and the arm64e dyld-pager
fixup decoders from <xnu-root>, compiles them into a host harness and runs
behavioral checks (decoded targets, bind bounds, key validation, malformed
chains). No source-text assertions: every check executes the code.

    python3 kernel-ci/compat/test-fixups.py <xnu-root>

Requires clang (the extracted code uses __has_feature, as in the kernel
build). Exit 0 with FIXUP_TEST_PASS on success; anything else fails.
"""

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SR = "osfmk/vm/vm_shared_region.c"
PAGER = "osfmk/vm/vm_dyld_pager.c"

START_ANCHOR = ("/*\n"
                " * Apply fixups to a page used by a 64 bit process using pointer authentication.\n"
                " */\n"
                "static kern_return_t\n"
                "fixupPageAuth64(\n")


def fail(msg):
    raise SystemExit("test-fixups: %s" % msg)


def extract_func(text, anchor, name):
    i = text.find(anchor)
    if i < 0 or text.find(anchor, i + 1) >= 0:
        fail("%s anchor not unique/found: %r" % (name, anchor))
    j = text.find("{", i)
    if j < 0:
        fail("%s has no body" % name)
    k = match_brace(text, j)
    return text[i:k]


def match_brace(text, open_idx):
    """Index just past the brace matching text[open_idx], skipping comments,
    strings and char literals."""
    i = open_idx
    n = len(text)
    depth = 0
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i + 2)
            i = n if j < 0 else j + 1
            continue
        if c == "/" and nxt == "*":
            j = text.find("*/", i + 2)
            if j < 0:
                fail("unterminated block comment in extraction")
            i = j + 2
            continue
        if c in "\"'":
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == c:
                    i += 1
                    break
                if text[i] == "\n" and c == "'":
                    fail("newline in char literal during extraction")
                i += 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    fail("unbalanced braces in extraction")


def strip_comments(text):
    """Comment-free copy with identical length/offsets (for #if scanning)."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            end = n if j < 0 else j
            for k in range(i, end):
                out[k] = " "
            i = end
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                fail("unterminated block comment in directive scan")
            for k in range(i, j + 2):
                if out[k] != "\n":
                    out[k] = " "
            i = j + 2
        else:
            i += 1
    return "".join(out)


def extract_sign_block(text):
    """The #if/#else/#endif signPointer group (Apple + compat definitions),
    letting the host preprocessor select the compat branch."""
    first = text.find("static kern_return_t\nsignPointer(")
    if first < 0:
        fail("signPointer not found")
    gate = text.rfind("#if defined(HAS_APPLE_PAC)", 0, first)
    if gate < 0:
        fail("signPointer HAS_APPLE_PAC gate not found")
    bare = strip_comments(text)
    depth = 0
    pos = gate
    while True:
        nl = bare.find("\n", pos)
        line = bare[pos:nl if nl >= 0 else len(bare)]
        s = line.strip()
        if s.startswith("#if"):
            depth += 1
        elif s.startswith("#endif"):
            depth -= 1
            if depth == 0:
                end = len(text) if nl < 0 else nl + 1
                block = text[gate:end]
                if block.count("static kern_return_t\nsignPointer(") != 2:
                    fail("signPointer block does not hold both definitions")
                return block
        pos = len(bare) if nl < 0 else nl + 1
        if pos >= len(bare):
            fail("signPointer gate never closes")


def extract_compat_types(text):
    """The compat key typedef/macros emitted just before the decoders."""
    b = text.find(START_ANCHOR)
    if b < 0:
        fail("fixupPageAuth64 banner not found")
    g = text.rfind("#if !defined(HAS_APPLE_PAC)", 0, b)
    e = text.find("#endif /* !defined(HAS_APPLE_PAC) */", g)
    if not (0 <= g < e < b):
        fail("compat types block not found before decoders")
    nl = text.find("\n", e)
    block = text[g:nl + 1]
    if "compat_ptrauth_key" not in block or "#define ptrauth_key " not in block:
        fail("compat types block incomplete")
    return block


def extract_decoders(text):
    end_anchor = "#if !defined(HAS_APPLE_PAC)\n#undef ptrauth_key\n"
    if text.count(START_ANCHOR) != 1:
        fail("fixupPageAuth64 banner not unique/found")
    if text.count(end_anchor) != 1:
        fail("compat undef anchor not unique/found")
    chunk = text.split(START_ANCHOR, 1)[1].split(end_anchor, 1)[0]
    if "fixupCachePageAuth64(" not in chunk or "signPointer(" not in chunk:
        fail("decoder chunk incomplete")
    return START_ANCHOR + chunk


PROLOGUE = r"""
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define __unused __attribute__((unused))
#define __nonnull
#define CONFIG_SPTM 0
typedef uintptr_t vm_offset_t;
typedef uint64_t mach_vm_offset_t;
typedef int kern_return_t;
#define KERN_SUCCESS 0
#define KERN_FAILURE 5
#define PAGE_SHIFT 12
#define PAGE_MASK 0xfff
#define PAGE_SIZE 4096
#define current_thread() (0)
static inline int thread_tid(int t) { return t; }
#define ktriage_record(...) ((void)0)
#define panic(...) do { fprintf(stderr, "panic in test\n"); abort(); } while (0)
int panic_on_dyld_issue = 0;
#if defined(__arm64__) && !defined(SPECULATION_GUARD_ZEROING_XXX)
#define SPECULATION_GUARD_ZEROING_XXX(out, out_valid, value, cmp1, cmp2, cc) \
    do { (out) = ((cmp1) == (cmp2) ? (value) : 0); (out_valid) = true; } while (0)
#endif

/* Layouts copied from the kernel headers (field offsets must match). */
struct mwl_info_hdr {
    uint32_t mwli_version;
    uint16_t mwli_page_size;
    uint16_t mwli_pointer_format;
    uint32_t mwli_binds_offset;
    uint32_t mwli_binds_count;
    uint32_t mwli_chains_offset;
    uint32_t mwli_chains_size;
    uint64_t mwli_slide;
    uint64_t mwli_image_address;
};
struct dyld_chained_starts_in_image {
    uint32_t seg_count;
    uint32_t seg_info_offset[1];
};
struct dyld_chained_starts_in_segment {
    uint32_t size;
    uint16_t page_size;
    uint16_t pointer_format;
    uint64_t segment_offset;
    uint32_t max_valid_pointer;
    uint16_t page_count;
    uint16_t page_start[4];
};
#define DYLD_CHAINED_PTR_START_NONE 0xFFFF
struct dyld_pager { void *dyld_link_info; uint32_t dyld_link_info_size; };
typedef struct dyld_pager *dyld_pager_t;

struct slide_v3 { uint32_t version; uint32_t page_size; uint32_t page_starts_count;
    uint64_t value_add; uint16_t page_starts[8]; };
struct slide_v5 { uint32_t version; uint32_t page_size; uint32_t page_starts_count;
    uint64_t value_add; uint16_t page_starts[8]; };
union slide_entry { struct { uint32_t version; uint32_t page_size; };
    struct slide_v3 v3; struct slide_v5 v5; };
typedef union slide_entry *vm_shared_region_slide_info_entry_t;
typedef struct slide_v3 *vm_shared_region_slide_info_entry_v3_t;
typedef struct slide_v5 *vm_shared_region_slide_info_entry_v5_t;
struct sr_si { uint32_t si_slide; vm_shared_region_slide_info_entry_t si_slide_info_entry; };
typedef struct sr_si *vm_shared_region_slide_info_t;
#define DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE 0xFFFF
#define DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE 0xFFFF

"""

TESTS = r"""
static int failures = 0;
static int checks = 0;
#define CHECK(cond, msg) do { checks++; \
    if (cond) { printf("ok: %s\n", msg); } \
    else { printf("FAIL: %s (line %d)\n", msg, __LINE__); failures++; } } while (0)

static uint64_t load64(void *p) { uint64_t v; memcpy(&v, p, 8); return v; }
static void store64(void *p, uint64_t v) { memcpy(p, &v, 8); }

/* --- shared cache sliders --- */

static void test_v5_auth_single(void) {
    static uint8_t page[256];
    memset(page, 0, sizeof page);
    store64(page, 0x8000000000000088ULL); /* auth, next=0, runtimeOffset 0x88 */
    union slide_entry e;
    memset(&e, 0, sizeof e);
    e.v5.version = 5; e.v5.page_size = 16384; e.v5.page_starts_count = 1;
    e.v5.value_add = 0x180000000ULL; e.v5.page_starts[0] = 0;
    struct sr_si si; si.si_slide = 0x1000; si.si_slide_info_entry = &e;
    kern_return_t kr = vm_shared_region_slide_page_v5(&si, (vm_offset_t)page, 0x700000000ULL, 0, 0);
    CHECK(kr == KERN_SUCCESS, "v5 auth returns success");
    CHECK(load64(page) == 0x88ULL + 0x180000000ULL + 0x1000, "v5 auth stores decoded unsigned target");
}

static void test_v5_chain_high8(void) {
    static uint8_t page[256];
    memset(page, 0, sizeof page);
    /* entry 0: auth, next=1 (delta 8); entry 1: non-auth with high8 0xAB. */
    store64(page, 0x8000000000000000ULL | (1ULL << 52) | 0x100);
    store64(page + 8, (0xABULL << 34) | 0x200);
    union slide_entry e;
    memset(&e, 0, sizeof e);
    e.v5.version = 5; e.v5.page_size = 16384; e.v5.page_starts_count = 1;
    e.v5.value_add = 0x180000000ULL; e.v5.page_starts[0] = 0;
    struct sr_si si; si.si_slide = 0x1000; si.si_slide_info_entry = &e;
    kern_return_t kr = vm_shared_region_slide_page_v5(&si, (vm_offset_t)page, 0x700000000ULL, 0, 0);
    CHECK(kr == KERN_SUCCESS, "v5 two-entry chain returns success");
    CHECK(load64(page) == 0x100ULL + 0x180000000ULL + 0x1000, "v5 chain head decoded (delta preserved)");
    CHECK(load64(page + 8) == 0xAB00000000000000ULL + 0x200 + 0x180000000ULL + 0x1000,
        "v5 non-auth keeps high8");
}

static void test_v3_auth(void) {
    static uint8_t page[256];
    memset(page, 0, sizeof page);
    store64(page, 0x8000000000001234ULL); /* auth, next=0, low32 0x1234 */
    union slide_entry e;
    memset(&e, 0, sizeof e);
    e.v3.version = 3; e.v3.page_size = 4096; e.v3.page_starts_count = 1;
    e.v3.value_add = 0x140000000ULL; e.v3.page_starts[0] = 0;
    struct sr_si si; si.si_slide = 0x2000; si.si_slide_info_entry = &e;
    kern_return_t kr = vm_shared_region_slide_page_v3(&si, (vm_offset_t)page, 0x700000000ULL, 0, 0);
    CHECK(kr == KERN_SUCCESS, "v3 auth returns success");
    CHECK(load64(page) == 0x1234ULL + 0x2000 + 0x140000000ULL, "v3 auth stores decoded unsigned target");
}

static void test_v3_nonauth_bind(void) {
    static uint8_t page[256];
    union slide_entry e;
    struct sr_si si;
    memset(&e, 0, sizeof e);
    e.v3.version = 3; e.v3.page_size = 4096; e.v3.page_starts_count = 1;
    e.v3.value_add = 0; e.v3.page_starts[0] = 0;
    si.si_slide = 0x2000; si.si_slide_info_entry = &e;
    /* top8 = bits 43..50 all set, bottom43 = 0x1ff, next/bind/auth clear. */
    memset(page, 0, sizeof page);
    store64(page, 0x0007F80000000000ULL | 0x1ff);
    kern_return_t kr = vm_shared_region_slide_page_v3(&si, (vm_offset_t)page, 0, 0, 0);
    CHECK(kr == KERN_SUCCESS, "v3 non-auth returns success");
    CHECK(load64(page) == 0xFF00000000000000ULL + 0x1ff + 0x2000, "v3 non-auth top8/bottom43 decode");
    /* bind entries in v3 slide data are rejected, as before. */
    memset(page, 0, sizeof page);
    store64(page, 1ULL << 62);
    kr = vm_shared_region_slide_page_v3(&si, (vm_offset_t)page, 0, 0, 0);
    CHECK(kr != KERN_SUCCESS, "v3 bind still fails");
}

/* --- dyld pager decoders --- */

struct pager_fixture {
    uint8_t blob[256];
    struct dyld_pager pager;
    struct dyld_chained_starts_in_segment *seg;
    uint8_t *page;
};

static void pager_init(struct pager_fixture *f, uint64_t bind0, uint64_t bind1) {
    memset(f->blob, 0, sizeof f->blob);
    struct mwl_info_hdr hdr;
    memset(&hdr, 0, sizeof hdr);
    hdr.mwli_version = 7;
    hdr.mwli_page_size = 4096;
    hdr.mwli_pointer_format = 1;
    hdr.mwli_binds_offset = sizeof hdr;
    hdr.mwli_binds_count = 2;
    hdr.mwli_chains_offset = sizeof hdr + 16;
    hdr.mwli_chains_size = 8 + 24;
    hdr.mwli_slide = 0x3000;
    hdr.mwli_image_address = 0x100000000ULL;
    memcpy(f->blob, &hdr, sizeof hdr);
    store64(f->blob + sizeof hdr, bind0);
    store64(f->blob + sizeof hdr + 8, bind1);
    struct dyld_chained_starts_in_image *img = (void *)(f->blob + hdr.mwli_chains_offset);
    img->seg_count = 1;
    img->seg_info_offset[0] = 8;
    struct dyld_chained_starts_in_segment *seg = (void *)(f->blob + hdr.mwli_chains_offset + 8);
    seg->size = 24; seg->page_size = 4096; seg->pointer_format = 1;
    seg->segment_offset = 0; seg->max_valid_pointer = 0;
    seg->page_count = 1; seg->page_start[0] = 0;
    f->seg = seg;
    f->pager.dyld_link_info = f->blob;
    f->pager.dyld_link_info_size = hdr.mwli_chains_offset + hdr.mwli_chains_size;
    if (posix_memalign((void **)&f->page, 4096, 4096) != 0) { fprintf(stderr, "memalign failed\n"); abort(); }
    memset(f->page, 0, 4096);
}

static void test_pager_auth(void) {
    struct pager_fixture f;
    kern_return_t kr;
    pager_init(&f, 0x200000000ULL, 0);
    /* auth rebase: key IA(0), target low32 0x1000 -> image_address + 0x1000. */
    store64(f.page, 0x8000000000001000ULL);
    kr = fixupPageAuth64(0x100000000ULL, (vm_offset_t)f.page, &f.pager, f.seg, 0, false);
    CHECK(kr == KERN_SUCCESS, "pager auth rebase returns success");
    CHECK(load64(f.page) == 0x100001000ULL, "pager auth rebase stores unsigned target");
    /* auth bind ordinal 0. */
    memset(f.page, 0, 4096);
    store64(f.page, 0xC000000000000000ULL);
    kr = fixupPageAuth64(0x100000000ULL, (vm_offset_t)f.page, &f.pager, f.seg, 0, false);
    CHECK(kr == KERN_SUCCESS, "pager auth bind returns success");
    CHECK(load64(f.page) == 0x200000000ULL, "pager auth bind stores unsigned bind target");
    /* auth bind of NULL stays NULL. */
    memset(f.page, 0, 4096);
    store64(f.page, 0xC000000000000001ULL);
    kr = fixupPageAuth64(0x100000000ULL, (vm_offset_t)f.page, &f.pager, f.seg, 0, false);
    CHECK(kr == KERN_SUCCESS, "pager NULL bind returns success");
    CHECK(load64(f.page) == 0, "pager NULL bind stays NULL");
    /* out-of-range bind ordinal fails. */
    memset(f.page, 0, 4096);
    store64(f.page, 0xC000000000000002ULL);
    kr = fixupPageAuth64(0x100000000ULL, (vm_offset_t)f.page, &f.pager, f.seg, 0, false);
    CHECK(kr != KERN_SUCCESS, "pager out-of-range bind fails");
    /* B key (asib=1) is rejected. */
    memset(f.page, 0, 4096);
    store64(f.page, 0x8000000000001000ULL | (1ULL << 49));
    kr = fixupPageAuth64(0x100000000ULL, (vm_offset_t)f.page, &f.pager, f.seg, 0, false);
    CHECK(kr != KERN_SUCCESS, "pager non-A key fails");
    free(f.page);
}

static void test_pager_nonauth(void) {
    struct pager_fixture f;
    pager_init(&f, 0, 0);
    /* non-auth rebase, high8 0xCD, target 0x5000, slide-relative. */
    store64(f.page, (0xCDULL << 43) | 0x5000);
    kern_return_t kr = fixupPageAuth64(0x100000000ULL, (vm_offset_t)f.page, &f.pager, f.seg, 0, false);
    CHECK(kr == KERN_SUCCESS, "pager non-auth rebase returns success");
    CHECK(load64(f.page) == 0xCD00000000000000ULL + 0x5000 + 0x3000, "pager non-auth keeps high8 + slide");
    /* offset-based variant adds the image address instead. */
    memset(f.page, 0, 4096);
    store64(f.page, (0xCDULL << 43) | 0x5000);
    kr = fixupPageAuth64(0x100000000ULL, (vm_offset_t)f.page, &f.pager, f.seg, 0, true);
    CHECK(kr == KERN_SUCCESS, "pager offset-based rebase returns success");
    CHECK(load64(f.page) == 0xCD00000000000000ULL + 0x5000 + 0x100000000ULL,
        "pager offset-based adds image address");
    free(f.page);
}

static void test_pager_malformed(void) {
    struct pager_fixture f;
    pager_init(&f, 0, 0);
    /* start offset past the page end fails. */
    f.seg->page_start[0] = 4096;
    kern_return_t kr = fixupPageAuth64(0x100000000ULL, (vm_offset_t)f.page, &f.pager, f.seg, 0, false);
    CHECK(kr != KERN_SUCCESS, "pager out-of-range chain start fails");
    /* unterminated chain: last slot points past the page end. */
    f.seg->page_start[0] = 4088;
    store64(f.page + 4088, (1ULL << 51) | 0x5000);
    kr = fixupPageAuth64(0x100000000ULL, (vm_offset_t)f.page, &f.pager, f.seg, 0, false);
    CHECK(kr != KERN_SUCCESS, "pager cross-page chain fails");
    free(f.page);
}

static void test_pager_cache(void) {
    struct pager_fixture f;
    pager_init(&f, 0, 0);
    /* format-13 auth rebase, IA. */
    store64(f.page, 0x8000000000000088ULL);
    kern_return_t kr = fixupCachePageAuth64(0x100000000ULL, (vm_offset_t)f.page, &f.pager, f.seg, 0);
    CHECK(kr == KERN_SUCCESS, "pager cache auth rebase returns success");
    CHECK(load64(f.page) == 0x88ULL + 0x100000000ULL, "pager cache auth stores unsigned target");
    /* format-13 auth rebase, DA. */
    memset(f.page, 0, 4096);
    store64(f.page, 0x8000000000000088ULL | (1ULL << 51));
    kr = fixupCachePageAuth64(0x100000000ULL, (vm_offset_t)f.page, &f.pager, f.seg, 0);
    CHECK(kr == KERN_SUCCESS, "pager cache DA rebase returns success");
    CHECK(load64(f.page) == 0x88ULL + 0x100000000ULL, "pager cache DA stores unsigned target");
    /* format-13 non-auth with high8. */
    memset(f.page, 0, 4096);
    store64(f.page, (0xABULL << 34) | 0x200);
    kr = fixupCachePageAuth64(0x100000000ULL, (vm_offset_t)f.page, &f.pager, f.seg, 0);
    CHECK(kr == KERN_SUCCESS, "pager cache non-auth returns success");
    CHECK(load64(f.page) == 0xAB00000000000000ULL + 0x200 + 0x100000000ULL,
        "pager cache non-auth keeps high8");
    free(f.page);
}

int main(void) {
    test_v5_auth_single();
    test_v5_chain_high8();
    test_v3_auth();
    test_v3_nonauth_bind();
    test_pager_auth();
    test_pager_nonauth();
    test_pager_malformed();
    test_pager_cache();
    printf("checks=%d failures=%d\n", checks, failures);
    if (failures == 0) {
        printf("FIXUP_TEST_PASS\n");
        return 0;
    }
    return 1;
}
"""


def main(argv):
    if len(argv) != 2:
        fail("usage: test-fixups.py <xnu-root>")
    root = Path(argv[1])
    sr_text = (root / SR).read_text()
    pager_text = (root / PAGER).read_text()

    v3 = extract_func(sr_text, "static kern_return_t\nvm_shared_region_slide_page_v3(", "v3 slider")
    v5 = extract_func(sr_text, "static kern_return_t\nvm_shared_region_slide_page_v5(", "v5 slider")
    delta = extract_func(pager_text, "static inline bool\n_delta_ptr_within_page_nospec(", "delta guard")
    sign = extract_sign_block(pager_text)
    compat_types = extract_compat_types(pager_text)
    decoders = extract_decoders(pager_text)

    clang = shutil.which("clang")
    if clang is None:
        fail("clang not found in PATH (needed for __has_feature)")

    with tempfile.TemporaryDirectory(prefix="fixup-test-") as tmp:
        src = Path(tmp) / "fixup-test.c"
        exe = Path(tmp) / "fixup-test"
        src.write_text(PROLOGUE + delta + "\n" + sign + "\n" + compat_types
                       + "\n" + decoders + "\n" + v3 + "\n" + v5 + "\n" + TESTS)
        cc = subprocess.run([clang, "-O1", "-o", str(exe), str(src)],
                            capture_output=True, text=True)
        if cc.returncode != 0:
            print(cc.stdout)
            print(cc.stderr, file=sys.stderr)
            fail("host compile failed")
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        print(run.stdout, end="")
        if run.stderr:
            print(run.stderr, file=sys.stderr, end="")
        if run.returncode != 0 or "FIXUP_TEST_PASS" not in run.stdout:
            fail("behavioral checks failed")
    print("test-fixups: PASS")


if __name__ == "__main__":
    main(sys.argv)
