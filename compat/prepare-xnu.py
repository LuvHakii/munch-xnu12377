#!/usr/bin/env python3
"""Apply the munch build fixes after the pinned HakiOS XNU patch."""
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])


def edit(path, fn):
    p = root / path
    s = p.read_text()
    n = fn(s)
    assert n != s, f'{path}: nothing changed'
    p.write_text(n)
    print('patched', path)


# This driver is not used on munch; do not download redwood touchscreen firmware.
(root / 'bsd/dev/redwood_focaltech_fw.h').write_text('''\
#ifndef REDWOOD_FOCALTECH_FW_H
#define REDWOOD_FOCALTECH_FW_H
#include <stdint.h>
#define FOCALTECH_FW_LENGTH 0u
static const uint8_t focaltech_fw[1] = { 0 };
#endif
''')
# Linux's compiler adapter defines this for its conservative type builtins.
if sys.platform == 'darwin':
    edit('libkern/libkern/c++/OSData.h', lambda s: s.replace('XNU_NO_TYPE_BUILTINS || ', ''))
else:
    # Upstream clang has no Apple SME switch; the arm64 target does not enable SME.
    edit('makedefs/MakeInc.def', lambda s: s.replace(' -mno-implicit-sme', ''))
# ccache cannot cache -MJ compiles; without them the JSON aggregation also fails.
edit('makedefs/MakeInc.rule', lambda s: s.replace(' -MJ $(@:o=o.json)', ''))
edit('makedefs/MakeInc.kernel', lambda s: s.replace('do_build_all:: do_build_compile_commands_json\n', ''))


def arm_init(s):
    head = 'hk_ib_probe(struct hk_ibprobe *r)\n{\n'
    i = s.index(head) + len(head)
    j = s.index('\n}\n', i)
    zero = 'r->before = r->after = r->reg_before = r->reg_after = r->cpacr = r->ttbr = 0;'
    return s[:i] + '#if defined(__arm64e__)\n' + s[i:j] + '\n#else\n\t' + zero + '\n#endif' + s[j:]


# These diagnostics otherwise assemble PAC key-register reads for a non-PAC CPU.
edit('osfmk/arm/arm_init.c', arm_init)


def sleh(s):
    a = '\t\t\t__asm__ volatile ("mrs %0, APIAKeyLo_EL1" : "=r" (ia));\n'
    b = '\t\t\t__asm__ volatile ("mrs %0, APGAKeyLo_EL1" : "=r" (ga));\n'
    assert s.count(a + b) == 1
    return s.replace(a + b, '#if defined(__arm64e__)\n' + a + b + '#else\n\t\t\tia = ga = 0;\n#endif\n')


edit('osfmk/arm64/sleh.c', sleh)


def start(s):
    m = re.search(r'\t// hakios DIAGNOSTIC \(checkpoint 9\).*?\n1:\n', s, re.S)
    assert m and s.count('hakios DIAGNOSTIC (checkpoint 9)') == 1
    return s[:m.start()] + '#if defined(__arm64e__)\n' + m.group(0) + '#endif\n' + s[m.end():]


edit('osfmk/arm64/start.s', start)


def ufs(s):
    # GPT entry 36; the write floor is 16 GiB, after all three iOS 26 containers.
    changes = {
        '#define UFS_DARWIN_FIRST   25374720ULL': '#define UFS_DARWIN_FIRST   45102848ULL',
        '#define UFS_DARWIN_BLOCKS  5242875ULL': '#define UFS_DARWIN_BLOCKS  16777216ULL',
        '#define UFS_WRITE_FIRST    2042368ULL': '#define UFS_WRITE_FIRST    4194304ULL',
    }
    for a, b in changes.items():
        assert s.count(a) == 1
        s = s.replace(a, b)
    return s


edit('bsd/dev/redwood_ufs.c', ufs)


def exclaves(s):
    # The KDK Tightbeam library has no plain-arm64 slice; munch has no exclaves.
    a = '#if __has_include(<Tightbeam/tightbeam.h>)\n\n#include <Tightbeam/tightbeam.h>'
    assert s.count(a) == 1
    return s.replace(a, '#if __has_include(<Tightbeam/tightbeam.h>) && defined(__arm64e__)\n\n#include <Tightbeam/tightbeam.h>')


edit('osfmk/kern/exclaves.c', exclaves)


def files(s):
    a = 'bsd/dev/hakios_dada_wlan.c\tstandard\n'
    assert s.count(a) == 1
    return s.replace(a, a + 'bsd/dev/munch_nw_stubs.c\tstandard\n')


edit('bsd/conf/files', files)
# Dada's ath12k object is not linked here; fail its entry points with ENODEV.
(root / 'bsd/dev/munch_nw_stubs.c').write_text('''\
#include <stdint.h>
#include <stddef.h>
uint64_t nw_wifi_stats[512] __attribute__((aligned(16)));
volatile uint64_t nw_wifi_where[4];
int nw_wifi_start(const void *p, const void *b) { (void)p; (void)b; return -19; }
int nw_wifi_step(void) { return -19; }
void nw_wifi_stop(void) { }
int nw_wifi_scan(const uint8_t *ssid, size_t len) { (void)ssid; (void)len; return -19; }
int nw_wifi_bss_count(void) { return 0; }
int nw_wifi_bss_get(unsigned i, void *out) { (void)i; (void)out; return -19; }
int nw_wifi_connect(const void *a, size_t b, const void *c, size_t d) { (void)a; (void)b; (void)c; (void)d; return -19; }
int nw_wifi_disconnect(void) { return -19; }
int nw_wifi_set_events(void *fn) { (void)fn; return -19; }
int nw_wifi_status_get(void *out) { (void)out; return -19; }
int nw_wifi_tx(const void *frame, size_t len) { (void)frame; (void)len; return -19; }
''')
