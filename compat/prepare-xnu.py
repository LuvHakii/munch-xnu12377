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


# The 24B156 dynamic data ends at 0x30ffd8000 before its 0x20000000 maximum
# slide. Round that end up to a 32 MiB pmap nesting boundary and keep the base.
edit('osfmk/mach/shared_region.h', lambda s: re.sub(
    r'^(#define SHARED_REGION_SIZE_ARM64[ \t]+)0x180000000ULL$',
    r'\g<1>0x1B0000000ULL', s, flags=re.MULTILINE))


# 24B156 reads a four-byte state through a caller-checked sysctl before launching services.
def public_lockdown_state(s):
    anchor = '#include <sys/lockdown_mode.h>'
    assert s.count(anchor) == 1 and 'lockdown_mode_state_public' not in s
    s = s.replace(anchor, anchor + '''
#include <sys/codesign.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <IOKit/IOBSD.h>''')
    return s + '''
static int
sysctl_lockdown_mode_state_public SYSCTL_HANDLER_ARGS
{
	if (!csproc_get_platform_binary(current_proc()) &&
	    !IOCurrentTaskHasEntitlement("com.apple.developer.lockdown-mode.state")) {
		return EPERM;
	}
	int state = get_lockdown_mode_state();
	return SYSCTL_OUT(req, &state, sizeof(state));
}

SYSCTL_PROC(_security_mac, OID_AUTO, lockdown_mode_state_public,
    CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED, 0, 0,
    sysctl_lockdown_mode_state_public, "I", "Lockdown Mode state for authorized callers");
'''


edit('bsd/kern/lockdown_mode.c', public_lockdown_state)


def register_watchdog_sample(s):
    anchor = 'osfmk/arm64/loader_return.c\toptional nos_arm_asm\n'
    assert s.count(anchor) == 1
    return s.replace(anchor, anchor + 'osfmk/arm64/munch_watchdog_sample.c\toptional nos_arm_asm\n')


edit('osfmk/conf/files.arm64', register_watchdog_sample)


# 24B156 libsystem_kernel stores crash_count at 0xb4, kqworkloop limits at 0xbc and the conclave
# limit at 0xc4; 23G90 (this kernel's layout) uses 0xac, 0xb4 and 0xbc. Unshifted, the kernel took
# launchd's crash count and throttle timeout as kqworkloop limits and daemons killed themselves.
def spawnattr_24b156(s):
    anchor = '\tuint16_t        psa_sec_flags;           /* flags for task_sec */\n'
    assert s.count(anchor) == 1
    return s.replace(anchor, anchor + '\tuint32_t        psa_24b156_ac;           /* set_task_security_policy_np */\n'
                     '\tuint8_t         psa_24b156_b0;           /* set_use_sanitizers_np */\n')


edit('bsd/sys/spawn_internal.h', spawnattr_24b156)
(root / 'osfmk/arm64/munch_watchdog_sample.c').write_bytes(
    Path(__file__).with_name('munch_watchdog_sample.c').read_bytes())


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
