#!/bin/bash
set -euo pipefail
HERE=$(cd -- "$(dirname -- "$0")" && pwd)
PROJECT=$(cd -- "$HERE/../.." && pwd)
OUT=${1:-"$PROJECT/out/pac-compat"}
LD=${LD64:-"$PROJECT/theos/toolchain/linux/iphone/bin/ld"}
LDID=${LDID:-"$PROJECT/theos/toolchain/linux/iphone/bin/ldid"}
mkdir -p -- "$OUT"
"${CLANG:-clang}" -target arm64e-apple-ios16.5 -c "$HERE/probe.S" -o "$OUT/probe.o"
"$LD" -arch arm64e -static -e _start -ios_version_min 16.5 -o "$OUT/probe" "$OUT/probe.o"
"$LDID" -S "$OUT/probe"
python3 - "$OUT/probe" <<'PY'
import pathlib
import struct
import sys
p = pathlib.Path(sys.argv[1])
b = p.read_bytes()
magic, cpu, subtype, kind, commands, command_bytes, _, _ = struct.unpack_from('<8I', b)
assert magic == 0xfeedfacf and cpu == 0x100000c
assert subtype & 0xffffff == 2, hex(subtype)
assert kind == 2
position = 32
entry = None
for _ in range(commands):
    command, size = struct.unpack_from('<II', b, position)
    assert size >= 8 and position + size <= len(b)
    assert command not in (0xe, 0x80000028), 'probe must not depend on dyld'
    if command == 5:
        flavor, count = struct.unpack_from('<II', b, position + 8)
        assert flavor == 6 and count == 68
        entry = struct.unpack_from('<Q', b, position + 16 + 32 * 8)[0]
    position += size
assert position == 32 + command_bytes and entry is not None
print(f'Built static arm64e probe: {p}, {len(b)} bytes, entry {entry:#x}, subtype {subtype:#x}')
PY
