#!/usr/bin/env python3
"""Check local build plist conversion and failure-before-write behavior."""

import pathlib
import plistlib
import subprocess
import sys
import tempfile

command = [sys.executable, str(pathlib.Path(__file__).with_name("plutil.py"))]
with tempfile.TemporaryDirectory() as directory:
    source = pathlib.Path(directory) / "source.plist"
    output = pathlib.Path(directory) / "output.plist"
    expected = {"Symbols": ["_kernel_symbol", "<&>"], "Version": 42, "Data": b"\x00\xff"}
    source.write_bytes(plistlib.dumps(expected))
    subprocess.run(command + ["-convert", "binary1", "-s", "-o", str(output), str(source)], check=True)
    assert output.read_bytes().startswith(b"bplist00")
    assert plistlib.loads(output.read_bytes()) == expected
    subprocess.run(command + ["-lint", "-s", str(output)], check=True)
    subprocess.run(command + ["-convert", "binary1", "-s", str(source)], check=True)
    assert plistlib.loads(source.read_bytes()) == expected

    malformed = b"<plist><dict><key>missing-value</key>"
    source.write_bytes(malformed)
    previous_output = output.read_bytes()
    for arguments in (
        ["-lint", "-s", str(source)],
        ["-convert", "binary1", "-s", str(source)],
        ["-convert", "binary1", "-s", "-o", str(output), str(source)],
    ):
        result = subprocess.run(command + arguments, capture_output=True)
        assert result.returncode != 0
        assert source.read_bytes() == malformed
        assert output.read_bytes() == previous_output
print("PLUTIL_TEST_PASS")
