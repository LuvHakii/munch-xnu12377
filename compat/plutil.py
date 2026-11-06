#!/usr/bin/env python3
"""Implement the plist lint/conversion operations used by the local XNU build."""

import argparse
import pathlib
import plistlib

parser = argparse.ArgumentParser(description=__doc__)
mode = parser.add_mutually_exclusive_group(required=True)
mode.add_argument("-lint", action="store_true")
mode.add_argument("-convert", choices=["binary1"])
parser.add_argument("-s", action="store_true", dest="silent")
parser.add_argument("-o", type=pathlib.Path, dest="output")
parser.add_argument("file", type=pathlib.Path)
args = parser.parse_args()
if args.lint and args.output is not None:
    parser.error("-o requires -convert")
try:
    value = plistlib.loads(args.file.read_bytes())
    if args.convert:
        converted = plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=False)
        (args.output or args.file).write_bytes(converted)
except Exception as error:
    parser.exit(1, f"{args.file}: {error}\n")
if not args.silent:
    print(f"{args.file}: OK")
