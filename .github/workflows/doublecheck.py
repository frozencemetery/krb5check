#!/usr/bin/python3

import re
import subprocess

# Discover OS version
with open("/etc/redhat-release", "r") as f:
    name = f.read()[:-1]

m = re.match(r"Red Hat Enterprise Linux Server release (\d\.\d)", name)
if not m:
    m = re.match(r"CentOS Linux release (\d\.\d)", name)
if not m:
    print("OS detection failed!")
    exit(-1)

el = m.group(1)

# Get the output
ret, out = subprocess.getstatusoutput("./check.py > out")
if ret != 0:
    print(f"Check failed: {out}")
    exit(ret)

# Check if it matches the reference
ret, out = subprocess.getstatusoutput(f"diff -u out ci/outputs/{el}")
if ret != 0:
    print("Output didn't match expectations; diff follows...")
    print(out)

exit(ret)
