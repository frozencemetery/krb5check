#!/usr/bin/env python3

import subprocess

from typing import Any, List, Tuple

def get_output(cmd: str) -> str:
    res = subprocess.check_output(cmd, shell=True)
    decoded = res.decode('utf-8')
    return decoded.strip()

def kl(command: str) -> str:
    return get_output("kadmin.local " + command)

# This has the bonus of catching deprecated keysalt types because non-v5 is
# appended where relevant.
goodlist = set(["aes256-cts-hmac-sha384-192", "aes256-cts-hmac-sha1-96",
                "aes128-cts-hmac-sha1-96", "aes256-cts-hmac-sha384-192",
                "camellia256-cts-cmac", "camellia128-cts-cmac"])
def partition_etypes(princ: str) -> Tuple[List[str], List[str]]:
    princlist = kl("getprinc " + princ).split("\n")
    etypes = [l.rsplit(" ")[-1] for l in princlist \
              if l.startswith("Key: vno ")]
    goods = []
    bads = []
    for e in etypes:
        if e in goodlist:
            goods.append(e)
            continue
        bads.append(e)
    return goods, bads

print("Hello!  Remember to back up your KDC before making changes.\n")
# TODO maybe some info about the stuff we warn about and why?

princs = kl("-q listprincs").split('\n')
if not princs[0].startswith("Authenticating as principal "):
    print("Error: couldn't list principals!")
    exit(-1)

del(princs[0])

kms = []
users = []
services = []
for p in princs:
    if p.startswith("K/M@"):
        kms.append(p)
        continue

    short, realm = p.rsplit("@", 1)
    if "/" not in short:
        users.append(p)
        continue

    services.append(p)

# TODO Handle krbtgt!

# Handle K/M
if len(kms) != 1:
    print("More than one K/M detected.  We're not prepared for that.")
    print(kms)
    exit(-1)
km = kms[0]
_, bad_etypes = partition_etypes(km)
if len(bad_etypes) != 0:
    print("! K/M (the database master key) uses bad encryption types:")
    print("!     " + " ".join(bad_etypes))
    print("! Use kdb5_util to fix.  Suggested commands:")
    print("!     kdb5_util add_mkey -e aes256-cts-hmac-sha384-192 -s")
    print("!     kdb5_util list_mkeys # take the highest KVNO")
    print("!     kdb5_util use_mkey # use KVNO from previous command")
    print("!     kdb5_util update_princ_encryption # will prompt")
    print("!     kdb5_util purge_mkeys")
    print("")
else:
    print("(K/M looks okay)\n")
    
# Handle users
nogood = []
havebad = []
for u in users:
    goods, bads = partition_etypes(u)
    if len(goods) == 0:
        nogood.append(u)
    elif len(bads) != 0:
        havebad.append(u)

if len(nogood) != 0:
    print("! The following user principals have no good encryption types:")
    print("!     " + " ".join(nogood))
    print("! They need to be rekeyed.  If they're password based, ")
    print("! this can be accomplished with kpasswd / kadmin change_password")
    print("")
if len(havebad) != 0:
    print("- The following user principals have some bad encryption types:")
    print("-     " + " ".join(havebad))
    print("- This is only a problem if your machines do not mandate")
    print("- good encryption types")
    print("")

# Handle services
nogood = []
havebad = []
for s in services:
    goods, bads = partition_etypes(s)
    if len(goods) == 0:
        nogood.append(s)
    elif len(bads) != 0:
        havebad.append(s)

if len(nogood) != 0:
    print("! The following service principals have no good encryption types:")
    print("!     " + " ".join(nogood))
    print("! They need to be rekeyed, and all keytabs updated.")
    print("! (Typically it is sufficient to generate new keytabs and copy ")
    print("! them to the relevant servers.)")
    print("")
if len(havebad) != 0:
    print("- The following service principals have some bad encryption types:")
    print("-     " + " ".join(havebad))
    print("- This is only a problem if your machines do not mandate")
    print("- good encryption types")
    print("")

print("(All done)")
