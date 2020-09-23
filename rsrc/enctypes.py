# A model for enctypes/keysalts from krb5.

import re

from typing import Set, Union

# "canonical" names are intentionally different from krb5's
et_mapping = {
    "des/crc32": set(["des-cbc-crc", "des"]),
    "des/md4": set(["des-cbc-md4", "des"]),
    "des/md5": set(["des-cbc-md5", "des"]),
    "des/sha1": set(["des-hmac-sha1"]),
    "des/raw": set(["des-cbc-raw"]),
    "des3/raw": set(["des3-cbc-raw"]),
    "des3/sha1": set(["des3-cbc-sha1", "des3-hmac-sha1", "des3-cbc-sha1-kd",
                      "des3"]),
    "aes256/sha1": set(["aes256-cts-hmac-sha1-96", "aes256-cts",
                        "aes256-sha1", "aes"]),
    "aes128/sha1": set(["aes128-cts-hmac-sha1-96", "aes128-cts",
                        "aes128-sha1", "aes"]),
    "aes256/sha2": set(["aes256-cts-hmac-sha384-192", "aes256-sha2", "aes"]),
    "aes128/sha2": set(["aes128-cts-hmac-sha256-128", "aes128-sha2", "aes"]),
    "rc4/md5": set(["arcfour-hmac", "rc4-hmac", "arcfour-hmac-md5", "rc4"]),
    "rc4/export": set(["arcfour-hmac-exp", "rc4-hmac-exp",
                       "arcfour-hmac-md5-exp"]),
    "camellia/256": set(["camellia256-cts-cmac", "camellia256-cts",
                         "camellia"]),
    "camellia/128": set(["camellia128-cts-cmac", "camellia128-cts",
                         "camellia"]),
}
ets = set(et_mapping.keys())

et_no_rhel8 = set(["des/crc32", "des/md4", "des/md5", "des/raw", "des/sha1",
                   "des3/raw", "des3/sha1"])
et_broken = et_no_rhel8.union(["rc4/md5", "rc4/export"])

salts = set(["normal", "v4", "norealm", "onlyrealm", "afs3", "special"])
salt_no_rhel8 = set(["v4", "afs3"])

splitre = re.compile(r"[, ]+")

def strip_deprecated(raw: str) -> str:
    # Thanks, past me
    if raw.startswith("UNSUPPORTED:"):
        print(f"Unsupported enctype/keysalt: {raw}")
        exit(1)
    elif raw.startswith("DEPRECATED:"):
        raw = raw.split(":", 1)[-1]
    return raw

def canonicalize_et(raw: str) -> Set[str]:
    raw = strip_deprecated(raw)
    ret = set()
    found = False
    for k, v in et_mapping.items():
        if raw in v:
            found = True
            ret.add(k)
    if not found:
        print(f"enctype {raw} is not recognized by krb5!")
        exit(1)

    return ret

def canonicalize_etlist(raw: str) -> Set[str]:
    ret = set()
    for et in splitre.split(raw):
        ret.update(canonicalize_et(et))
    return ret

def warn_if_in(etlist: Set[str], bad: Set[str], error: str) -> None:
    in_bad = etlist.intersection(bad)
    if len(in_bad) > 0:
        print(f"{error}: {sorted(in_bad)}")

def check_etlist(raw: Union[str, bytes], name: str) -> None:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")

    etlist = canonicalize_etlist(raw)
    warn_if_in(etlist, et_no_rhel8,
               f"Unsupported in RHEL 8 enctype(s) specified in {name}")
    warn_if_in(etlist, et_broken, f"Insecure enctype(s) specified in {name}")

def all_in(smaller: Set[str], larger: Set[str]) -> bool:
    i = smaller.intersection(larger)
    return len(i) == len(smaller)

def ensure_hasgood(raw: Union[str, bytes], name: str) -> None:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")

    norhel8 = 0
    broken = 0

    kslist = splitre.split(raw)
    assert(len(kslist) > 0)
    for ks in kslist:
        ks = strip_deprecated(ks)

        et = ks
        salt = "normal"

        sp = ks.split(":", 1)
        if len(sp) > 1:
            et = sp[0]
            if len(sp[1]) > 1:
                salt = sp[1]

        ets = canonicalize_et(et)

        # This is ugly because we've prepared for partial deprecation of
        # aliases - for exapmle, this allows us to deprecate aes128/sha1 while
        # keeping aes256/sha1, and behaving properly when someone sets "aes".
        if salt in salt_no_rhel8 or all_in(ets, et_no_rhel8):
            norhel8 += 1
        if all_in(ets, et_broken):
            broken += 1

    if norhel8 == len(kslist):
        print(f"No RHEL 8 supported enctypes for {name}")
    if broken == len(kslist):
        print(f"No secure enctypes for {name}")
