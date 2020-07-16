# A model for enctypes/keysalts from krb5.

import re

from typing import Set, Tuple, Union

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

et_no_rhel8 = set(["des/crc32", "des/md4", "des/md5", "des/raw", "des/sha1",
                   "des3/raw", "des3/sha1"])
et_broken = et_no_rhel8.union(["rc4/md5", "rc4/export"])

salts = set(["normal", "v4", "norealm", "onlyrealm", "afs3", "special"])
salt_no_rhel8 = set(["v4", "afs3"])

def strip_deprecated(raw: Union[str, bytes]) -> str:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")

    # Thanks, past me
    if raw.startswith("UNSUPPORTED:"):
        raise Exception(f"Unsupported enctype/keysalt: {raw}")
    elif raw.startswith("DEPRECATED:"):
        raw = raw.split(":", 1)[-1]
    return raw

def canonicalize_et(raw: Union[str, bytes]) -> Set[str]:
    ret = set()

    raw = strip_deprecated(raw)

    found = False
    for k, v in et_mapping.items():
        if raw in v:
            found = True
            ret.add(k)
    if not found:
        raise Exception(f"enctype {raw} is not recognized by krb5!")

    return ret

splitre = re.compile(r"[, ]+")

def canonicalize_etlist(raw: Union[str, bytes]) -> Set[str]:
    ret = set()

    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")

    for et in splitre.split(raw):
        ret.update(canonicalize_et(et))

    return ret

# returns: canonicalized etypes, keysalts found
def canonicalize_kslist(raw: Union[str, bytes]) -> Tuple[Set[str], Set[str]]:
    enctypes: Set[str] = set()
    keysalts: Set[str] = set()

    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    for et in splitre.split(raw):
        salt = "normal"
        et = strip_deprecated(et)
        if ":" in et:
            et, salt = et.split(":")
            if salt not in salts:
                raise Exception(f"Salt {salt} is not recognized by krb5!")

        keysalts.add(salt)

        enctypes.update(canonicalize_et(et))

    return enctypes, keysalts

def warn_if_in(etlist: Set[str], bad: Set[str], error: str) -> None:
    in_bad = etlist.intersection(bad)
    if len(in_bad) > 0:
        print(f"{error}: {sorted(in_bad)}")

def warn_if_not_in(etlist: Set[str], bad: Set[str], error: str) -> None:
    in_good = etlist.difference(bad)
    if len(in_good) == 0:
        print(f"{error}")

def check_etlist(raw: Union[str, bytes], name: str) -> None:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")

    etlist = canonicalize_etlist(raw)
    warn_if_in(etlist, et_no_rhel8, f"Non-rhel8 enctype(s) in {name}")
    warn_if_in(etlist, et_broken, f"Broken enctype(s) in {name}")

def ensure_hasgood(raw: Union[str, bytes], name: str) -> None:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")

    etlist, salts = canonicalize_kslist(raw)
    warn_if_not_in(etlist, et_no_rhel8, f"No RHEL-8 enctypes for {name}")
    warn_if_not_in(etlist, et_broken, f"No non-broken enctypes for {name}")
    warn_if_not_in(salts, salt_no_rhel8, f"No RHEL-8 salts for {name}")

def check_kslist(raw: Union[str, bytes], name: str) -> None:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")

    ets, salts = canonicalize_kslist(raw)

    no_rhel8 = salts.intersection(salt_no_rhel8)
    if len(no_rhel8) > 0:
        print(f"Non-rhel8 capable salts in {name}: {sorted(no_rhel8)}")
    weird = salts.difference(["normal"])
    if len(weird) > 0:
        print(f"Abnormal salts in {name}: {sorted(weird)}")

    warn_if_in(ets, et_no_rhel8, f"Non-rhel8 enctype(s) in {name}")
    warn_if_in(ets, et_broken, f"Broken enctype(s) in {name}")
