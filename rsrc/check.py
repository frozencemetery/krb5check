#!/usr/bin/python3

import os
import re
import subprocess

from enctypes import check_etlist, ensure_hasgood
from profile import KRB5Profile

from typing import List

# This has been true since 1.14, though man pages don't reflect it.
defkeysalts = "aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal"

# Prior to 1.18, this includes 1DES.  This is upstreams, so it includes 3DES.
defetypes = " ".join(["aes256-cts-hmac-sha1-96", "aes128-cts-hmac-sha1-96",
                      "aes256-cts-hmac-sha384-192",
                      "aes128-cts-hmac-sha256-128", "des3-cbc-sha1",
                      "arcfour-hmac-md5", "camellia256-cts-cmac",
                      "camellia128-cts-cmac"])

# True since 1.11, prior to which it was 3DES.
defmkey = "aes256-cts-hmac-sha1-96"

def check_client() -> None:
    prof = KRB5Profile()

    allow_weak_crypto = prof.get_bool("libdefaults", "allow_weak_crypto",
                                      default=0)
    if allow_weak_crypto:
        print("allow_weak_crypto enabled (turns on very broken cryptography)")

    permitted_enctypes = prof.get_string("libdefaults", "permitted_enctypes",
                                         default=defetypes)
    check_etlist(permitted_enctypes, "permitted_enctypes")

    # Prior to 1.18, these default to defetypes, not permitted_enctypes
    tgs = prof.get_string("libdefaults", "default_tgs_enctypes")
    if tgs:
        check_etlist(tgs, "default_tgs_enctypes")

    tkt = prof.get_string("libdefaults", "default_tkt_enctypes")
    if tkt:
        check_etlist(tkt, "default_tkt_enctypes")

    # PKINIT-related values can be set in five different places - three in
    # krb5.conf, and two in kdc.conf.
    dh_min_values = set()
    dh_3 = prof.get_integer("libdefaults", "pkinit_dh_min_bits", None, 2048)
    if dh_3:
        dh_min_values.add(int(dh_3))

    # There's enough zero-conf that this being empty on the client is okay.
    realms = prof.section("realms")
    for realm, config in realms:
        keys = {k for k, _ in config}
        if not keys.isdisjoint(["v4_realm", "v4_instance_convert"]):
            print(f"Kerberos v4 configuration found for {realm}")

        dh_2 = {int(v) for k, v in config if k == "pkinit_dh_min_bits"}
        dh_min_values.update(dh_2)

    # If libdefaults is empty, there'll be warnings elsewhere, but it's a
    # valid configuration.
    libdefaults = prof.section("libdefaults")
    for realm, stanza in libdefaults:
        # krb5 doesn't use uppercase for configs, and realms pretty much have
        # to be uppercase, so this will do for now as a heiuristic.
        if not realm.isupper():
            continue

        dh_1 = {int(v) for k, v in stanza if k == "pkinit_dh_min_bits"}
        dh_min_values.update(dh_1)

    # default is 2048, which is considered fine for now
    for v in dh_min_values:
        if v < 2048:
            print(f"Weak value for pkinit_dh_min_bits: {v}")

def kl(cmd: str) -> List[str]:
    res = subprocess.check_output(f"kadmin.local -q '{cmd}'", shell=True)
    decoded = res.decode('utf-8')
    return decoded.strip().split("\n")[1:]

key_re = re.compile(r"^Key: vno \d+, (.*)$")
def get_princdata(princ: str) -> str:
    etlist = []
    for line in kl(f"getprinc {princ}"):
        m = key_re.match(line)
        if m:
            etlist.append(m.group(1))

    return " ".join(etlist)

def check_crypto_policies() -> None:
    try:
        policies = subprocess.check_output(
            ["update-crypto-policies", "--show"])[:-1]
    except FileNotFoundError:
        return

    for policy in policies.split(b":"):
        if policy == b"AD-SUPPORT":
            print("RC4 (weak) permitted by crypto-policies!")
        elif policy == b"LEGACY":
            print("Legacy (insecure) algorithms permitted by crypto-policies!")

tgtre = re.compile(r"krbtgt/(.*)")
def check_princs(permitted_enctypes: str) -> None:
    princs = kl("listprincs")
    for princ in princs:
        short, myrealm = princ.rsplit("@", 1)

        kslist = get_princdata(princ)
        if short == "K/M":
            ensure_hasgood(kslist, "the K/M principal (database master key)")
            continue

        m = tgtre.match(short)
        if not m:
            ensure_hasgood(kslist, f"the {short} principal")
            continue

        destrealm = m.group(1)
        if destrealm != myrealm:
            ensure_hasgood(kslist, f"cross-realm principal for {destrealm}")
            continue

        ensure_hasgood(kslist,
                       "the krbtgt principal (ticket granting service key)")

def check_kdc() -> None:
    if os.getuid() != 0:
        print("\nNot running as root; skipping KDC checks!")
        return

    prof = KRB5Profile(kdc=True)

    permitted_enctypes = prof.get_string("libdefaults", "permitted_enctypes",
                                         default=defetypes)
    check_etlist(permitted_enctypes, "KDC permitted_enctypes")

    otp = prof.section("otp")
    for toktype, stanza in otp:
        server = [v for k, v in stanza if k == "server"]
        if len(server) > 0 and server[0][0] != '/':
            print(f"OTP type {toktype} configures RADIUS")

    # Two pkinit_dh_min_bits places on the KDC.
    dh_min_values = set()
    dh_4 = prof.get_integer("kdcdefaults", "pkinit_dh_min_bits", None, 2048)
    if dh_4:
        dh_min_values.add(int(dh_4))

    realms = prof.section("realms")
    if len(realms) == 0:
        print("No realms found checking KDC configuration")
        exit(1)

    for realm, stanza in realms:
        has_preauth = False
        for k, v in stanza:
            if k == "pkinit_dh_min_bits":
                dh_min_values.add(int(v)) # dh_5
            elif k == "master_key_type":
                # defaults to defmkey, so it's okay to not specify
                check_etlist(v, "master_key_type")
            elif k == "default_principal_flags":
                has_preauth = "+preauth" in v

        if not has_preauth:
            print(f"{realm} doesn't set +preauth in default_principal_flags")

    # Same rationale as in check_client
    for v in dh_min_values:
        if v < 2048:
            print(f"Weak value for pkinit_dh_min_bits: {v}")

    check_princs(permitted_enctypes)

if __name__ == "__main__":
    ret, out = subprocess.getstatusoutput("rpm -qv krb5-libs")
    if ret != 0:
        print(f"Couldn't detect OS version: {out}")
        exit(1)

    minvers = re.match(r"krb5-libs-1\.([0-9]{1,2})", out)

    if minvers is None:
        print("Couldn't detect krb5 version; is it installed?")
        exit(1)

    minver = int(minvers.group(1))
    if minver < 14:
        print("krb5 < 1.14 not supported; upgrade and try again")
        exit(1)
    if minver >= 18:
        check_crypto_policies()

    check_client()
    check_kdc()
