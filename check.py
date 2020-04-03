#!/usr/bin/python3

import os
import re
import subprocess

from enctypes import check_etlist, check_kslist
from profile import KRB5Profile

# This has been true since 1.14, though man pages don't reflect it
defkeysalts = "aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal"

# Prior to 1.18, this includes 1DES.
defetypes = "aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128 des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac camellia128-cts-cmac"

# True since 1.11, prior to which it was 3des
defmkey = "aes256-cts-hmac-sha1-96"

def check_client() -> None:
    prof = KRB5Profile()

    allow_weak_crypto = prof.get_bool("libdefaults", "allow_weak_crypto",
                                      default=0)
    if allow_weak_crypto:
        raise Exception("Fatal: allow_weak_crypto is enabled")

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

    # There's enough zero-conf that this is actually okay now.
    realms = prof.section("realms")
    realms = realms if realms else []
    for realm, config in realms:
        keys = {k for k, _ in config}
        if not keys.isdisjoint(["v4_realm", "v4_instance_convert"]):
            print(f"Kerberos v4 configuration found for {realm}")

        dh_2 = {int(v) for k, v in config if k == "pkinit_dh_min_bits"}
        dh_min_values.update(dh_2)

    # If libdefaults is empty, there'll be warnings elsewhere, but it's a
    # valid configuration.
    libdefaults = prof.section("libdefaults")
    libdefaults = libdefaults if libdefaults else []
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

def check_kdc(family: str) -> None:
    if os.getuid() != 0:
        raise Exception("You need to be root to read KDC data")

    prof = KRB5Profile(kdc=True)

    otp = prof.section("otp")
    otp = otp if otp else []
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
    if not realms:
        raise Exception("No realms found checking KDC configuration")

    for realm, stanza in realms:
        has_preauth = False
        for k, v in stanza:
            if k == "supported_enctypes":
                # TODO this check isn't right.  Actual enctypes that get used
                # is determined by permitted_enctypes &co., so we should check
                # that again here.  However, we also do need to check that
                # *removed* enctypes aren't listed here because then new
                # principal creation won't work right.

                # default is defkeysalts, so it's okay-ish to not specify
                check_kslist(v, "supported_enctypes")
            elif k == "pkinit_dh_min_bits":
                dh_min_values.add(int(v)) # dh_5
            elif k == "master_key_type":
                # defaults to defmkey, so it's okay to not specify
                check_etlist(v, "master_key_type")
            elif k == "default_principal_flags":
                has_preauth = "+preauth" in v
            # TODO save K/M name here for later.  If multiple realms are
            # found, we don't support it.

        if not has_preauth:
            print(f"{realm} doesn't set +preauth in default_principal_flags")

    # Same rationale as in check_client
    for v in dh_min_values:
        if v < 2048:
            print(f"Weak value for pkinit_dh_min_bits: {v}")

# TODO: KDC checks for principals

if __name__ == "__main__":
    try:
        p = subprocess.run(["dpkg-query", "-W", "libkrb5-3"],
                           capture_output=True)
        if p.returncode == 0:
            family = "Debian"
            minverb = re.match(rb"libkrb5-3.*\t1\.([0-9]{1,2})", p.stdout)
    except FileNotFoundError:
        # TODO check crypto-policies and RHEL version (delay this)
        family = "Fedora"
        p = subprocess.run(["rpm", "-qv", "krb5-libs"], capture_output=True)
        if p.returncode != 0:
            raise Exception("Couldn't detect OS version")

        minverb = re.match(rb"krb5-libs-1\.([0-9]{1,2})", p.stdout)
    if minverb is None:
        raise Exception("Couldn't detect krb5 version; is it installed?")

    minver = int(minverb.group(1))
    if minver < 14:
        raise Exception("krb5 < 1.14 not supported")
    # elif minver >= 18:
    #     raise Exception("krb5 >= 1.18 not supported (you already upgraded)")

    check_client()
    check_kdc(family) # TODO flag for this probably
