#!/usr/bin/python3

from enctypes import canonicalize_etlist, check_etlist # TODO
from profile import KRB5Profile

prof = KRB5Profile()

# This has been true since 1.14, though man pages don't reflect it
defkeysalts = "aes256-cts-hmac-sha1-96:normal aes128-cts-hmac-sha1-96:normal"

# Prior to 1.18, this includes 1DES.  It never included 3DES.
defetypes = "aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96 aes256-cts-hmac-sha384-192 aes128-cts-hmac-sha256-128 des3-cbc-sha1 arcfour-hmac-md5 camellia256-cts-cmac camellia128-cts-cmac"

# TODO check krb5 version (delay this).  Right now everything assumes that:
# 1.14 <= version < 1.18.  This leaves out RHEL6 and the future.

# TODO check crypto-policies and RHEL version (delay this)

allow_weak_crypto = prof.get_bool("libdefaults", "allow_weak_crypto",
                                  default=0)
if allow_weak_crypto:
    raise Exception("Fatal: allow_weak_crypto is enabled")

permitted_enctypes = prof.get_string("libdefaults", "permitted_enctypes",
                                     default=defetypes)
check_etlist(permitted_enctypes, "permitted_enctypes")

# Prior to 1.18, these default to defetypes, not permitted_enctypes
default_tgs_enctypes = prof.get_string("libdefaults", "default_tgs_enctypes")
if default_tgs_enctypes:
    check_etlist(default_tgs_enctypes, "default_tgs_enctypes")

default_tkt_enctypes = prof.get_string("libdefaults", "default_tkt_enctypes")
if default_tkt_enctypes:
    check_etlist(default_tkt_enctypes, "default_tkt_enctypes")

# PKINIT-related values can be set in 5 different places - 3 in krb5.conf, and
# 2 in kdc.conf.
dh_min_values = set()
dh_3 = prof.get_string("libdefaults", "pkinit_dh_min_bits")
if dh_3:
    dh_min_values.add(int(dh_3))

realms = prof.section("realms")
for realm, config in realms:
    keys = {k for k, _ in config}
    if not keys.isdisjoint(["v4_realm", "v4_instance_convert"]):
        print(f"Kerberos v4 configuration found for {realm}")

    dh_2 = {int(v) for k, v in config if k == "pkinit_dh_min_bits"}
    dh_min_values.update(dh_2)

# krb5 doesn't use uppercase for configs, and realms pretty much have to be
# uppercase, so this will do for now as a heiuristic.
libdefaults = prof.section("libdefaults")
for realm, stanza in libdefaults:
    if not realm.isupper():
        continue
    dh_1 = {int(v) for k, v in stanza if k == "pkinit_dh_min_bits"}
    dh_min_values.update(dh_1)

# default is 2048, which is considered fine for now
for v in dh_min_values:
    if v < 2048:
        print(f"Weak value for pkinit_dh_min_bits: {v}")

# TODO: should we do a site-wide crypto-policies check?

# on a KDC, we also need to check:
# TODO: realms->supported_enctypes
# TODO: otp->server is not a RADIUS server
# TODO: realms->pkinit_dh_min_bits overrides kdcdefaults->pkinit_dh_min_bits

# TODO: KDC checks for principals
