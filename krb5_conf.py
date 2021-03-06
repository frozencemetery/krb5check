#!/usr/bin/python3

# This is used in crypto-policies's test suite.  Before making changes, be
# sure it won't break them.

import os
import re
import subprocess
import sys

from collections import defaultdict

STANZA_SECTIONS = ["realms", "capaths", "appdefaults", "plugins", # krb5.conf
                   "dbmodules"] # kdc
FLAT_SECTIONS = ["libdefaults", "domain_realm", # krb5.conf
                 "kdcdefaults", "dbdefaults", "dbmodules", "logging"] # kdc
ALL_SECTIONS = STANZA_SECTIONS + FLAT_SECTIONS

# Ideally this wouldn't have rc4 on it, but that's not the world we live in
# ... yet.
ACCEPTED_ENCTYPES = [
    "aes256-cts-hmac-sha1-96", "aes256-cts", "aes256-sha1",
    "aes128-cts-hmac-sha1-96", "aes128-cts", "aes128-sha1",
    "aes256-cts-hmac-sha384-192", "aes256-sha2",
    "aes128-cts-hmac-sha256-128", "aes128-sha2",
    "arcfour-hmac", "rc4-hmac", "arcfour-hmac-md5",
    "camellia256-cts-cmac", "camellia256-cts",
    "camellia128-cts-cmac", "camellia128-cts",
    "aes", "rc4", "camellia"
]

min_ver = None

def error(s, prefix):
    print("%s: %s" % (prefix, s), file=sys.stderr)
    exit(1)

def by_section(lines, prefix):
    secs = {}

    while len(lines) > 0:
        m = re.match(r"\[(.*)\]", lines[0])
        if m is None or m.group(1) not in ALL_SECTIONS:
            error("malformed/missing section header: " + lines[0], prefix)
        elif m.group(1) in secs.keys():
            error("duplicate section header: " + m.group(1), prefix)

        values = []
        del(lines[0])

        while len(lines) > 0 and not lines[0].startswith('['):
            values.append(lines[0])
            del(lines[0])
        if len(values) != 0:
            secs[m.group(1)] = values

    return secs

def merge(parent, child, prefix):
    for sec in child.keys():
        if sec not in parent.keys():
            parent[sec] = child[sec]
            continue

        parent[sec] += child[sec]

    return parent

def get_clean_contents(f, prefix=None):
    prefix = f if prefix is None else prefix + ": " + f

    try:
        data = open(f, "r").read()
    except Exception as e:
        error(e, prefix)

    lines = data.replace("\r\n", "\n").split("\n")
    lines = [line.strip() for line in lines
             if not line.startswith("#") and len(line.strip()) > 0]

    extra = []
    while lines[0].startswith("include"):
        m = re.match(r"(include|includedir)\s+(.*)", lines[0])
        verb = m.group(1)
        path = m.group(2).strip()

        if verb == "include":
            extra.append(get_clean_contents(path, prefix))
        elif verb == "includedir":
            for nf in os.listdir(path):
                if not nf.endswith(".conf") \
                   and re.search("[^a-zA-Z0-9_-]", nf) is not None:
                    error("file ignored by libkrb5: " + nf, prefix)

                nf = os.path.join(path, nf)
                extra.append(get_clean_contents(nf, prefix))

        else:
            error("unrecognized include directive: " + verb, prefix)

        del(lines[0])

    secs = by_section(lines, prefix)
    for d in extra:
        secs = merge(secs, d, prefix)
    return secs

def first_level(lines):
    tup_list = []
    for line in lines:
        m = re.match(r"(.*?)\s*=\s*(.*)", line)
        if m is None:
            error("malformed assignment: " + line, "(parsing)")

        tup_list.append((m.group(1), m.group(2)))

    return tup_list

def second_level(lines):
    secs = {}

    while len(lines) > 0:
        m = re.match(r"(.*?)\s*=\s*{", lines[0])
        if m is None:
            error("malformed stanza: " + lines[0], "(parsing)")

        del(lines[0])
        attrs = []
        while lines[0] != "}":
            attrs.append(lines[0])
            del(lines[0])

        secs[m.group(1)] = to_dict(first_level(attrs), True)
        del(lines[0])

    return secs

def to_dict(tuplist, dups_okay=False):
    d = defaultdict(list) if dups_okay else {}

    for (k, v) in tuplist:
        if dups_okay:
            d[k] += [v]
            continue
        elif k in d:
            print(tuplist)
            error("duplicate assignment: " + k, "(parsing)")

        d[k] = v

    # convert to regular dict for display purposes
    return dict(d)

def parse(f):
    sections = get_clean_contents(f)
    for s in sections.keys():
        if s in STANZA_SECTIONS:
            sections[s] = second_level(sections[s])
            continue
        sections[s] = to_dict(first_level(sections[s]))

    return sections

def krb5_min_ver():
    global min_ver
    if min_ver is not None:
        return min_ver

    # Try krb5-config
    ret, res = subprocess.getstatusoutput("krb5-config --version")
    if ret == 0:
        res = res.strip()
        min_ver = int(res.split(".")[1])
        return min_ver

    print("krb5-config not found; falling back...")

    # Fallback to RPM
    ret, res = subprocess.getstatusoutput(
        "rpm -q --qf '%{VERSION}' krb5-libs")
    if ret == 0:
        res = res.strip()
        min_ver = int(res.split(".")[1])
        return min_ver

    print("not an RPM system; falling back...")

    # Fallback to APT
    ret, res = subprocess.getstatusoutput("apt show libkrb5-3")
    if ret == 0:
        res = res.strip()
        res = [l for l in res.split("\n") if l.startswith("Version: ")][0]
        min_ver = int(res.split("-")[0].split(".")[1]) # 1.15-3, e.g.
        return min_ver

    error("Couldn't get krb5 version!", "(internal)")

def check(secs, accepted):
    libdefaults = secs.get("libdefaults")
    if libdefaults is None:
        error("missing libdefaults section", "(checks)")

    permitted_enctypes = libdefaults.get("permitted_enctypes")
    if permitted_enctypes is None:
        error("permitted_enctypes not specified", "libdefaults")
    for enctype in permitted_enctypes.split():
        if enctype not in accepted:
            error("bad enctype: " + enctype, "libdefaults")
        if krb5_min_ver() < 15 and \
           enctype in ["aes256-cts-hmac-sha384-192", "aes256-sha2",
                       "aes128-cts-hmac-sha256-128", "aes128-sha2"]:
            error("enctype too new: " + enctype, "libdefaults")

    pkinit_dh_min_bits = libdefaults.get("pkinit_dh_min_bits")
    if pkinit_dh_min_bits is not None:
        pkinit_dh_min_bits = int(pkinit_dh_min_bits)
        if pkinit_dh_min_bits < 2048:
            error("pkinit_dh_min_bits set lower than default", "libdefaults")
        elif pkinit_dh_min_bits % 2048 != 0:
            error("bad value for pkinit_dh_min_bits", "libdefaults")

def pretty_print(secs):
    for sec in secs.keys():
        print("[%s]" % sec)

        if sec in FLAT_SECTIONS:
            flat = secs[sec]
            for left in sorted(flat.keys()):
                print("    %s = %s" % (left, flat[left]))
            print("")
            continue

        blocks = secs[sec]
        for header in secs[sec].keys():
            print("    %s = {" % header)

            stanza = blocks[header]
            for left in sorted(blocks[header].keys()):
                for right in stanza[left]:
                    print("        %s = %s" % (left, right))

            print("    }")

        print("")

######

if __name__ == "__main__":
    if len(sys.argv) > 1 and not os.path.exists(sys.argv[1]):
        print("Usage: %s [file [file ...]]" % sys.argv[0])
        print("")
        print("Verify and pretty-print krb5 configuration")
        print("By default, checks /etc/krb5.conf")
        exit(1)

    files = ["/etc/krb5.conf"] if len(sys.argv) == 1 else sys.argv[1:]

    for f in files:
        out = parse(f)
        check(out, ACCEPTED_ENCTYPES)
        pretty_print(out)
