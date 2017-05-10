#!/usr/bin/python3

import re
import os
import sys

STANZA_SECTIONS = ["realms", "capaths", "appdefaults", "plugins", # krb5.conf
                   "dbmodules"] # kdc
FLAT_SECTIONS = ["libdefaults", "domain_realm", # krb5.conf
                 "kdcdefaults", "dbdefaults", "dbmodules", "logging"] # kdc
ALL_SECTIONS = STANZA_SECTIONS + FLAT_SECTIONS

def error(s, prefix):
    print("%s: %s" % (prefix, s), file=sys.stderr)
    return exit(1)

def by_section(lines, prefix):
    secs = {}

    while len(lines) > 0:
        m = re.match(r"\[(.*)\]", lines[0])
        if m == None or m.group(1) not in ALL_SECTIONS:
            return error("malformed/missing section header: " +lines[0],
                         prefix)
        elif m.group(1) in secs.keys():
            return error("duplicate section header: " + m.group(1), prefix)

        values = []
        del(lines[0])

        while len(lines) > 0 and not lines[0].startswith('['):
            values.append(lines[0])
            del(lines[0])
            pass
        if len(values) != 0:
            secs[m.group(1)] = values
            pass

        continue
    return secs

def merge(parent, child, prefix):
    for sec in child.keys():
        if sec not in parent.keys():
            parent[sec] = child[sec]
            continue

        parent[sec] += child[sec]
        pass
    return parent

def get_clean_contents(f, prefix=None):
    prefix = f if prefix is None else prefix + ": " + f

    try:
        data = open(f, "r").read()
        pass
    except Exception as e:
        return error(e, prefix)

    lines = data.replace("\r\n", "\n").split("\n")
    lines = [line.strip() for line in lines
             if not line.startswith("#") and len(line.strip()) > 0]

    extra = []
    while lines[0].startswith("include"):
        m = re.match("(include|includedir)\s+(.*)", lines[0])
        verb = m.group(1)
        path = m.group(2).strip()

        if verb == "include":
            extra.append(get_clean_contents(path, prefix))
            pass
        elif verb == "includedir":
            for nf in os.listdir(path):
                if not nf.endswith(".conf") \
                   and re.search("[^a-zA-Z0-9_-]", nf) is not None:
                    return error("file ignored by libkrb5: " + nf, prefix)

                extra.append(get_clean_contents(path + "/" + nf, prefix))
                pass
            pass
        else:
            return error("unrecognized include directive: " + verb, prefix)

        del(lines[0])
        pass

    secs = by_section(lines, prefix)
    for d in extra:
        secs = merge(secs, d, prefix)
        pass
    return secs

def first_level(lines):
    tup_list = []
    for line in lines:
        m = re.match("(.*?)\s*=\s*(.*)", line)
        if m is None:
            return error("malformed assignment: " + line, "(parsing)")

        tup_list.append((m.group(1), m.group(2)))
        pass
    return tup_list

def second_level(lines):
    secs = {}

    while len(lines) > 0:
        m = re.match("(.*?)\s*=\s*{", lines[0])
        if m is None:
            return error("malformed stanza: " + lines[0], "(parsing)")

        del(lines[0])
        attrs = []
        while lines[0] != "}":
            attrs.append(lines[0])
            del(lines[0])
            pass

        secs[m.group(1)] = first_level(attrs)
        del(lines[0])
        pass
    return secs

def parse(f):
    sections = get_clean_contents(f)
    for s in sections.keys():
        if s in STANZA_SECTIONS:
            sections[s] = second_level(sections[s])
            continue
        sections[s] = first_level(sections[s])
        pass
    return sections

if __name__ == "__main__":
    if len(sys.argv) > 1 and not os.path.exists(sys.argv[1]):
        print("Usage: %s [file [file ...]]" % sys.argv[0])
        print("")
        print("Check krb5 configuration (defaults to /etc/krb5.conf)")
        exit(1)

    files = ["/etc/krb5.conf"] if len(sys.argv) == 1 else sys.argv[1:]

    for f in files:
        sections = parse(f)
        for k in sections.keys():
            print("%s: %s\n" % (k, sections[k]))
            pass
        pass
    exit(0)
