#!/usr/bin/python3

import re
import os
import sys

def error(s, prefix):
    print("%s: %s" % (prefix, s), file=sys.stderr)
    return

def by_section(lines, prefix):
    secs = {}

    while len(lines) > 0:
        m = re.match(r"\[(.*)\]", lines[0])
        if m == None \
           or m.group(1) not in ["libdefaults", "realms", "domain_realm",
                                 "capaths", "appdefaults", "plugins",
                                 "kdcdefaults", "realms", "dbdefaults", # kdc
                                 "dbmodules", "logging"]: # kdc
            error("malformed section header %s" % lines[0], prefix)
            exit(1)
        elif m.group(1) in secs.keys():
            error("duplicate section header %s" % m.group(1), prefix)
            exit(1)

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
        error(e, prefix)
        exit(1)

    lines = data.replace("\r\n", "\n").split("\n")
    lines = [line.strip() for line in lines
             if not line.startswith("#") and len(line.strip()) > 0]

    extra = []
    while lines[0].startswith("include"):
        m = re.match("(include|includedir)\s(.*)", lines[0])
        verb = m.group(1)
        path = m.group(2).strip()

        if verb == "include":
            extra.append(get_clean_contents(path, prefix))
            pass
        elif verb == "includedir":
            for nf in os.listdir(path):
                if not nf.endswith(".conf") \
                   and re.search("[^a-zA-Z0-9_-]", nf) is not None:
                    error("File is ignored by libkrb5: %s" % nf, prefix)
                    exit(1)

                extra.append(get_clean_contents(path + "/" + nf, prefix))
                pass
            pass
        else:
            error("unrecognized include directive '%s'" % verb, prefix)
            exit(1)

        del(lines[0])
        pass

    secs = by_section(lines, prefix)
    for d in extra:
        secs = merge(secs, d, prefix)
        pass
    return secs

if __name__ == "__main__":
    if len(sys.argv) > 1 and not os.path.exists(sys.argv[1]):
        print("Usage: %s [file [file ...]]" % sys.argv[0])
        print("")
        print("Check krb5 configuration (defaults to /etc/krb5.conf)")
        exit(1)

    files = ["/etc/krb5.conf"] if len(sys.argv) == 1 else sys.argv[1:]

    for f in files:
        sections = get_clean_contents(f)
        for k in sections.keys():
            print("%s: %s\n" % (k, sections[k]))
            pass
        pass
    exit(0)
