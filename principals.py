#!/usr/bin/env python3

import subprocess

from typing import List, Optional, Tuple

from krb5_conf import check, parse

# TODO handle multiple kvno like, at all
# TODO check configuration to find out about enctypes

def get_output(cmd: str) -> str:
    res = subprocess.check_output(cmd, shell=True)
    decoded = res.decode('utf-8')
    return decoded.strip()

def kl(command: str) -> str:
    return get_output("kadmin.local -q '" + command + "'")

# This has the bonus of catching deprecated keysalt types because non-v5 is
# appended where relevant.

# TODO right now this is a hack - kadmin will only use the long names, but
# configs use the short names, and I'm sharing a variable but shouldn't
goodlist = set(["aes256-cts-hmac-sha384-192", "aes256-sha2",
                "aes256-cts-hmac-sha1-96", "aes256-sha1", "aes256-cts",
                "aes128-cts-hmac-sha256-128", "aes128-sha2",
                "aes128-cts-hmac-sha1-96", "aes128-sha1", "aes128-cts",
                "camellia256-cts-cmac", "camellia256-cts",
                "camellia128-cts-cmac", "camellia128-cts",
                "aes", "camellia"])
def partition_etypes(princ: str) -> Tuple[List[str], List[str]]:
    princlist = kl("getprinc " + princ).split("\n")
    etypes = [l.rsplit(" ")[-1] for l in princlist
              if l.startswith("Key: vno ")]
    goods = []
    bads = []
    for e in etypes:
        if e in goodlist:
            goods.append(e)
            continue
        bads.append(e)
    return goods, bads

def handle_krbtgt(krbtgt: Optional[str]) -> None:
    if krbtgt is None:
        print("No krbtgt found; failing!")
        exit(-1)

    good, bad = partition_etypes(krbtgt)
    if len(good) == 0:
        print("krbtgt " + krbtgt + " has no good enctypes!")
        print("It needs to be reissued.  To do this, first: ")
        print('    kadmin.local -q "cpw -rankdkey -keepold ' + krbtgt + '"')
        print("(Propogate the new key to any replicas.)")
        print("Wait until all current TGTs expire (typically 1d).  Then:")
        print("    kadmin.local -q purgekeys")
        print("")
    elif len(bad) != 0:
        print("krbtgt " + krbtgt + " supports some bad enctypes.")
        print("This is only a problem if your machines do not mandate")
        print("good encryption types.")
        print("")
    else:
        print("(krbtgt looks okay)")

def handle_cross_realm(croses: List[str]) -> None:
    need_updated = []
    for cross in crosses:
        good, _ = partition_etypes(cross)
        if len(good) == 0:
            need_updated.append(cross)

    if len(need_updated) == 0:
        print("(cross-realm principals look okay)")
        return

    print("These cross-realm relationships rely on weak encryption:")
    print("    " + " ".join(need_updated))
    print("They need to be recreaed.  This requires coordination with the")
    print("administration of those realms.  A new key must be established")
    print("over a very secure channel.  For more information, see:")
    print("https://web.mit.edu/kerberos/krb5-latest/doc/admin/database.html#cross-realm-authentication")
    print("")

def handle_km() -> None:
    _, bad_etypes = partition_etypes("K/M")
    if len(bad_etypes) == 0:
        print("(K/M looks okay)\n")
        return

    print("K/M (the database master key) uses bad encryption types:")
    print("    " + " ".join(bad_etypes))
    print("Use kdb5_util to fix.  Suggested commands:")
    print("    kdb5_util add_mkey -e aes256-cts-hmac-sha384-192 -s")
    print("    kdb5_util list_mkeys # take the highest KVNO")
    print("    kdb5_util use_mkey # use KVNO from previous command")
    print("    kdb5_util update_princ_encryption # will prompt")
    print("    kdb5_util purge_mkeys")
    print("")

def handle_users(users: List[str]) -> None:
    nogood = []
    havebad = []
    for u in users:
        goods, bads = partition_etypes(u)
        if len(goods) == 0:
            nogood.append(u)
        elif len(bads) != 0:
            havebad.append(u)

    if len(nogood) != 0:
        print("The following users have no good encryption types:")
        print("    " + " ".join(nogood))
        print("They need to be rekeyed.  Usually, this can be fixed with ")
        print("kpasswd or kadmin change_password")
        print("")
    if len(havebad) != 0:
        print("The following users have some bad encryption types:")
        print("    " + " ".join(havebad))
        print("This is only a problem if your machines do not mandate")
        print("good encryption types")
        print("")
    if len(nogood) == 0 and len(havebad) == 0:
        print("(users look okay)")

def handle_services(services: List[str]) -> None:
    nogood = []
    havebad = []
    for s in services:
        goods, bads = partition_etypes(s)
        if len(goods) == 0:
            nogood.append(s)
        elif len(bads) != 0:
            havebad.append(s)

    if len(nogood) != 0:
        print("The following services have no good encryption types:")
        print("    " + " ".join(nogood))
        print("They need to be rekeyed, and all keytabs updated.")
        print("(Typically it is sufficient to generate new keytabs and ")
        print("move them to the relevant servers.)")
        print("")
    if len(havebad) != 0:
        print("The following services have some bad encryption types:")
        print("    " + " ".join(havebad))
        print("This is only a problem if your machines do not mandate")
        print("good encryption types")
        print("")
    if len(nogood) == 0 and len(havebad) == 0:
        print("(services look okay)")

def kdc_conf_check(kdc_conf, goodlist):
    realms = kdc_conf["realms"]
    for realm in realms.keys():
        supported_enctypes = realms[realm].get("supported_enctypes")
        if supported_enctypes is None:
            # This is the default since 1.14, though the man pages don't
            # reflect it.
            supported_enctypes = ["aes256-cts-hmac-sha1-96:normal",
                                  "aes128-cts-hmac-sha1-96:normal"]
            # TODO we here

if __name__ == "__main__":
    print("Hello!  Remember to back up your KDC before making changes.\n")
    # TODO maybe some info about the stuff we warn about and why?

    # TODO we don't support < 1.14

    krb5_conf = parse("/etc/krb5.conf")
    check(krb5_conf, goodlist)

    kdc_conf = parse("/var/kerberos/krb5kdc/kdc.conf")
    kdc_conf_check(kdc_conf, goodlist)
    
    princs = kl("listprincs").split('\n')
    if not princs[0].startswith("Authenticating as principal "):
        print("Error: couldn't list principals!")
        exit(-1)

    del(princs[0])
    krbtgt = None
    crosses = []
    users = []
    services = []
    for p in princs:
        short, realm = p.rsplit("@", 1)
        if short == "K/M":
            # Assume we always have the one K/M
            continue
        elif short.startswith("krbtgt/"):
            foreign = short[short.index("/") + 1:]
            if foreign != realm:
                crosses.append(p)
            else:
                krbtgt = p

            continue
        elif "/" not in short:
            users.append(p)
            continue

        services.append(p)

    handle_krbtgt(krbtgt)
    handle_cross_realm(crosses)
    handle_km()
    handle_users(users)
    handle_services(services)

    print("(All done)")
