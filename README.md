krb5check
=========

A collection of scripts for checking the health of Kerberos realms.

To use:

```bash
git clone https://github.com/frozencemetery/krb5check
cd krb5check
./runme
```

runme
-----

Inspects a Kerberos environment, looking for:

1. Breakage-free upgrade to RHEL-8.3+ (see below)
2. Usage of insecure (broken) cryptography

Ideally, this is run as root on the KDC, but it can also check
client-only configuration if run as non-root.  However, the things we can
check on the client are very few by comparison.

Running random code on the KDC is obviously not good practice.  A few steps
have been taken to mitigate the risk here:

1. Code is all Python (with a bit of shell); this means no untrusted binaries
2. No state is kept, no writes (output IO) are performed anywhere, and no
   changes are made to the KDC
3. Project is small and readable; ~500 lines with comments
4. Strict [mypy](http://mypy-lang.org/) compliance on our business logic

So I encourage you to read through the code before running it.

RHEL-8.3+ no longer support DES/3DES as well as the non-default afs3 and v4
salttypes.  I anticipate that DES removal will be the bigger problem.
Information on enctype migration can be found in [krb5's enctype
documentation](https://web.mit.edu/kerberos/krb5-devel/doc/admin/enctypes.html#migrating-away-from-older-encryption-types).

Our definition of "insecure (broken) cryptography" is derived from RFCs
[6649](https://tools.ietf.org/html/rfc6649) and
[8429](https://tools.ietf.org/html/rfc8429) - though note that these
documents, while current at the time they were written, cannot be kept
up-to-date.  Therefore, the requisite alarm around these algorithms is
typically higher than they suggest.

krb5_conf.py
------------

Verifies and pretty-prints a krb5 configuration.  Inspects /etc/krb5.conf by
default.  Will not make changes.  Used by
[crypto-policies](https://gitlab.com/redhat-crypto/fedora-crypto-policies).
