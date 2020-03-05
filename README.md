krb5check
=========

A collection of scripts for checking the health of Kerberos realms.

principals.py
-------------

Inspects each principal on your KDC and indicates which ones need to be using
stronger encryption.  Must be run on the KDC; will not make changes.

krb5_conf.py
------------

Verifies and pretty-prints a krb5 configuration.  Inspects /etc/krb5.conf by
default.  Will not make changes.  Used by
[crypto-policies](https://gitlab.com/redhat-crypto/fedora-crypto-policies).
