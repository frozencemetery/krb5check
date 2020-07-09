#!/bin/bash -ex

p=secretes
h=kerberos.example.com

function yi() {
    yum -y --nogpgcheck install $@
}

# epel for nss_wrapper in el7
if [ ! -f /usr/bin/dnf ]; then
    yi https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
fi

yi krb5-{server,workstation} nss_wrapper python3 diffutils

echo "127.0.0.1 $h" > hosts
export NSS_WRAPPER_HOSTS=`pwd`/hosts
export NSS_WRAPPER_HOSTNAME=$h
export LD_PRELOAD=libnss_wrapper.so

# crypto-policies explanation takes up 2 lines on el8
sed -i '3~1s/^# / /g' /etc/krb5.conf

# containers break KEYRING, and el7 KCM is tech preview, so...
sed -i 's/ default_ccache_name/# default_ccache_name/g' /etc/krb5.conf

echo -e "$p\n$p" | kdb5_util create -s
kadmin.local addprinc -pw $p admin
kadmin.local addprinc -pw $p test
kadmin.local addprinc -randkey host/$h
kadmin.local ktadd host/$h

# For completeness, this would start the KDC.  However, we don't need to do
# that - and if we were to in this environment, we would need to pass in the
# nss_wrapper variables separately.
#
# systemctl start krb5kdc kadmin
