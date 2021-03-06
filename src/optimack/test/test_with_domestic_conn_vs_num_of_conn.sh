#!/bin/bash

# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso' #837M
# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template' #83M
# url='http://mirrors.mit.edu/ubuntu/indices/md5sums.gz' #28.5M
# site='mirrors.mit.edu'

# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.iso' #837M
url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.template'
site='mirror.math.princeton.edu'

for i in 1 2 3 4 5 6 7; do
    sed -i "s/define CONN_NUM .*/define CONN_NUM $i/g" ~/squid_copy/src/optimack/Optimack.cc
    cd ~/squid_copy/
    make install
    bash ~/squid_copy/src/optimack/test/test_with_domestic_conn.sh ${i}optim+1range
done
