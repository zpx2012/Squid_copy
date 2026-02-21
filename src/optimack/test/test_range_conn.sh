#!/bin/bash

site='161.35.100.102'
# site='138.68.49.206' #SF-HTTP-SV
#site='67.205.159.15' #NY-HTTP-SV
url="http://$site/ubuntu-16.04.6-server-i386.template"
# url="http://$site/md5sums.gz"

# url='http://terran.cs.ucr.edu/ubuntu-16.04.6-server-i386.template' #83M
# site='terran'

# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso' #837M
# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template' #83M
# url='http://mirrors.mit.edu/ubuntu/indices/md5sums.gz' #28.5M
# site='mirrors.mit.edu'

# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.iso' #837M
# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.template'
# site='mirror.math.princeton.edu'


nums=(1 2 3)
ranges=(1 2 3 4 5 6 7 8 9 10)
# ackpaces=(250 500 750 1000 1250 1500 1750 2000 2250 2500 2750 3000)

i=0


sed -i "s/define BACKUP_MODE .*/define BACKUP_MODE 0/g" ~/squid_copy/src/optimack/Optimack.cc
sed -i "s/define RANGE_MODE .*/define RANGE_MODE 1/g" ~/squid_copy/src/optimack/Optimack.cc
# sed -i "s/define RANGE_NUM .*/define RANGE_NUM 1/g" ~/squid_copy/src/optimack/range_request.cc
# sed -i "s/define GROUP_NUM .*/define GROUP_NUM 1/g" ~/squid_copy/src/optimack/range_request.cc
j=1
k=1

for ((cnt=0; cnt<3; cnt++)); do
    echo $cnt
    for i in 1 2 3;do # 1 3
        for j in 1 2 4 6 8 12; do #1 2 7 8
            for k in 1 2 3 4; do #3 4 5 6
        #         iptables -F;
                iptables -F -t mangle
                sed -i "s/define CONN_NUM .*/define CONN_NUM ${i}/g" ~/squid_copy/src/optimack/Optimack.cc
                sed -i "s/const int GROUP_NUM = .*;/const int GROUP_NUM = ${j};/g" ~/squid_copy/src/optimack/range_request.cc
                sed -i "s/const int RANGE_NUM = .*;/const int RANGE_NUM = ${k};/g" ~/squid_copy/src/optimack/range_request.cc
                # # sed -i "s/define GROUP_NUM .*/define GROUP_NUM ${j}/g" ~/squid_copy/src/optimack/range_request.cc
                # sed -i "s/define RANGE_NUM .*/define RANGE_NUM ${k}/g" ~/squid_copy/src/optimack/range_request.cc
                # sed -i "s/define RANGE_NUM .*/define RANGE_NUM $((k*4))/g" ~/squid_copy/src/optimack/range_request.cc
                cd ~/squid_copy/
                make install 2&>1 >  /dev/null
                echo
                echo ${i}optim+${j}*${k}range

 
                bash ~/squid_copy/src/optimack/test/ABtest_onerun.sh conn ${i}optim+${j}*${k}range_${cnt}_$1 $site $url
                sudo sh -c 'echo 3 >  /proc/sys/vm/drop_caches'
                sudo sync && echo 1 > /proc/sys/vm/drop_caches
                sleep 60    
            done
        done
    done
done

echo -e "Subject: Test $1 Done\n\n$1 is Done, Please check" | ssmtp zhupengxiong@gmail.com

#achieved bandwidth, consumed bandwidth
#commercial, 8p+1r, 1p+8r, 4p+4r, 2p+6r
#bandwidth: client + server, normalize it to file size, or 1/10 of the tranmx

