#! /bin/bash
# usage: ./test_off_packet.sh [tag]

# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso' #837M
# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template' #83M
# url='http://mirrors.mit.edu/ubuntu/indices/md5sums.gz' #28.5M
# site='mirrors.mit.edu'

url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.iso' #837M
# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.template'
site='mirror.math.princeton.edu'


mkdir -p ~/rs/vsAria2/
outdir=~/rs/vsAria2/$(date +%Y-%m-%d)
mkdir -p $outdir
stime=$(date +%Y%m%d%H%M)
tag=$(hostname)_${site}_http_${stime}
squid_out=$outdir/curl_squid_${tag}.txt
normal_out=$outdir/curl_normal_${tag}.txt
aria2_out=$outdir/aria2_${tag}.txt
squid_log=$outdir/squid_log_${tag}.txt


function cleanup()
{
    sudo /usr/local/squid/sbin/squid -k interrupt
    sleep 5
    if screen -ls | grep 'squid'; 
    then
        # exit
        sudo /usr/local/squid/sbin/squid -k kill
    fi
    sudo killall squid
    bash ~/squid_copy/src/optimack/test/ks.sh normal
    sudo iptables -F
    sudo iptables -t mangle -F
}


function INT_handler()
{
    cleanup
    exit
}

trap INT_handler SIGINT


while true;do

    echo Start: $(date -Iseconds) >> $normal_out
    screen -dmS normal bash -c "curl -LJ4vk $url -o /dev/null 2>&1 | tee -a ${normal_out}"

    echo Start: $(date -Iseconds) >> ${aria2_out} 
    aria2c $url -x 10 --continue=false | tee -a ${aria2_out}
    rm -v ubuntu-16.04.5-server-i386.iso*

    bash ~/squid_copy/src/optimack/test/ks.sh normal
    # screen -dmS squid bash -c "sudo /usr/local/squid/sbin/squid -N >> ${squid_log}"
    # sleep 2

    # echo Start: $(date -Iseconds) >> $squid_out 
    # curl -LJ4vk $url -o /dev/null -x http://127.0.0.1:3128 -m 120 2>&1 | tee -a ${squid_out}
    # cleanup
done
