#! /bin/bash
# usage: ./test_off_packet.sh [tag]

# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso' #837M
# url='http://mirrors.mit.edu/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.template' #83M
# url='http://mirrors.mit.edu/ubuntu/indices/md5sums.gz' #28.5M
# site='mirrors.mit.edu'

# url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.iso' #837M
url='http://mirror.math.princeton.edu/pub/ubuntu-archive/releases/xenial/ubuntu-16.04.5-server-i386.template'
site='mirror.math.princeton.edu'


mkdir -p ~/rs/vs_domestic_conn/
outdir=~/rs/vs_domestic_conn/$(date +%Y-%m-%d)
mkdir -p $outdir
stime=$(date +%Y%m%d%H%M)
tag=$(hostname)_${site}_http_$1_vs_domestic_conn_${stime}
dom_tag=$(hostname)_mirrors.tuna.tsinghua.edu.cn_http_$1_vs_domestic_conn_${stime}
squid_out=$outdir/curl_squid_${tag}.txt
normal_out=$outdir/curl_normal_${tag}.txt
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
    rm /usr/local/squid/var/logs/cache.log
}


function INT_handler()
{
    cleanup
    exit
}

trap INT_handler SIGINT



screen -dmS squid bash -c "sudo /usr/local/squid/sbin/squid -N"
sleep 2

echo Start: $(date -Iseconds) >> $normal_out
echo Start: $(date -Iseconds) >> $squid_out 
screen -dmS normal bash -c "curl http://mirrors.tuna.tsinghua.edu.cn/ubuntu-releases/16.04/ubuntu-16.04.6-server-i386.iso -o /dev/null 2>&1 | tee -a ${normal_out}"
sleep 10
curl -LJ4vk $url -o /dev/null -x http://127.0.0.1:3128 2>&1 | tee -a ${squid_out}
cleanup

