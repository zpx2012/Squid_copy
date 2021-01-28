#include "hping2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <ctime>
#include <sys/time.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <sstream>
using namespace std;

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netlink.h>
#include <libnfnetlink/libnfnetlink.h>

#include "socket.h"
#include "util.h"
#include "checksum.h"
#include "Debug.h"
#include "logging.h"

#include <cstring> // for http parsing
#include <algorithm>

#include "Optimack.h"

#ifndef RANGE_MODE
#define RANGE_MODE 1
#endif

// Utility
double elapsed(std::chrono::time_point<std::chrono::system_clock> start){
    auto now = std::chrono::system_clock::now();
    if (now > start)
        return std::chrono::duration<double>(now - start).count();
    else 
        return 0;
}

bool is_timeout_and_update(std::chrono::time_point<std::chrono::system_clock> &start, double timeout){
    if (elapsed(start) < timeout)
        return false;
    start = std::chrono::system_clock::now();
    return true;        
}

string exec(const char* cmd) {
    char buffer[128];
    std::string result = "";
    FILE* pipe = popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}

template <typename Out>
void split(const std::string &s, char delim, Out result) {
    std::istringstream iss(s);
    std::string item;
    while (std::getline(iss, item, delim)) {
        if(!item.empty())
            *result++ = item;
    }
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);

void*
nfq_loop(void *arg)
{
    int rv;
    char buf[65536];
    //void * placeholder = 0;

    Optimack* obj = (Optimack*)arg;
    log_info("nfq_loop thread starts");
    while (!(obj->nfq_stop)) {
        rv = recv(obj->g_nfq_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (rv >= 0) {
            //debugs(0, DBG_CRITICAL,"%d", rv);
            //hex_dump((unsigned char *)buf, rv);
            //log_debugv("pkt received");
            nfq_handle_packet(obj->g_nfq_h, buf, rv);
        }
        else {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                debugs(0, DBG_CRITICAL,"recv() ret " << rv << " errno " << errno);
                // printf("recv() ret %d errno %d\n", rv, errno);
            }
            usleep(100); //10000
        }
    }
    log_info("nfq_loop thread ends");
    pthread_exit(NULL);
    //return placeholder;
}

void* 
pool_handler(void* arg)
{
    //char log[LOGSIZE];
    struct thread_data* thr_data = (struct thread_data*)arg;
    Optimack* obj = (Optimack*)(thr_data->obj);
    u_int32_t id = thr_data->pkt_id;
    int ret = -1;

    //debugs(0, DBG_CRITICAL, "pool_handler: "<<id);

    short protocol = ip_hdr(thr_data->buf)->protocol;
    if (protocol == 6)
        ret = obj->process_tcp_packet(thr_data);
    else{ 
        //sprintf(log, "Invalid protocol: 0x%04x, len %d", protocol, thr_data->len);
        //debugs(0, DBG_CRITICAL, log);
        struct myiphdr *iphdr = ip_hdr(thr_data->buf);
        // struct mytcphdr *tcphdr = tcp_hdr(thr_data->buf);

        //unsigned char *payload = tcp_payload(thr_data->buf);
        // unsigned int payload_len = thr_data->len - iphdr->ihl*4 - tcphdr->th_off*4;
        char sip[16], dip[16];
        ip2str(iphdr->saddr, sip);
        ip2str(iphdr->daddr, dip);

        //memset(log, 0, LOGSIZE);
        //sprintf(log, "%s:%d -> %s:%d <%s> seq %x ack %x ttl %u plen %d", sip, ntohs(tcphdr->th_sport), dip, ntohs(tcphdr->th_dport), tcp_flags_str(tcphdr->th_flags), tcphdr->th_seq, tcphdr->th_ack, iphdr->ttl, payload_len);
        //debugs(0, DBG_CRITICAL, log);
        char* hex_str = hex_dump_str(thr_data->buf, thr_data->len);
        //debugs(0, DBG_CRITICAL, hex_str);
        free(hex_str);
    }

    if (ret == 0){
        nfq_set_verdict(obj->g_nfq_qh, id, NF_ACCEPT, thr_data->len, thr_data->buf);
        //debugs(0, DBG_CRITICAL, "Verdict: Accept");
    }
    else{
        nfq_set_verdict(obj->g_nfq_qh, id, NF_DROP, 0, NULL);
        //debugs(0, DBG_CRITICAL, "Verdict: Drop");
    }

    free(thr_data->buf);
    free(thr_data);
    // TODO: ret NULL?
    return NULL;
}

void adjust_optimack_speed(struct subconn_info* conn, int id, int mode, int offset){
    //mode: 1 - speedup, -1 - slowdown
    if(conn->ack_pacing > 500 && conn->ack_pacing - offset > 10){
        conn->ack_pacing -= mode*offset;
        if(mode == 1)
            printf("S%d: adjust - speed up by ack_interval by %d to %d!\n", id, offset, conn->ack_pacing);
        else if(mode == -1)
            printf("S%d: adjust - slow down by ack_interval by %d to %d!\n", id, offset, conn->ack_pacing);
        else
            printf("S%d: unknown mode!\n", id);
    }
    else {
        conn->payload_len += mode*offset;
        if(mode == 1)
            printf("S%d: adjust - speed up by ack_pace by %d to %d!\n", id, offset, conn->ack_pacing);
        else if(mode == -1)
            printf("S%d: adjust - slow down by ack_pace by %d to %d!\n", id, offset, conn->ack_pacing);
        else
            printf("S%d: unknown mode!\n", id);    }
}

void adjust_optimack_speed_by_ack_interval(struct subconn_info* conn, int id, int offset)
{
    if(conn->ack_pacing - offset > 10){
        conn->ack_pacing -= offset;
        printf("S%d: speed up by ack_interval by %d to %d!\n", id, offset, conn->ack_pacing);
    }
}

void adjust_optimack_speed_by_ack_step(struct subconn_info* conn, int id, int offset)
{
    conn->payload_len += offset;
    printf("S%d: speed up by ack_step by %d to %d!\n", id, offset, conn->payload_len);
}


#ifndef SPEEDUP_CONFIG
#define SPEEDUP_CONFIG 0
#endif

#ifndef SLOWDOWN_CONFIG
#define SLOWDOWN_CONFIG 0
#endif

#ifndef DEBUG_PRINT_LEVEL
#define DEBUG_PRINT_LEVEL 0
#endif

bool Optimack::does_packet_lost_on_all_conns(){
    // Packet lost on all connections
    bool is_all_lost = true;
    
    log_debugv("does_packet_lost_on_all_conns: mutex_seq_gaps - trying lock"); 
    pthread_mutex_lock(&mutex_seq_gaps);
    for(size_t i = 1; i < subconn_infos.size(); i++){
        // printf("cur_seq_rem %u, cur_ack_rel %u, payload_len %u\n", subconn_infos[i].cur_seq_rem, cur_ack_rel, subconn_infos[0].payload_len);
        if ( (!seq_gaps.empty() && subconn_infos[i].cur_seq_rem < seq_gaps.at(0).start) || subconn_infos[i].cur_seq_rem <= cur_ack_rel){//Why seq_gaps? because squid might drop some packets forwarded to it
            if (subconn_infos[i].cur_seq_rem != subconn_infos[i].last_cur_seq_rem){
                log_debug("S%u: cur_seq_rem %u, seq_gaps[0].start %u", i, subconn_infos[i].cur_seq_rem, seq_gaps[0].start);  
                subconn_infos[i].last_cur_seq_rem = subconn_infos[i].cur_seq_rem;
            }
            is_all_lost = false;
            break;
        }
        else if(!seq_gaps.empty() && subconn_infos[i].cur_seq_rem == seq_gaps.at(0).start){
            log_error("S%u: Didn't remove [%u, %u], cur_seq_rem %u", i, seq_gaps[0].start, seq_gaps[0].end, subconn_infos[i].cur_seq_rem);
        }
    }

    if (is_all_lost){
        std::string rst_str = exec("cat /proc/net/netfilter/nfnetlink_queue");
        cout << "cat /proc/net/netfilter/nfnetlink_queue:\n " << rst_str << endl;
        std::vector<std::string> fields = split(rst_str, ' ');
        if(fields.size() > 7){
            if(fields.at(5) != "0" || fields.at(6) != "0"){
                printf("\n\n###################\nNetfilter Queue too full!\n###################\n");
                exit(-1);
            }
        }
        else
            printf("Error! nfnetlink_queue result is shorter than 7 fields!");

        printf("\n\n###################\nPacket lost on all connections. \n###################\n\nlast ack:%d\n", cur_ack_rel);
        for(size_t i = 1; i < subconn_infos.size(); i++){
            printf("S%d: %d\n", i, subconn_infos[i].cur_seq_rem);
        }
        if(seq_gaps[0].start < cur_ack_rel){
            printf("ACK packet, gap removal wrong!!!\n");
        }
        printIntervals(seq_gaps);
        // for (int i = 0; i < seq_gaps.size(); i++)
        //     log_debugv("[%u, %u], ", seq_gaps[i].start, seq_gaps[i].end);

        // logIntervals(seq_gaps, )
        sleep(5);
        exit(-1);
    }
    pthread_mutex_unlock(&mutex_seq_gaps);
    log_debugv("does_packet_lost_on_all_conns: mutex_seq_gaps - unlock"); 
    
    return is_all_lost;    
}


void* overrun_detector(void* arg){
    Optimack* obj = (Optimack* )arg;
    uint num_conns = obj->subconn_infos.size(), timeout = 3;
    uint *last_seq_rems = new uint[num_conns];
    // std::chrono::time_point<std::chrono::system_clock> *timers = new std::chrono::time_point<std::chrono::system_clock>[num_conns];

    sleep(10);//Wait for the packets to come
    log_info("Start overrun_detector thread");

    for(uint i = 0; i < num_conns; i++){
        last_seq_rems[i] = 0;
        obj->subconn_infos[i].last_restart_time = std::chrono::system_clock::now();
    }

    while(!obj->overrun_stop){
        for(uint i = 0; i < num_conns; i++){
            struct subconn_info* subconn = &obj->subconn_infos[i];
            if(!subconn->cur_seq_rem)
                continue;
            if(last_seq_rems[i] != subconn->cur_seq_rem){
                last_seq_rems[i] = subconn->cur_seq_rem;
                subconn->last_restart_time = std::chrono::system_clock::now();
            }
            else if (is_timeout_and_update(subconn->last_restart_time, timeout)){
                //Restart
                printf("S%d: idle for %ds from %u\n", i, timeout, subconn->cur_seq_rem); 
                obj->restart_optim_ack(i, subconn->cur_seq_rem+subconn->ini_seq_rem, subconn->cur_seq_loc, subconn->payload_len, subconn->cur_seq_rem, subconn->last_restart_time);
                // obj->subconn_infos[i].last_restart_time += std::chrono::seconds(5);
            }
        }
        sleep(1);
    }
    free(last_seq_rems);
    // free(timers);
    log_info("ovverrun_detector thread ends");
    pthread_exit(NULL);
}


void* 
optimistic_ack(void* arg)
{
    struct int_thread* ack_thr = (struct int_thread*)arg;
    int id = ack_thr->thread_id;
    Optimack* obj = ack_thr->obj;
    struct subconn_info* conn = &(obj->subconn_infos[id]);
    // unsigned int ack_step = conn->payload_len;
    unsigned int opa_seq_start = conn->opa_seq_start;
    unsigned int opa_ack_start = conn->opa_ack_start;
    unsigned int local_port = conn->local_port;
    // unsigned int ack_pacing = conn->ack_pacing;

    free(ack_thr);

    //debugs(1, DBG_CRITICAL, "S" << id << ": Optim ack starts");
    char empty_payload[] = "";
    log_info("S%d: optimistic ack started", id);   
    // unsigned int last_speedup_ack = 0;
    int cur_win_scale = 0;
    auto last_adjust_rwnd_write = std::chrono::system_clock::now(), last_zero_window = std::chrono::system_clock::now();
    bool is_zero_window = true;
    // for (unsigned int k = opa_ack_start; !conn->optim_ack_stop; k += conn->payload_len) {
    while (!conn->optim_ack_stop) {
        cur_win_scale = (obj->cur_ack_rel + obj->rwnd - opa_ack_start + conn->ini_seq_rem) / 2048;
        // if (elapsed(last_adjust_rwnd_write) >= 1){
        //     fprintf(obj->adjust_rwnd_file, "%s, %u\n", obj->cur_time.time_in_HH_MM_SS_US(), cur_win_scale);
        //     last_adjust_rwnd_write = std::chrono::system_clock::now();
        // }
        if (cur_win_scale < 1) {
            if (is_timeout_and_update(last_adjust_rwnd_write, 2)){
                log_debug("O%d: cur_win_scale == 0", id);
            }
            if (!is_zero_window){
                last_zero_window = std::chrono::system_clock::now();
                is_zero_window = true;
            }
            if (elapsed(last_zero_window) >= 10){
                obj->does_packet_lost_on_all_conns();
                // printIntervals(obj->seq_gaps);
            }
            sleep(1);
            continue;
        }
        is_zero_window = false;
        send_ACK(obj->g_remote_ip, obj->g_local_ip, obj->g_remote_port, local_port, empty_payload, opa_ack_start, opa_seq_start, cur_win_scale);
        log_debug("O%d: ack %u, seq %u, win_scaled %d", id, opa_ack_start - conn->ini_seq_rem, opa_seq_start - conn->ini_seq_loc, cur_win_scale);
        opa_ack_start += conn->payload_len;

        // TODO: casue BUG in local machine
        if(!id)
            fprintf(obj->ack_file, "%s, %u\n", obj->cur_time.time_in_HH_MM_SS_US(), opa_ack_start - conn->ini_seq_rem);

        if (SPEEDUP_CONFIG){
            if(conn->cur_seq_rem-opa_ack_start > 1460*100 && conn->cur_seq_rem > opa_ack_start && obj->subconn_infos[0].off_pkt_num < 1 && elapsed(obj->last_speedup_time) > 10){
                log_debugv("optimistic_ack: mutex_subconn_infos - tring lock");
                pthread_mutex_lock(&obj->mutex_subconn_infos);
                if(conn->cur_seq_rem-opa_ack_start > 1460*100 && conn->cur_seq_rem > opa_ack_start && obj->subconn_infos[0].off_pkt_num < 1 && elapsed(obj->last_speedup_time) > 10){
                    for (int i = 0; i < obj->subconn_infos.size(); i++)
                        adjust_optimack_speed(&(obj->subconn_infos[i]), i, 1, 10);//low frequence
                    obj->last_speedup_ack_rel = opa_ack_start - conn->ini_seq_rem;
                    obj->last_speedup_time = std::chrono::system_clock::now();
                }
                pthread_mutex_unlock(&obj->mutex_subconn_infos);
                log_debugv("optimistic_ack: mutex_subconn_infos - unlock");
            }
        }
        usleep(conn->ack_pacing);
    }
    // TODO: why 0???
    conn->optim_ack_stop = 0;
    log_info("S%d: optimistic ack ends", id);
    //debugs(1, DBG_CRITICAL, "S" << id << ": Optim ack ends");
    pthread_exit(NULL);
}

int 
Optimack::start_optim_ack(int id, unsigned int opa_ack_start, unsigned int opa_seq_start, unsigned int payload_len, unsigned int seq_max)
{
    subconn_infos[id].opa_seq_start = opa_seq_start;
    subconn_infos[id].opa_ack_start = opa_ack_start;
    subconn_infos[id].opa_seq_max_restart = seq_max;
    subconn_infos[id].opa_retrx_counter = 0;
    subconn_infos[id].payload_len = payload_len;
    // set to running
    subconn_infos[id].optim_ack_stop = 0;

    // ack thread data
    // TODO: Remember to free in cleanup
    struct int_thread* ack_thr = (struct int_thread*)malloc(sizeof(struct int_thread));
    if (!ack_thr)
    {
        debugs(0, DBG_CRITICAL, "optimistic_ack: error during thr_data malloc");
        return -1;
    }
    memset(ack_thr, 0, sizeof(struct int_thread));
    ack_thr->thread_id = id;
    ack_thr->obj = this;

    if (pthread_create(&(subconn_infos[id].thread), NULL, optimistic_ack, (void *)ack_thr) != 0) {
        //debugs(0, DBG_CRITICAL, "Fail to create optimistic_ack thread");
        printf("S%d: Fail to create optimistic_ack thread\n", id);
        return -1;
    }
    //debugs(1, DBG_CRITICAL, "S" << id <<": optimistic ack thread created");   
    // printf("S%d: optimistic ack thread created\n", id);
    return 0;
}

int Optimack::restart_optim_ack(int id, unsigned int opa_ack_start, unsigned int opa_seq_start, unsigned int payload_len, unsigned int seq_max, std::chrono::time_point<std::chrono::system_clock> &timer)
{
    struct subconn_info* subconn = &subconn_infos[id];
    uint seq_rel = opa_ack_start - subconn->ini_seq_rem;

    subconn->optim_ack_stop = 1;
    subconn->ack_pacing += 10;
    pthread_join(subconn->thread, NULL);
    printf("S%d: Restart optim ack from %u\n\n", id, seq_rel);
    log_info("S%d: Restart optim ack from %u", id, seq_rel);
    start_optim_ack(id, opa_ack_start, opa_seq_start, payload_len, seq_max);//subconn->cur_seq_rem
    timer += std::chrono::seconds(2);
}

void
Optimack::cleanup()
{
    // stop other optimistic_ack threads and close fd
    for (size_t i=1; i < subconn_infos.size(); i++) {
        // TODO: mutex?
        subconn_infos[i].optim_ack_stop = 1;
        pthread_join(subconn_infos[i].thread, NULL);
        close(subconn_infos[i].sockfd);
    }
    log_info("NFQ %d all optimistic threads exited", nfq_queue_num);
    subconn_infos.clear();
    // clear iptables rules
    for (size_t i=0; i<iptables_rules.size(); i++) {
        exec_iptables('D', iptables_rules[i]);
        free(iptables_rules[i]);
    }
    iptables_rules.clear();
    request_recved = false;
}

Optimack::~Optimack()
{
    // stop nfq_loop thread
    nfq_stop = 1;
    pthread_join(nfq_thread, NULL);
    log_info("NFQ %d nfq_thread exited", nfq_queue_num);

    overrun_stop = 1;
    pthread_join(overrun_thread, NULL);
    log_info("overrun_thread exited");

    // clear thr_pool
    thr_pool_destroy(pool);

    cleanup();

    teardown_nfq();
    pthread_mutex_destroy(&mutex_seq_next_global);
    pthread_mutex_destroy(&mutex_seq_gaps);
    pthread_mutex_destroy(&mutex_subconn_infos);
    pthread_mutex_destroy(&mutex_optim_ack_stop);
}

void
Optimack::init()
{
    // init random seed
    srand(time(NULL));

    init_log();
    init_exp_log("/root/rs/exp.log");

    // initializing globals
    sockraw = open_sockraw();
    if (setsockopt(sockraw, SOL_SOCKET, SO_MARK, &MARK, sizeof(MARK)) < 0)
    {
        debugs(0, DBG_CRITICAL, "couldn't set mark");
        exit(1);
    }

    int portno = 80;
    sockpacket = open_sockpacket(portno);
    if (sockpacket == -1) {
        debugs(0, DBG_CRITICAL, "[main] can't open packet socket");
        exit(EXIT_FAILURE);
    }
    //if (signal(SIGINT, signal_handler) == SIG_ERR) {
        //log_error("register SIGINT handler failed.\n");
        //exit(EXIT_FAILURE);
    //}
    //if (signal(SIGSEGV, signal_handler) == SIG_ERR) {
        //log_error("register SIGSEGV handler failed.");
        //exit(EXIT_FAILURE);
    //}
    //if (signal(SIGPIPE, signal_handler) == SIG_ERR) {
        //log_error("register SIGPIPE handler failed.");
        //exit(EXIT_FAILURE);
    //}

    pool = thr_pool_create(4, 16, 300, NULL);
    if (!pool) {
            debugs(0, DBG_CRITICAL, "couldn't create thr_pool");
            exit(1);                
    }
    // char log_file_name[100];
    // sprintf(log_file_name, "/root/off_packet_%s.csv", cur_time.time_in_HH_MM_SS());
    log_file = fopen("/root/rs/off_packet.csv", "w");
    fprintf(log_file, "time,off_packet_num\n");

    rwnd_file = fopen("/root/rs/rwnd.csv", "w");
    fprintf(rwnd_file, "time,rwnd\n");

    adjust_rwnd_file = fopen("/root/rs/adjust_rwnd.csv", "w");
    fprintf(adjust_rwnd_file, "time,adjust_rwnd\n");

    seq_file = fopen("/root/rs/seq.csv", "w");
    fprintf(seq_file, "time,seq_num\n");

    ack_file = fopen("/root/rs/ack.csv", "w");
    fprintf(ack_file, "time,ack_num\n");

    last_speedup_time = last_rwnd_write_time = last_restart_time = std::chrono::system_clock::now();

    nfq_stop = overrun_stop = 1;
}

int 
Optimack::setup_nfq(unsigned short id)
{
    g_nfq_h = nfq_open();
    if (!g_nfq_h) {
        debugs(0, DBG_CRITICAL,"error during nfq_open()");
        return -1;
    }

    debugs(0, DBG_CRITICAL,"unbinding existing nf_queue handler for AF_INET (if any)");
    if (nfq_unbind_pf(g_nfq_h, AF_INET) < 0) {
        debugs(0, DBG_CRITICAL,"error during nfq_unbind_pf()");
        return -1;
    }

    debugs(0, DBG_CRITICAL,"binding nfnetlink_queue as nf_queue handler for AF_INET");
    if (nfq_bind_pf(g_nfq_h, AF_INET) < 0) {
        debugs(0, DBG_CRITICAL,"error during nfq_bind_pf()");
        return -1;
    }

    // set up a queue
    nfq_queue_num = id;
    debugs(0, DBG_CRITICAL,"binding this socket to queue " << nfq_queue_num);
    g_nfq_qh = nfq_create_queue(g_nfq_h, nfq_queue_num, &cb, (void*)this);
    if (!g_nfq_qh) {
        debugs(0, DBG_CRITICAL,"error during nfq_create_queue()");
        return -1;
    }
    debugs(0, DBG_CRITICAL,"nfq queue handler: " << g_nfq_qh);

    debugs(0, DBG_CRITICAL,"setting copy_packet mode");
    if (nfq_set_mode(g_nfq_qh, NFQNL_COPY_PACKET, 0x0fff) < 0) {
        debugs(0, DBG_CRITICAL,"can't set packet_copy mode");
        return -1;
    }

    unsigned int bufsize = 0x3fffffff, rc = 0;//
    if (nfq_set_queue_maxlen(g_nfq_qh, bufsize/1024) < 0) {
        debugs(0, DBG_CRITICAL,"error during nfq_set_queue_maxlen()\n");
        return -1;
    }
    struct nfnl_handle* nfnl_hl = nfq_nfnlh(g_nfq_h);
    // for (; ; bufsize-=0x1000){
    //     rc = nfnl_rcvbufsiz(nfnl_hl, bufsize);
    //     printf("Buffer size %x wanted %x\n", rc, bufsize);
    //     if (rc == bufsize*2)
    //         break;
    // }
    rc = nfnl_rcvbufsiz(nfnl_hl, bufsize);
    log_info("Buffer size %x wanted %x", rc, bufsize*2);
    if(rc != bufsize*2){
        exit(-1);
    }

    g_nfq_fd = nfq_fd(g_nfq_h);

    return 0;
}

int 
Optimack::setup_nfqloop()
{
    // pass the Optimack obj
    nfq_stop = 0;
    if (pthread_create(&nfq_thread, NULL, nfq_loop, (void*)this) != 0) {
        debugs(1, DBG_CRITICAL,"Fail to create nfq thread.");
        return -1;
    }
    return 0;
}

int 
Optimack::teardown_nfq()
{
    debugs(0, DBG_CRITICAL,"unbinding from queue " << nfq_queue_num);
    if (nfq_destroy_queue(g_nfq_qh) != 0) {
        debugs(0, DBG_CRITICAL,"error during nfq_destroy_queue()");
        return -1;
    }

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    debugs(0, DBG_CRITICAL,"unbinding from AF_INET");
    nfq_unbind_pf(g_nfq_h, AF_INET);
#endif

    debugs(0, DBG_CRITICAL,"closing library handle");
    if (nfq_close(g_nfq_h) != 0) {
        debugs(0, DBG_CRITICAL,"error during nfq_close()");
        return -1;
    }

    return 0;
}

static int 
cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    Optimack* obj = (Optimack*)data;
    unsigned char* packet;
    int packet_len = nfq_get_payload(nfa, &packet);

    struct myiphdr *iphdr = ip_hdr(packet);
    // struct mytcphdr *tcphdr = tcp_hdr(packet);
    //unsigned char *payload = tcp_payload(thr_data->buf);
    // unsigned int payload_len = packet_len - iphdr->ihl*4 - tcphdr->th_off*4;
    char sip[16], dip[16];
    ip2str(iphdr->saddr, sip);
    ip2str(iphdr->daddr, dip);

    //char log[LOGSIZE];
    //sprintf(log, "%s:%d -> %s:%d <%s> seq %x ack %x ttl %u plen %d", sip, ntohs(tcphdr->th_sport), dip, ntohs(tcphdr->th_dport), tcp_flags_str(tcphdr->th_flags), tcphdr->th_seq, tcphdr->th_ack, iphdr->ttl, payload_len);
    //debugs(0, DBG_CRITICAL, log);

    struct thread_data* thr_data = (struct thread_data*)malloc(sizeof(struct thread_data));
    if (!thr_data)
    {
        debugs(0, DBG_CRITICAL, "cb: error during thr_data malloc");
        return -1;
    }
    memset(thr_data, 0, sizeof(struct thread_data));

    // sanity check, could be abbr later
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    // printf("P%d: hook %d\n", ph->packet_id, ph->hook);
    if (!ph) {
        debugs(0, DBG_CRITICAL,"nfq_get_msg_packet_hdr failed");
        return -1;
    }

    thr_data->pkt_id = htonl(ph->packet_id);
    thr_data->len = packet_len;
    thr_data->buf = (unsigned char *)malloc(packet_len);
    thr_data->obj = obj;
    if (!thr_data->buf){
            debugs(0, DBG_CRITICAL, "cb: error during malloc");
            return -1;
    }
    memcpy(thr_data->buf, packet, packet_len);
    // printf("in cb: packet_len %d\nthr_data->buf", packet_len);
    // hex_dump(thr_data->buf, packet_len);
    // printf("packet:\n");
    // hex_dump(packet, packet_len);

    // pool_handler((void *)thr_data);
    if(thr_pool_queue(obj->pool, pool_handler, (void *)thr_data) < 0) {
        debugs(0, DBG_CRITICAL, "cb: error during thr_pool_queue");
        return -1;
    }
    return 0;
}

const char header_field[] = "HTTP/1.1 206";
const char range_field[] = "Content-Range: bytes ";
const char tail_field[] = "\r\n\r\n";
const char keep_alive_field[] = "Keep-Alive: ";
const char max_field[] = "max=";

struct http_header {
    int parsed;
    int remain;
    int start;
    int end;
};

int
parse_response(http_header *head, char *response, int unread)
{
    char *recv_end = response + unread;
    char *parse_head;
    if (head->parsed) {
        log_debug("[Range] error: header should have been parsed");
        return -1;
    }
    // check header
    parse_head = std::search(response, recv_end, header_field, header_field+12);
    if (parse_head < recv_end) {
        // check range
        parse_head = std::search(parse_head, recv_end, range_field, range_field+21);
        if (parse_head < recv_end) {
            parse_head += 21;
            head->start = (int)strtol(parse_head, &parse_head, 10);
            parse_head++;
            head->end = (int)strtol(parse_head, &parse_head, 10);
            head->remain = head->end - head->start + 1;
            parse_head = std::search(parse_head, recv_end, tail_field, tail_field+4);
            if (parse_head < recv_end) {
                parse_head += 4;
                head->parsed = 1;
                log_debug("[Range] Header received %d - %d", head->start, head->end);
                return parse_head-response;
            }
        }
    }
    return 0;
}

void*
range_watch(void* arg)
{
    int rv, range_sockfd, local_port, remote_port, seq_offset, seq_loc;
    char response[MAX_RANGE_SIZE];
    char data[MAX_RANGE_SIZE];
    char *local_ip, *remote_ip;
    bool req_max_get = false;

    Optimack* obj = ((struct int_thread*)arg)->obj;
    range_sockfd = ((struct int_thread*)arg)->thread_id;
    local_ip = obj->g_local_ip;
    remote_ip = obj->g_remote_ip;
    local_port = obj->subconn_infos[0].local_port;
    remote_port = obj->g_remote_port;
    seq_offset = obj->subconn_infos[0].ini_seq_rem;
    seq_loc = obj->subconn_infos[0].cur_seq_loc;

    int consumed=0, unread=0, parsed=0, offset=0, recv_offset=0;
    http_header* header = (http_header*)malloc(sizeof(http_header));
    memset(header, 0, sizeof(http_header));
    char *tmp;

    do {
        // blocking sock
        memset(response+recv_offset, 0, MAX_RANGE_SIZE-recv_offset);
        rv = recv(range_sockfd, response+recv_offset, MAX_RANGE_SIZE-recv_offset, 0);
        if (rv > 0) {
            unread += rv;
            consumed = 0;

            if (!req_max_get) {
                //range = strstr(response, "Keep-Alive: ");
                tmp = std::search(response, response+unread, keep_alive_field, keep_alive_field+12);
                if (tmp < response+unread) {
                    //body = strstr(range, "max=");
                    tmp = std::search(tmp, response+unread, max_field, max_field+4);
                    if (tmp < response+unread) {
                        tmp += 4;
                        pthread_mutex_lock(&(obj->mutex_req_max));
                        obj->req_max += (int)strtol(tmp, &tmp, 10);
                        pthread_mutex_unlock(&(obj->mutex_req_max));
                        req_max_get = true;
                    }
                }
            }

            while (unread > 0) {
                if (header->parsed) {
                    // collect data
                    if (header->remain <= unread) {
                        // we have all the data
                        memcpy(data+offset, response+consumed, header->remain);
                        header->parsed = 0;
                        unread -= header->remain;
                        consumed += header->remain;
                        offset = 0;
                        send_ACK_payload(local_ip, remote_ip, local_port, remote_port, data, \
                                header->end - header->start + 1, seq_loc, seq_offset + header->start);
                        log_debug("[Range] retrieved %d - %d", header->start, header->end);
                    }
                    else {
                        // still need more data
                        memcpy(data+offset, response+consumed, unread); 
                        header->remain -= unread;
                        consumed += unread;
                        unread = 0;
                        offset += unread;
                    }
                }
                else {
                    // parse header
                    parsed = parse_response(header, response+consumed, unread);
                    if (parsed <= 0) {
                        // incomplete http header
                        // keep receiving and parse in next response
                        memmove(response, response+consumed, unread);
                        recv_offset += unread;
                        break;
                    }
                    else {
                        recv_offset = 0;
                        consumed += parsed;
                        unread -= parsed;
                    }
                }
            }
            // TODO: debug
            if (unread < 0)
                log_debug("[Range] error: unread < 0");
        }
        else if (rv < 0)
            log_debug("[Range] error: ret %d errno %d", rv, errno);
    } while (rv > 0);

    // sock is closed
    close(range_sockfd);
    pthread_exit(NULL);
}

int
Optimack::init_range()
{
    pthread_t range_thread;
    int range_sockfd;
    struct sockaddr_in server_addr;

    // Open socket
    if ((range_sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Can't open stream socket.");
    }

    // Set server_addr
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(g_remote_ip);
    server_addr.sin_port = htons(g_remote_port);

    // Connect to server
    if (connect(range_sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connect server error");
        close(range_sockfd);
    }

    // range thread data
    struct int_thread* range_thr = (struct int_thread*)malloc(sizeof(struct int_thread));
    if (!range_thr)
    {
        debugs(0, DBG_CRITICAL, "init_range: error during thr_data malloc");
        return -1;
    }
    memset(range_thr, 0, sizeof(struct int_thread));
    range_thr->thread_id = range_sockfd;
    range_thr->obj = this;

    if (pthread_create(&range_thread, NULL, range_watch, (void *)range_thr) != 0) {
        //debugs(0, DBG_CRITICAL, "Fail to create optimistic_ack thread");
        perror("Can't create range_watch thread\n");
        return -1;
    }

    return range_sockfd;
}

int 
Optimack::process_tcp_packet(struct thread_data* thr_data)
{
    char log[LOGSIZE];

    struct myiphdr *iphdr = ip_hdr(thr_data->buf);
    struct mytcphdr *tcphdr = tcp_hdr(thr_data->buf);
    unsigned char *payload = tcp_payload(thr_data->buf);
    unsigned int payload_len = htons(iphdr->tot_len) - iphdr->ihl*4 - tcphdr->th_off*4;
    unsigned short sport = ntohs(tcphdr->th_sport);
    unsigned short dport = ntohs(tcphdr->th_dport);
    unsigned int seq = htonl(tcphdr->th_seq);
    unsigned int ack = htonl(tcphdr->th_ack);

    // printf("right in process_tcp_packet\n");
    // hex_dump(payload, payload_len);

    // check remote ip, local ip
    // and set key_port
    bool incoming = true;
    int subconn_i = -1;
    char *sip, *dip;
    if (g_remote_ip_int == iphdr->saddr) {
        incoming = true;
        sip = g_remote_ip;
        dip = g_local_ip;
        log_debugv("P%d: process_tcp_packet:640: mutex_subconn_infos - trying lock", thr_data->pkt_id); 
        pthread_mutex_lock(&mutex_subconn_infos);
        for (size_t i = 0; i < subconn_infos.size(); i++)
            if (subconn_infos[i].local_port == dport) {
                subconn_i = (int)i;
                break;
            }
        pthread_mutex_unlock(&mutex_subconn_infos);
        log_debugv("P%d: process_tcp_packet:640: mutex_subconn_infos - unlock", thr_data->pkt_id); 
    }
    else if (g_remote_ip_int == iphdr->daddr) {
        incoming = false;
        sip = g_local_ip;
        dip = g_remote_ip;
        log_debugv("P%d: process_tcp_packet:654: mutex_subconn_infos - trying lock", thr_data->pkt_id); 
        pthread_mutex_lock(&mutex_subconn_infos);
        for (size_t i = 0; i < subconn_infos.size(); i++)
            if (subconn_infos[i].local_port == sport) {
                subconn_i = (int)i;
                break;
            }
        pthread_mutex_unlock(&mutex_subconn_infos);
        log_debugv("P%d: process_tcp_packet:654: mutex_subconn_infos - unlock", thr_data->pkt_id); 
    }
    if (subconn_i == -1) {
        char sip_[16], dip_[16];
        ip2str(iphdr->saddr, sip_);
        ip2str(iphdr->daddr, dip_);
        sprintf(log, "P%d: ERROR - IP or Subconn not found: %s:%d -> %s:%d <%s> seq %x ack %x ttl %u plen %d", thr_data->pkt_id, sip_, ntohs(tcphdr->th_sport), dip_, ntohs(tcphdr->th_dport), tcp_flags_str(tcphdr->th_flags), tcphdr->th_seq, tcphdr->th_ack, iphdr->ttl, payload_len);
        printf("%s\n", log);
        return -1;
    }

    subconn_info* subconn = &subconn_infos[subconn_i];

    // Outgoing Packets
    if (!incoming) 
    {   
        switch (tcphdr->th_flags) {
            case TH_ACK:
            case TH_ACK | TH_PUSH:
            case TH_ACK | TH_URG:
                {
                    // init seq and ack if haven't
                    if (!subconn->seq_init && payload_len) {
                        log_debugv("P%d-S%d-out: process_tcp_packet:685: subconn->mutex_opa - trying lock", thr_data->pkt_id, subconn_i); 
                        pthread_mutex_lock(&subconn->mutex_opa);
                        if (!subconn->seq_init && payload_len) {
                            subconn->ini_seq_rem = ack - 1;
                            subconn->cur_seq_rem = 1;
                            subconn->ini_seq_loc = seq - 1;
                            subconn->seq_init = true;
                            log_info("Subconn %d seq_init done", subconn_i);
                            // reply to our send()
                            if (subconn_i) {
                                char empty_payload[] = "";
                                send_ACK(sip, dip, sport, dport, empty_payload, seq+payload_len, ack);
                            }
                        }
                        pthread_mutex_unlock(&subconn->mutex_opa);
                        log_debugv("P%d-S%d-out: process_tcp_packet:685: subconn->mutex_opa - unlock", thr_data->pkt_id, subconn_i); 
                        // TODO: should we drop if subconn_i==0 ?
                        return -1;
                    }

                    if (subconn_i == 0) {
                        rwnd = ntohs(tcphdr->th_win) * win_scale;                            
                        if(rwnd > max_win_size)
                            max_win_size = rwnd;
                        cur_ack_rel = ack - subconn_infos[0].ini_seq_rem;

                        log_debugv("P%d-S%d-out: process_tcp_packet:710: mutex_cur_ack_rel - trying lock", thr_data->pkt_id, subconn_i); 
                        pthread_mutex_lock(&mutex_cur_ack_rel);
                        if (cur_ack_rel == last_ack_rel){
                            same_ack_cnt++;
                            if(SLOWDOWN_CONFIG){
                                if(same_ack_cnt >= 4){
                                    bool can_slow_down = false;
                                    unsigned int interval = 100, dup = 100;
                                    if (cur_ack_rel - last_slowdown_ack_rel > subconn_infos[0].payload_len*interval){
                                        same_ack_cnt = 0;
                                        can_slow_down = true;
                                        printf("P%d-Squid-out: can slow down, new ack with interval %d\n", thr_data->pkt_id, interval);
                                    }
                                    else if( last_slowdown_ack_rel == cur_ack_rel && same_ack_cnt % dup == 0){
                                        can_slow_down = true;
                                        printf("P%d-Squid-out: can slow down, dup ack %d\n", thr_data->pkt_id, same_ack_cnt);
                                    }

                                    if(can_slow_down){
                                        for (size_t i=1; i<subconn_infos.size(); i++)
                                            adjust_optimack_speed(&subconn_infos[i], i, -1, 100);
                                        last_slowdown_ack_rel = cur_ack_rel;
                                    }
                                }
                            }
                        }
                        else{
                            log_debugv("P%d-S%d-out: process_tcp_packet:737: mutex_seq_gaps - trying lock", thr_data->pkt_id, subconn_i); 
                            pthread_mutex_lock(&mutex_seq_gaps);
                            if(!seq_gaps.empty()){
                                // printf("P%d-Squid-out: trying to remove 1-%u\nBefore removing:\n", thr_data->pkt_id, cur_ack_rel);
                                seq_gaps = removeInterval(seq_gaps, Interval(1, cur_ack_rel)); //packet received from subconn 0
                                if (!seq_gaps.empty() && seq_gaps.at(0).start < cur_ack_rel) {
                                    log_error("P%d-Squid-out: Not removing correctly", thr_data->pkt_id);
                                    printIntervals(seq_gaps);
                                }
                            }
                            pthread_mutex_unlock(&mutex_seq_gaps);
                            log_debugv("P%d-S%d-out: process_tcp_packet:737: mutex_seq_gaps - unlock", thr_data->pkt_id, subconn_i); 
                            last_ack_rel = cur_ack_rel;
                        }
                        pthread_mutex_unlock(&mutex_cur_ack_rel);
                        log_debugv("P%d-S%d-out: process_tcp_packet:710: mutex_cur_ack_rel - unlock", thr_data->pkt_id, subconn_i); 

                        // if (elapsed(last_rwnd_write_time) >= 1){
                        //     fprintf(rwnd_file, "%s, %u\n", cur_time.time_in_HH_MM_SS_US(), ntohs(tcphdr->th_win)*2048);
                        //     last_rwnd_write_time = std::chrono::system_clock::now();
                        // }                       

                        if (!payload_len) {                            
                            if (subconn_infos[0].payload_len && seq_next_global > cur_ack_rel) { ////packet received from subconn 0
                                float off_packet_num = (seq_next_global-cur_ack_rel)/subconn_infos[0].payload_len;
                                subconn_infos[0].off_pkt_num = off_packet_num;

                                // if (last_ack_rel != cur_ack_rel) {
                                if (last_off_packet != off_packet_num) {
                                    log_debug("P%d-Squid-out: squid ack %d, seq_global %d, off %.2f packets, win_size %d, max win_size %d", thr_data->pkt_id, cur_ack_rel, seq_next_global, off_packet_num, rwnd, max_win_size);
                                    // fprintf(log_file, "%s, %.2f\n", cur_time.time_in_HH_MM_SS_US(), off_packet_num);
                                    last_off_packet = off_packet_num;
                                }

                                // if (off_packet_num > 0.9*rwnd/subconn_infos[0].payload_len){
                                //     log_debug("P%d-Squid-out: > 0.9*rwnd",  thr_data->pkt_id);
                                //     does_packet_lost_on_all_conns();
                                // }
                                // // Packet lost on all connections
                                // bool is_all_lost = true;
                                // for(size_t i = 1; i < subconn_infos.size(); i++){
                                //     // printf("cur_seq_rem %u, cur_ack_rel %u, payload_len %u\n", subconn_infos[i].cur_seq_rem, cur_ack_rel, subconn_infos[0].payload_len);
                                //     if (subconn_infos[i].cur_seq_rem < cur_ack_rel + subconn_infos[0].payload_len * 10000){
                                //         is_all_lost = false;
                                //     }
                                // }
                                // if (is_all_lost){
                                //     printf("\n\n###################\nPacket lost on all connections. \n###################\n\nlast ack:%d\n", cur_ack_rel);
                                //     for(size_t i = 1; i < subconn_infos.size(); i++){
                                //         printf("S%d: %d\n", i, subconn_infos[i].cur_seq_rem);
                                //     }

                                //     exit(-1);
                                // }
                            }
                        

                            //if(off_packet_num < 0.01 && ack_rel > last_speedup_ack_rel+500000 && ack_rel > 5000000){
                            //pthread_mutex_lock(&mutex_subconn_infos);
                            //if (ack_rel > 4*last_speedup_ack_rel){
                            //last_speedup_ack_rel = ack_rel;
                            //printf("P%d-Squid-out: ack pacing speed up by 100!\n", thr_data->pkt_id);
                            //for (size_t i = 0; i < subconn_infos.size(); ++i)
                            //{
                            //if(subconn_infos[i].ack_pacing > 100)
                            //subconn_infos[i].ack_pacing -= 100;
                            //}
                            //}
                            //pthread_mutex_unlock(&mutex_subconn_infos);
                            //}
                            return -1;
                        }
                        // if payload_len != 0, assume it's request
                        // squid connection with payload -> copy request, our connection -> only update seq/ack 
                        memset(request, 0, 1000);
                        memcpy(request, payload, payload_len);
                        request_len = payload_len;
                        request_recved = true;
                        log_info("P%d-Squid-out: request sent to server %d", thr_data->pkt_id, payload_len);
                        // check if we can send request now
                        log_debugv("P%d-S%d-out: process_tcp_packet:817: mutex_subconn_infos - trying lock", thr_data->pkt_id, subconn_i); 
                        pthread_mutex_lock(&mutex_subconn_infos);
                        for (size_t i=1; i<subconn_infos.size(); i++)
                            if (subconn_infos[i].seq_init == false) {
                                pthread_mutex_unlock(&mutex_subconn_infos);
                                log_debugv("P%d-S%d-out: process_tcp_packet: mutex_subconn_infos - unlock", thr_data->pkt_id, subconn_i); 
                                return -1;
                            }
                        // all done, start to send request
                        for (size_t i=0; i<subconn_infos.size(); i++) {
                            send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn_infos[i].local_port, request, subconn_infos[i].ini_seq_rem+1, subconn_infos[i].ini_seq_loc+1);
                            subconn_infos[i].cur_seq_loc = subconn_infos[i].ini_seq_loc + 1 + request_len;
                        }
                        pthread_mutex_unlock(&mutex_subconn_infos);
                        log_debugv("P%d-S%d-out: process_tcp_packet:817: mutex_subconn_infos - unlock", thr_data->pkt_id, subconn_i); 
                    }
                    else{
                            // log_info("P%d-S%d-out: ack %u", thr_data->pkt_id, subconn_i, ack - subconn->ini_seq_rem);
                    }
                    return -1;
                    break;
                }
            default:
                return 0;
        }
    }
    // Incoming Packets
    else        
    {
        
        //debugs(1, DBG_CRITICAL, log);
        unsigned int seq_rel = seq - subconn->ini_seq_rem;
        switch (tcphdr->th_flags) {
    /*
     * 1. 在httpAccept里加只有remote_ip, remote_port的iptablesguize
     * 2. 这里抓到squid发给server的SYN包，加squid连接的subconn_info, 复制test.c 1068-1077, 1087, SYN 发出去
     * 3. 收到server的SYN/ACK，判断是squid还是我们的连接，如果是squid，放走accept,如果是我们的，回ack（473-476）,判断是否所有连接都发了ack(479-486)，是否收到request(自己写)，向所有连接发请求(487-492)
     * 4. 抓到squid发给server的ACK包,都放行(accept),如果有长度，就是request，把payload复制下来
    */
            // case TH_SYN:
            // {
            //     // in this case, pkt must be squid -> server
            //     if (subconn_i != -1 && subconn_i != 0){ //subconn_i == -1,正常情况;subconn_i == 0, SYN丢了重传了
            //         //debugs(1, DBG_CRITICAL, "subconn_infos != -1/0 when receiving a SYN");
            //         return 0;
            //     }
            //     // build subconn[0] for squid
            //     if (subconn_i == -1) {
            //         strncpy(local_ip, sip, 16); //TODO: change position
            //         strncpy(remote_ip,dip, 16);
            //         remote_port = dport;

            //         pthread_mutex_lock(&mutex_subconn_infos); //TODO: how to deal with conns by other applications?
            //         struct subconn_info new_subconn;
            //         new_subconn.local_port = sport;//No nfq callback will interfere because iptable rules haven't been added
            //         new_subconn.ini_seq_loc = seq; //unknown
            //         new_subconn.cur_seq_loc = seq;
            //         new_subconn.win_size = 29200*128;
            //         new_subconn.ack_pacing = 5000;
            //         new_subconn.ack_sent = 1; //Assume squid will send ACK
            //         new_subconn.optim_ack_stop = 1;
            //         new_subconn.mutex_opa = PTHREAD_MUTEX_INITIALIZER;
            //         subconn_infos.push_back(new_subconn);
            //         pthread_mutex_unlock(&mutex_subconn_infos);
            //     }
            //     return 0;
            //     break;
            // }


            //case TH_SYN | TH_ACK:
            //{
                //// if server -> squid, init remote seq for squid
                //if(!subconn_i) {
                    //if (subconn_infos.size() > 0)
                        //subconn_infos[0].ini_seq_rem = seq;
                    //return 0;
                //}

                //char empty_payload[] = "";
                //send_ACK(sip, dip, sport, dport, empty_payload, seq+1, ack);
                //subconn->ini_seq_rem = subconn->cur_seq_rem = seq; //unknown
                ////debugs(1, DBG_IMPORTANT, "S" << subconn_i << ": Received SYN/ACK. Sent ACK");

                //pthread_mutex_lock(&mutex_subconn_infos);
                //subconn->ack_sent = 1;

                //if(!request_recved) {
                    //pthread_mutex_unlock(&mutex_subconn_infos);
                    //return -1;
                //}

                ////check if all subconns receive syn/ack        
                //size_t i;
                //for (i = 0; i < subconn_infos.size(); i++)
                    //if (!subconn_infos[i].ack_sent) {
                        //break;
                    //}
                //if (i == subconn_infos.size()) {
                    //for (size_t i = 0; i < subconn_infos.size(); i++) {
                        //send_ACK(sip, dip, sport, subconn_infos[i].local_port, request, subconn_infos[i].ini_seq_rem+1, subconn_infos[i].ini_seq_loc+1);
                        //subconn_infos[i].cur_seq_loc = subconn_infos[i].ini_seq_loc + 1 + request_len;
                    //}
                    ////debugs(1, DBG_IMPORTANT, "S" << subconn_i << "All ACK sent, sent request");
                //}
                //pthread_mutex_unlock(&mutex_subconn_infos);


                //return -1;
                //break;
            //}

            case TH_ACK:
            case TH_ACK | TH_PUSH:
            case TH_ACK | TH_URG:
            {
                if (!payload_len) {
                    // TODO: let our reply through...for now
                    if (subconn_i)
                        return 0;
                    log_info("P%d-S%d-in: server or our ack %u", thr_data->pkt_id, subconn_i, ack - subconn->ini_seq_loc);
                    return -1;
                }

                if(!subconn->payload_len && subconn->optim_ack_stop){
                    log_debugv("P%d-S%d: process_tcp_packet:991: subconn->mutex_opa - trying lock", thr_data->pkt_id, subconn_i); 
                    pthread_mutex_lock(&subconn->mutex_opa);
                    if(!subconn->payload_len && subconn->optim_ack_stop){
                        subconn->payload_len = payload_len;
                        // subconn_infos[0].payload_len = payload_len;
                        start_optim_ack(subconn_i, subconn->ini_seq_rem + 1, subconn->cur_seq_loc, payload_len, 0); //TODO: read MTU
                        // printf("P%d-S%d: Start optimistic_ack\n", thr_data->pkt_id, subconn_i); 
                    }
                    pthread_mutex_unlock(&subconn->mutex_opa);
                    log_debugv("P%d-S%d: process_tcp_packet:991: subconn->mutex_opa - unlock", thr_data->pkt_id, subconn_i); 
                }

                if(overrun_stop) {
                    log_debugv("P%d-S%d: process_tcp_packet:1003: mutex_subconn_infos - trying lock", thr_data->pkt_id, subconn_i); 
                    pthread_mutex_lock(&mutex_subconn_infos);
                    size_t i;
                    for (i = 1; i < subconn_infos.size(); i++)
                        if (subconn->optim_ack_stop == 1) {
                            break;
                        }
                    if (i == subconn_infos.size()){
                        if(overrun_stop){
                            overrun_stop = 0;
                            if (pthread_create(&overrun_thread, NULL, overrun_detector, (void*)this) != 0) {
                                log_error("Fail to create overrun_detector thread.");
                            }
                        }
                    }
                    pthread_mutex_unlock(&mutex_subconn_infos);
                    log_debugv("P%d-S%d: process_tcp_packet:1003: mutex_subconn_infos - unlock", thr_data->pkt_id, subconn_i); 
                }

                sprintf(log, "P%d-S%d: %s:%d -> %s:%d <%s> seq %x(%u) ack %x(%u) ttl %u plen %d", thr_data->pkt_id, subconn_i, sip, sport, dip, dport, tcp_flags_str(tcphdr->th_flags), tcphdr->th_seq, seq-subconn->ini_seq_rem, tcphdr->th_ack, ack-subconn->ini_seq_loc, iphdr->ttl, payload_len);
                // printf("%s\n", log);

                if(!subconn_i)
                    fprintf(seq_file, "%s, %u\n", cur_time.time_in_HH_MM_SS_US(), seq_rel);
                
                if(payload_len != subconn_infos[0].payload_len){
                    sprintf(log, "%s - unusal payload_len!", log);
                }

                log_debugv("P%d-S%d: process_tcp_packet:1021: subconn->mutex_opa - trying lock", thr_data->pkt_id, subconn_i); 
                pthread_mutex_lock(&subconn->mutex_opa);
                if(subconn->cur_seq_rem < seq_rel){
                    subconn->cur_seq_rem = seq_rel;
                }
                // Dup Retrnx
                else if(!RANGE_MODE && seq_rel > 1 && subconn->cur_seq_rem >= seq_rel){// && seq > subconn->opa_seq_max_restart && elapsed(last_restart_time) >= 1){ //TODO: out-of-order?
                    log_info("P%d-S%d: cur_seq_rem(%u) >= seq_rel(%u)", thr_data->pkt_id, subconn_i, subconn->cur_seq_rem, seq_rel);
                    //print dup_seqs
                    if(++subconn->dup_seqs[seq_rel] >= 2){
                        // subconn->dup_seqs.clear();                       
                        std::map<uint, uint>::iterator it = subconn->dup_seqs.begin(); 
                        while (it != subconn->dup_seqs.end()){
                            if(it->first <= seq_rel){
                                it = subconn->dup_seqs.erase(it);
                            }
                            else
                                it++;
                        }
                        //print dup_seqs

                        //Restart
                        printf("P%d-S%d: retrx detected %u\n", thr_data->pkt_id, subconn_i, seq_rel);
                        send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn->local_port, "", seq, ack, (cur_ack_rel-seq_rel+rwnd)/2048);
                        restart_optim_ack(subconn_i, seq, ack, payload_len, seq, subconn->last_restart_time);
                        subconn->cur_seq_rem = seq_rel;
                //         last_restart_time = std::chrono::system_clock::now();

                    }
                }
                pthread_mutex_unlock(&subconn->mutex_opa);
                log_debugv("P%d-S%d: process_tcp_packet:1021: subconn->mutex_opa - unlock", thr_data->pkt_id, subconn_i); 
                //Retrnx the whole window
                // if(subconn->cur_seq_rem >= seq_rel && seq >= subconn->opa_seq_max_restart && elapsed(last_restart_time) >= 1){

                //     subconn->opa_retrx_counter++;
                //     if (subconn->opa_retrx_counter >= 3){
                //         subconn->optim_ack_stop = 1;
                //         subconn->ack_pacing += 100;
                //         send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn->local_port, "", seq, ack, (cur_ack_rel-seq_rel+rwnd)/2048);
                //         // printf("S%d: before join\n", subconn_i);
                //         pthread_join(subconn->thread, NULL);
                //         printf("S%d: Restart optim ack from %u\n", subconn_i, seq_rel);
                //         start_optim_ack(subconn_i, seq, ack, payload_len, subconn->cur_seq_rem);//subconn->cur_seq_rem
                //         subconn->cur_seq_rem = seq_rel;

                //         subconn->opa_retrx_counter = 0;
                //         last_restart_time = std::chrono::system_clock::now();
                //     }
                // }

                if (seq_rel + subconn_infos[0].payload_len*5 < cur_ack_rel) {
                    // printf("P%d-S%d: discarded\n", thr_data->pkt_id, subconn_i); 
                    log_debug("%s - discarded", log);
                    return -1;
                }

                log_debugv("P%d-S%d: process_tcp_packet:1078: mutex_seq_gaps - trying lock", thr_data->pkt_id, subconn_i); 
                pthread_mutex_lock(&mutex_seq_gaps);

                if (seq_next_global < seq_rel) {
                    if (RANGE_MODE) {
                        int start = seq_next_global;
                        pthread_mutex_lock(&mutex_req_max);
                        // we allow negative here
                        // tricky & risky
                        if (req_max == 0) {
                            range_sockfd = init_range();
                            req_max = -1;
                        }
                        else
                            req_max--;
                        char range_request[MAX_RANGE_REQ_LEN];
                        memcpy(range_request, request, request_len);
                        // assume last characters are \r\n\r\n
                        sprintf(range_request+request_len-2, "Range: bytes=%d-%d\r\n\r\n", start, seq_rel-1);
                        send(range_sockfd, range_request, strlen(range_request), 0);
                        log_debug("[Range] request sent: %d - %d", start, seq_rel-1);
                        pthread_mutex_unlock(&mutex_req_max);
                    }
                    seq_gaps = insertNewInterval(seq_gaps, Interval(seq_next_global, seq_rel-1));
                }
                else if (seq_next_global > seq_rel) {
                    seq_gaps = removeInterval(seq_gaps, Interval(seq_rel, seq_rel+payload_len));
                }

                if (seq_next_global < seq_rel + payload_len)
                    seq_next_global = seq_rel + payload_len;
                
                pthread_mutex_unlock(&mutex_seq_gaps);
                log_debugv("P%d-S%d: process_tcp_packet:1078: mutex_seq_gaps - unlock", thr_data->pkt_id, subconn_i); 

                // if (subconn->optim_ack_stop) {
                //     // TODO: what if payload_len changes?
                //     printf("P%d-S%d: Start optimistic_ack\n", thr_data->pkt_id, subconn_i);
                // }
 
                // pthread_mutex_lock(&mutex_seq_next_global);

                // int offset = seq_rel - seq_next_global;
                // unsigned int append = 0;
                // if (offset > 0) {
                //     printf("P%d-S%d: > Insert gaps %d -> %d\n", thr_data->pkt_id, subconn_i, seq_next_global, seq_rel);
                //     //debugs(1, DBG_CRITICAL, "Subconn " << subconn_i << "-" << thr_data->pkt_id << ": Insert gaps: " << seq_next_global << ", to: " << seq_rel);
                //     // pthread_mutex_lock(&mutex_seq_gaps);
                //     insert_seq_gaps(seq_next_global, seq_rel, payload_len);
                //     // pthread_mutex_unlock(&mutex_seq_gaps);
                //     append = offset + payload_len;
                // }
                // else if (offset < 0){
                    
                //     int ret = find_seq_gaps(seq_rel);
                //     if (!ret){
                //         //debugs(1, DBG_CRITICAL, "Subconn " << subconn_i << "-" << thr_data->pkt_id << ": recv " << seq_rel << " < wanting " << seq_next_global);
                //         pthread_mutex_unlock(&mutex_seq_next_global);
                //         return -1;
                //     }
                //     // pthread_mutex_lock(&mutex_seq_gaps);
                //     delete_seq_gaps(seq_rel);
                //     // pthread_mutex_unlock(&mutex_seq_gaps);
                //     //debugs(1, DBG_CRITICAL, "Subconn " << subconn_i << "-" << thr_data->pkt_id << ": Found gap " << seq_rel << ". Delete gap");
                //     printf("P%d-S%d: < Found gaps %d. Deleted\n", thr_data->pkt_id, subconn_i, seq_rel);
                // }
                // else {
                //     append = payload_len;
                //     //debugs(1, DBG_CRITICAL, "Subconn " << subconn_i << "-" << thr_data->pkt_id << ": Found seg " << seq_rel);
                //     printf("P%d-S%d: = In order %d\n", thr_data->pkt_id, subconn_i, seq_rel);
                // }

                // if(append){
                //     seq_next_global += append;
                //     printf("P%d-S%d: Update seq_next_global to %d\n", thr_data->pkt_id, subconn_i, seq_next_global);
                //     //debugs(1, DBG_CRITICAL, "Subconn " << subconn_i << "-" << thr_data->pkt_id << ": Update seq_global to " << seq_next_global);
                // }

                // pthread_mutex_unlock(&mutex_seq_next_global);

                // // send to squid 
                // // 1. dest port -> sub1->localport
                // // 2. seq -> sub1->init_seq_rem + seq_rel
                // // 3. ack -> sub1->cur_seq_loc
                // // 4. checksum(IP,TCP)
                log_debug("%s - forwarded to squid", log); 
                if(!subconn_i)
                    return 0; //Main subconn, return directly
                tcphdr->th_dport = htons(subconn_infos[0].local_port);
                tcphdr->th_seq = htonl(subconn_infos[0].ini_seq_rem+seq_rel);
                tcphdr->th_ack = htonl(subconn_infos[0].cur_seq_loc);
                compute_checksums(thr_data->buf, 20, thr_data->len);
                // printf("P%d-S%d: forwarded to squid\n", thr_data->pkt_id, subconn_i); 
                // printf("before sendto\n");
                // hex_dump(thr_data->buf, thr_data->len);
                // int result = sendto(sockraw, thr_data->buf, thr_data->len, 0, (struct sockaddr*)&dstAddr, sizeof(struct sockaddr));
                // if(result < 0){
                //     printf("P%d-S%d: sendto error\n", thr_data->pkt_id, subconn_i);
                // }
                // printf("after sendto\n");
                // hex_dump(thr_data->buf, thr_data->len);
                // if(subconn_i == 8)
                //     return 0;
                return 0;

                break;
            }
            case TH_ACK | TH_FIN:
            {
                //send_FIN_ACK("", seq+1, ack, dport);
                // TODO: should I stop all or just one?
                subconn->optim_ack_stop = 1;
                //debugs(0, DBG_CRITICAL, "Subconn " << subconn_i << ": Received FIN/ACK. Sent FIN/ACK. Stop current optim ack thread");
                break;
            }
            default:
                //debugs(0, DBG_CRITICAL, "Invalid tcp flags: " << tcp_flags_str(tcphdr->th_flags));
                break;
        }
        return 0;
    }
}

void 
Optimack::open_duplicate_conns(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port)
{
    char* cmd;
    int ret;

    // if marked, let through
    //cmd = (char*) malloc(IPTABLESLEN);
    //sprintf(cmd, "OUTPUT -p tcp -d %s --dport %d -m mark --mark %d -j ACCEPT", remote_ip, remote_port, MARK);
    //ret = exec_iptables('A', cmd);
    //iptables_rules.push_back(cmd);
    //debugs(11, 2, cmd << ret);

    //TODO: iptables too broad??
    cmd = (char*) malloc(IPTABLESLEN);
    // sprintf(cmd, "INPUT -p tcp -s %s --sport %d --dport %d -j DROP", remote_ip, remote_port, local_port);
    sprintf(cmd, "PREROUTING -t mangle -p tcp -s %s --sport %d --dport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, local_port, nfq_queue_num);
    ret = exec_iptables('A', cmd);
    iptables_rules.push_back(cmd);
    debugs(11, 2, cmd << ret);

    cmd = (char*) malloc(IPTABLESLEN);
    sprintf(cmd, "OUTPUT -p tcp -d %s --dport %d --sport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, local_port, nfq_queue_num);
    ret = exec_iptables('A', cmd);
    iptables_rules.push_back(cmd);
    debugs(11, 2, cmd << ret);
 
    strncpy(g_local_ip, local_ip, 16); //TODO: change position
    strncpy(g_remote_ip, remote_ip, 16);
    inet_pton(AF_INET, local_ip, &g_local_ip_int);
    inet_pton(AF_INET, remote_ip, &g_remote_ip_int);
    g_remote_port = remote_port;
    
    dstAddr.sin_family = AF_INET;
    memcpy((char*)&dstAddr.sin_addr, &g_remote_ip_int, sizeof(g_remote_ip_int));

    // pthread_mutex_lock(&mutex_subconn_infos);
    // TODO: how to deal with conns by other applications?
    struct subconn_info squid_conn;
    memset(&squid_conn, 0, sizeof(struct subconn_info));
    squid_conn.local_port = local_port;
    squid_conn.ini_seq_loc = squid_conn.cur_seq_loc = 0;
    squid_conn.ack_pacing = ACKPACING;
    squid_conn.ack_sent = 1; //Assume squid will send ACK
    squid_conn.optim_ack_stop = 1;
    squid_conn.mutex_opa = PTHREAD_MUTEX_INITIALIZER;
    subconn_infos.push_back(squid_conn);
    // pthread_mutex_unlock(&mutex_subconn_infos);

    int conn_num = 15;
    // range
    if (RANGE_MODE) {
        conn_num = 0;
        range_sockfd = 0;
        req_max = 0;
    }

    for (int i = 1; i <= conn_num; i++) {
        // pthread_mutex_lock(&mutex_subconn_infos);
        struct subconn_info new_subconn;
        memset(&new_subconn, 0, sizeof(struct subconn_info));
        //new_subconn.local_port = local_port_new;
        new_subconn.ini_seq_loc = new_subconn.cur_seq_loc = 0;
        new_subconn.last_cur_seq_rem = 0;
        // new_subconn.rwnd = 365;
        new_subconn.ack_pacing = ACKPACING;
        new_subconn.ack_sent = 0;
        new_subconn.optim_ack_stop = 1;
        new_subconn.mutex_opa = PTHREAD_MUTEX_INITIALIZER;
        new_subconn.seq_init = false;
        // pthread_mutex_unlock(&mutex_subconn_infos);

        struct sockaddr_in server_addr, my_addr;

        // Open socket
        if ((new_subconn.sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		    perror("Can't open stream socket.");
            break;
        }

        // Set server_addr
        bzero(&server_addr, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = inet_addr(g_remote_ip);
        server_addr.sin_port = htons(g_remote_port);
        
        // Connect to server
        if (connect(new_subconn.sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            perror("Connect server error");
            close(new_subconn.sockfd);
            break;
        }

        // Get my port
        socklen_t len = sizeof(my_addr);
        bzero(&my_addr, len);
        if (getsockname(new_subconn.sockfd, (struct sockaddr*)&my_addr, &len) < 0) {
            perror("getsockname error");
            close(new_subconn.sockfd);
            break;
        }
        new_subconn.local_port = ntohs(my_addr.sin_port);
        subconn_infos.push_back(new_subconn);

        //TODO: iptables too broad??
        cmd = (char*) malloc(IPTABLESLEN);
        sprintf(cmd, "PREROUTING -t mangle -p tcp -s %s --sport %d --dport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, new_subconn.local_port, nfq_queue_num);
        ret = exec_iptables('A', cmd);
        iptables_rules.push_back(cmd);
        debugs(11, 2, cmd << ret);

        //TODO: iptables too broad??
        cmd = (char*) malloc(IPTABLESLEN);
        sprintf(cmd, "OUTPUT -p tcp -d %s --dport %d --sport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, new_subconn.local_port, nfq_queue_num);
        ret = exec_iptables('A', cmd);
        iptables_rules.push_back(cmd);
        debugs(11, 2, cmd << ret);

        // probe seq and ack
        // leave the INPUT rule cleanup to process_tcp_packet
        char dummy_buffer[] = "Hello";
        send(new_subconn.sockfd, dummy_buffer, 5, 0);
    
        // unsigned int size = 1000;
        // if (setsockopt(new_subconn.sockfd, SOL_SOCKET, SO_RCVBUF, (char *) &size, sizeof(size)) < 0) {
        //     int xerrno = errno;
        //     perror("set SO_RCVBUF failed.");
        //     // debugs(50, DBG_CRITICAL, MYNAME << "FD " << new_subconn.sockfd << ", SIZE " << size << ": " << xstrerr(xerrno));
        // }

        //send_SYN(remote_ip, local_ip, remote_port, local_port_new, empty_payload, 0, seq);
        //debugs(1, DBG_IMPORTANT, "Subconn " << i << ": Sent SYN");
    }
}


int
Optimack::exec_iptables(char action, char* rule)
{
    char cmd[IPTABLESLEN+32];
    sprintf(cmd, "sudo iptables -%c %s", action, rule);
    return system(cmd);
}

// int 
// Optimack::find_seq_gaps(unsigned int seq)
// {
//     if (seq < *seq_gaps.begin()[0] || seq > *seq_gaps.end()[1])
//         return 0;
//     return seq_gaps.find(seq) != seq_gaps.end();
//     // for (size_t i = 0; i < seq_gaps.size(); i++)
//     // {
//     //     if (seq < seq_gaps.at(i))
//     //         return -1;
//     //     else if(seq == seq_gaps.at(i))
//     //         return i;
//     // }
//     // return -1;
// }

// void 
// Optimack::insert_seq_gaps(unsigned int start, unsigned int end)
// {
//     printf("insert gap: (%u, %u)\n", start, end);
//     std::vector<uint*>::iterator it;
//     if (seq_gaps.empty()){
//         it = seq_gaps.begin();
//     }
//     else {
//         for (it = seq_gaps.end() ; it != seq_gaps.begin(); --it){
//             if(end < *it[0]) // start < end < *it[0] < *it[1]
//                 continue;
//             else if (end == *it[0]){
//                 printf("end and it.start overlapping: end(%u), it(%u,%u)\n", end, *it[0], *it[1]);
//                 insert_seq_gaps(start, end-1);
//             }

//             if(start > *it[1]) //*it[0] < *it[1] < start < end < *it+1[0]
//                 break;
//             else if (start == *it[1]){
//                 printf("start and it.end overlapping: start(%u), it(%u,%u)\n", start, *it[0], *it[1]);
//                 insert_seq_gaps(start+1, end);
//                 return;
//             }
//             else{// start < *it[1]
//                 if (start >= *it[0])
//                     if(end <= *it[1]) // *it[0] <= start < end <= *it[1], already exists
//                         return;
//                     else{
//                         insert_seq_gaps(*it[1]+1, end); // insert
//                         return;
//                     }
//             }
//         }
//     }
//     uint* gap = new uint[2];
//     gap[0] = start;
//     gap[1] = end;
//     seq_gaps.insert(it, gap);
    
//     // unsigned int last = seq_gaps.at(seq_gaps.size()-1);
//     // if (start > last){
//     //     for(; start < end; start += step)
//     //         seq_gaps.push_back(start);
//     // }
//     // else if (start < last) {
//     //     for(; start < end; start += step){

//     //     }       
//     // }
// }

// void 
// Optimack::delete_seq_gaps(unsigned int val)
// {
//     seq_gaps.erase(val);
// }


/** end **/
