#include "hping2.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <vector>
#include <set>
using namespace std;

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netlink.h>
#include <libnfnetlink/libnfnetlink.h>


#include "thr_pool.h"
#include "socket.h"
#include "util.h"
#include "checksum.h"
#include "netfilter_queue.h"
#include "Debug.h"

// globals
struct nfq_handle *g_nfq_h;
struct nfq_q_handle *g_nfq_qh;
int g_nfq_fd;
int nfq_stop;

char g_local_ip[16]; //TODO: different connection from client
char g_remote_ip[16];
unsigned int g_local_ip_int;
unsigned int g_remote_ip_int;
unsigned short g_remote_port;
char request[1000];
unsigned short request_len;

std::vector<struct subconn_info> subconn_infos;

// locals
bool request_recved = false;
char empty_payload[] = "";
const int MARK = 666;

thr_pool_t* pool;
pthread_mutex_t mutex_seq_next_global = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_seq_gaps = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_subconn_infos = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex_optim_ack_stop = PTHREAD_MUTEX_INITIALIZER;


// seq
unsigned int seq_next_global = 1;
std::set<unsigned int> seq_gaps;
unsigned int max_win_size = 0;
unsigned int last_speedup_ack_rel = 1;


void init()
{
    // init random seed
    srand(time(NULL));

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
    if (!pool){
            debugs(0, DBG_CRITICAL, "couldn't create thr_pool");
            exit(1);                
    }
}

int setup_nfq(void* data)
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
    debugs(0, DBG_CRITICAL,"binding this socket to queue " << NF_QUEUE_NUM);
    g_nfq_qh = nfq_create_queue(g_nfq_h, NF_QUEUE_NUM, &cb, data);
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

#define NFQLENGTH 1024*200
#define BUFLENGTH 4096
    if (nfq_set_queue_maxlen(g_nfq_qh, NFQLENGTH) < 0) {
        debugs(0, DBG_CRITICAL,"error during nfq_set_queue_maxlen()\n");
        return -1;
    }
    struct nfnl_handle* nfnl_hl = nfq_nfnlh(g_nfq_h);
    nfnl_rcvbufsiz(nfnl_hl, NFQLENGTH * BUFLENGTH);

    g_nfq_fd = nfq_fd(g_nfq_h);

    return 0;
}

int teardown_nfq()
{
    debugs(0, DBG_CRITICAL,"unbinding from queue " << NF_QUEUE_NUM);
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

void *nfq_loop(void *arg)
{
    int rv;
    char buf[65536];
    void * placeholder = 0;

    while (!nfq_stop) {
        rv = recv(g_nfq_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (rv >= 0) {
            //debugs(0, DBG_CRITICAL,"%d", rv);
            //hex_dump((unsigned char *)buf, rv);
            //log_debugv("pkt received");
            nfq_handle_packet(g_nfq_h, buf, rv);
        }
        else {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                debugs(0, DBG_CRITICAL,"recv() ret " << rv << "errno " << errno);
            }
            usleep(100); //10000
        }
    }
    return placeholder;
}

int find_seq_gaps(unsigned int seq)
{
    if (seq < *seq_gaps.begin())
        return 0;
    return seq_gaps.find(seq) != seq_gaps.end();
    // for (size_t i = 0; i < seq_gaps.size(); i++)
    // {
    //     if (seq < seq_gaps.at(i))
    //         return -1;
    //     else if(seq == seq_gaps.at(i))
    //         return i;
    // }
    // return -1;
}

void insert_seq_gaps(unsigned int start, unsigned int end, unsigned int step)
{
    printf("insert gap: ");
    for(; start < end; start += step){
        printf("%d ", start);
        //debugs(1, DBG_CRITICAL, "insert gap u" << start);
        seq_gaps.insert(start);
    }
    printf("\n");
    // unsigned int last = seq_gaps.at(seq_gaps.size()-1);
    // if (start > last){
    //     for(; start < end; start += step)
    //         seq_gaps.push_back(start);
    // }
    // else if (start < last) {
    //     for(; start < end; start += step){

    //     }       
    // }
}

void delete_seq_gaps(unsigned int val)
{
    seq_gaps.erase(val);
}

void* optimistic_ack(void* threadid)
{
    int id = (long) threadid;
    unsigned int ack_step = subconn_infos[id].payload_len;
    unsigned int opa_seq_start = subconn_infos[id].opa_seq_start;
    unsigned int opa_ack_start = subconn_infos[id].opa_ack_start;
    unsigned int local_port = subconn_infos[id].local_port;
    unsigned int ack_pacing = subconn_infos[id].ack_pacing;

    //debugs(1, DBG_CRITICAL, "S" << id << ": Optim ack starts");
    printf("S%d: optimistic ack started\n", id);   
    for (int k = 0; !subconn_infos[id].optim_ack_stop; k++){
        send_ACK(g_remote_ip, g_local_ip, g_remote_port, local_port, empty_payload, opa_ack_start+k*ack_step, opa_seq_start);
        usleep(subconn_infos[id].ack_pacing);
    }
    // TODO: why 0???
    subconn_infos[id].optim_ack_stop = 0;
    printf("S%d: optimistic ack ends\n", id);   
    //debugs(1, DBG_CRITICAL, "S" << id << ": Optim ack ends");
    pthread_exit(NULL);
}

int start_optim_ack(int id, unsigned int opa_ack_start, unsigned int opa_seq_start, unsigned int payload_len, unsigned int seq_max)
{
    subconn_infos[id].opa_seq_start = opa_seq_start;
    subconn_infos[id].opa_ack_start = opa_ack_start;
    subconn_infos[id].opa_seq_max_restart = seq_max;
    subconn_infos[id].opa_retrx_counter = 0;
    subconn_infos[id].payload_len = payload_len;
    // set to running
    subconn_infos[id].optim_ack_stop = 0;
    pthread_t thread;
    if (pthread_create(&thread, NULL, optimistic_ack, (void *)(intptr_t)id) != 0) {
        //debugs(0, DBG_CRITICAL, "Fail to create optimistic_ack thread");
        printf("S%d: Fail to create optimistic_ack thread\n", id);
        return -1;
    }
    //debugs(1, DBG_CRITICAL, "S" << id <<": optimistic ack thread created");   
    printf("S%d: optimistic ack thread created\n", id);   
    return 0;
}


int process_tcp_packet(struct thread_data* thr_data)
{
    char log[LOGSIZE];

    struct myiphdr *iphdr = ip_hdr(thr_data->buf);
    struct mytcphdr *tcphdr = tcp_hdr(thr_data->buf);
    unsigned char *payload = tcp_payload(thr_data->buf);
    unsigned int payload_len = htons(iphdr->tot_len) - iphdr->ihl*4 - tcphdr->th_off*4;

    // check remote ip, local ip
    bool incoming = true;
    char *sip, *dip;
    if (g_remote_ip_int == iphdr->saddr){
        incoming = true;
        sip = g_remote_ip;
        dip = g_local_ip;
    }
    else if (g_remote_ip_int == iphdr->daddr){
        incoming = false;
        sip = g_local_ip;
        dip = g_remote_ip;
    }
    else 
    {
        char sip_[16], dip_[16];
        ip2str(iphdr->saddr, sip_);
        ip2str(iphdr->daddr, dip_);
        sprintf(log, "P%d: ERROR - IP not found: %s:%d -> %s:%d <%s> seq %x ack %x ttl %u plen %d", thr_data->pkt_id, sip_, ntohs(tcphdr->th_sport), dip_, ntohs(tcphdr->th_dport), tcp_flags_str(tcphdr->th_flags), tcphdr->th_seq, tcphdr->th_ack, iphdr->ttl, payload_len);
        printf("%s\n", log);
        return 0;
    }


    unsigned short sport = ntohs(tcphdr->th_sport);
    unsigned short dport = ntohs(tcphdr->th_dport);
    unsigned int seq = htonl(tcphdr->th_seq);
    unsigned int ack = htonl(tcphdr->th_ack);

    
    //Incoming Packets
    if (!incoming) 
    {   
        if (subconn_infos[0].local_port == sport)
        { 
            switch (tcphdr->th_flags) {
                case TH_ACK:
                case TH_ACK | TH_PUSH:
                case TH_ACK | TH_URG:
                {
                    if (!payload_len){
                        int win_size = ntohs(tcphdr->th_win);
                        if(win_size > max_win_size)
                            max_win_size = win_size;
                        int ack_rel = ack - subconn_infos[0].ini_seq_rem;
                        float off_packet_num = (seq_next_global-ack_rel)/1460.0;
                        printf("P%d-Squid-out: squid ack %d, seq_global %d, off %.2f packets, win_size %d, max win_size %d\n", thr_data->pkt_id, ack_rel, seq_next_global, off_packet_num, win_size, max_win_size);
                        
                        if(off_packet_num < 0.01 && ack_rel > last_speedup_ack_rel+500000 && ack_rel > 5000000){
                            pthread_mutex_lock(&mutex_subconn_infos);
                            if (ack_rel > 4*last_speedup_ack_rel){
                                last_speedup_ack_rel = ack_rel;
                                printf("P%d-Squid-out: ack pacing speed up by 100!\n", thr_data->pkt_id);
                                for (size_t i = 0; i < subconn_infos.size(); ++i)
                                {
                                    if(subconn_infos[i].ack_pacing > 100)
                                        subconn_infos[i].ack_pacing -= 100;
                                }
                            }
                            pthread_mutex_unlock(&mutex_subconn_infos);
                        }
                        return -1;
                    }

                    subconn_infos[0].ini_seq_rem = ack - 1;
                    subconn_infos[0].cur_seq_rem = ack;
                    subconn_infos[0].ini_seq_loc = seq - 1;
                    subconn_infos[0].cur_seq_loc = seq;

                    memset(request, 0, 1000);
                    memcpy(request, payload, payload_len);
                    request_len = payload_len;
                    request_recved = true;
                    printf("P%d-Squid-out: request sent to server %d\n", thr_data->pkt_id, payload_len);
                    return -1;
                    break;
                }
                default:
                    return 0;
            }
        }
        else
        {
            sprintf(log, "P%d: ERROR - Incoming packet not from Squid: %s:%d -> %s:%d <%s> seq %x ack %x ttl %u plen %d", thr_data->pkt_id, sip, sport, dip, dport, tcp_flags_str(tcphdr->th_flags), tcphdr->th_seq, tcphdr->th_ack, iphdr->ttl, payload_len);
            printf("%s\n", log);
            return 0;
        }
    }

    //Outgoing Packets
    else        
    {

        // TODO: mutex?
        int subconn_i = -1;
        for (size_t i = 0; i < subconn_infos.size(); i++)
            if (subconn_infos[i].local_port == dport) {
                subconn_i = (int)i;
                break;
            }

        if (subconn_i == -1) {
            sprintf(log, "P%d: ERROR - Subconn not found: %s:%d -> %s:%d <%s> seq %x ack %x ttl %u plen %d", thr_data->pkt_id, sip, sport, dip, dport, tcp_flags_str(tcphdr->th_flags), tcphdr->th_seq, tcphdr->th_ack, iphdr->ttl, payload_len);
            printf("%s\n", log);
            return -1;
        }

        // print only if we have the subconn_i
        sprintf(log, "P%d-S%d: %s:%d -> %s:%d <%s> seq %x(%u) ack %x(%u) ttl %u plen %d", thr_data->pkt_id, subconn_i, sip, sport, dip, dport, tcp_flags_str(tcphdr->th_flags), tcphdr->th_seq, seq-subconn_infos[subconn_i].ini_seq_rem, tcphdr->th_ack, ack-subconn_infos[subconn_i].ini_seq_loc, iphdr->ttl, payload_len);
        printf("%s\n", log);
        //debugs(1, DBG_CRITICAL, log);

        unsigned int seq_rel = seq - subconn_infos[subconn_i].ini_seq_rem;
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


            case TH_SYN | TH_ACK:
            {
                // if server -> squid, init remote seq for squid
                if(!subconn_i) {
                    if (subconn_infos.size() > 0)
                        subconn_infos[0].ini_seq_rem = seq;
                    return 0;
                }

                send_ACK(sip, dip, sport, dport, empty_payload, seq+1, ack);
                subconn_infos[subconn_i].ini_seq_rem = subconn_infos[subconn_i].cur_seq_rem = seq; //unknown
                //debugs(1, DBG_IMPORTANT, "S" << subconn_i << ": Received SYN/ACK. Sent ACK");

                pthread_mutex_lock(&mutex_subconn_infos);
                subconn_infos[subconn_i].ack_sent = 1;  

                if(!request_recved) {
                    pthread_mutex_unlock(&mutex_subconn_infos);
                    return -1;
                }

                //check if all subconns receive syn/ack        
                size_t i;
                for (i = 0; i < subconn_infos.size(); i++)
                    if (!subconn_infos[i].ack_sent) {
                        break;
                    }
                if (i == subconn_infos.size()) {
                    for (size_t i = 0; i < subconn_infos.size(); i++) {
                        send_ACK(sip, dip, sport, subconn_infos[i].local_port, request, subconn_infos[i].ini_seq_rem+1, subconn_infos[i].ini_seq_loc+1);
                        subconn_infos[i].cur_seq_loc = subconn_infos[i].ini_seq_loc + 1 + request_len;
                        start_optim_ack(i, subconn_infos[i].ini_seq_rem + 1, subconn_infos[i].cur_seq_loc, 1460, 0); //TODO: read MTU
                        printf("P%d-S%d: Start optimistic_ack\n", thr_data->pkt_id, i);
                    }
                    //debugs(1, DBG_IMPORTANT, "S" << subconn_i << "All ACK sent, sent request");
                }
                pthread_mutex_unlock(&mutex_subconn_infos);


                return -1;
                break;
            }

            case TH_ACK:
            case TH_ACK | TH_PUSH:
            case TH_ACK | TH_URG:
            {
                if (!payload_len) {
                    printf("P%d-Squid-in: server ack %d\n", thr_data->pkt_id, ack);
                    return -1;
                }

                if (seq_next_global < seq_rel + payload_len)
                    seq_next_global = seq_rel + payload_len;

                // if (subconn_infos[subconn_i].optim_ack_stop) {
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
                if(!subconn_i)
                    return 0; //Main subconn, return directly
                tcphdr->th_dport = htons(subconn_infos[0].local_port);
                tcphdr->th_seq = htonl(subconn_infos[0].ini_seq_rem+seq_rel);
                tcphdr->th_ack = htonl(subconn_infos[0].cur_seq_loc);
                compute_checksums(thr_data->buf, 20, thr_data->len);
                return 0;

                break;
            }
            case TH_ACK | TH_FIN:
            {
                //send_FIN_ACK("", seq+1, ack, dport);
                // TODO: should I stop all or just one?
                subconn_infos[subconn_i].optim_ack_stop = 1;
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

void* pool_handler(void* arg)
{
    //char log[LOGSIZE];
    struct thread_data* thr_data = (struct thread_data*)arg;
    u_int32_t id = thr_data->pkt_id;
    int ret = -1;

    //debugs(0, DBG_CRITICAL, "pool_handler: "<<id);

    short protocol = ip_hdr(thr_data->buf)->protocol;
    if (protocol == 6)
        ret = process_tcp_packet(thr_data);
    else{ 
        //sprintf(log, "Invalid protocol: 0x%04x, len %d", protocol, thr_data->len);
        //debugs(0, DBG_CRITICAL, log);
        struct myiphdr *iphdr = ip_hdr(thr_data->buf);
        struct mytcphdr *tcphdr = tcp_hdr(thr_data->buf);
        //unsigned char *payload = tcp_payload(thr_data->buf);
        unsigned int payload_len = thr_data->len - iphdr->ihl*4 - tcphdr->th_off*4;
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
        nfq_set_verdict(g_nfq_qh, id, NF_ACCEPT, thr_data->len, thr_data->buf);
        //debugs(0, DBG_CRITICAL, "Verdict: Accept");
    }
    else{
        nfq_set_verdict(g_nfq_qh, id, NF_DROP, 0, NULL);
        //debugs(0, DBG_CRITICAL, "Verdict: Drop");
    }

    free(thr_data->buf);
    free(thr_data);
    // TODO: ret NULL?
    return NULL;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    unsigned char* packet;
    int packet_len = nfq_get_payload(nfa, &packet);

    struct myiphdr *iphdr = ip_hdr(packet);
    struct mytcphdr *tcphdr = tcp_hdr(packet);
    //unsigned char *payload = tcp_payload(thr_data->buf);
    unsigned int payload_len = packet_len - iphdr->ihl*4 - tcphdr->th_off*4;
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
    if (!ph) {
        debugs(0, DBG_CRITICAL,"nfq_get_msg_packet_hdr failed");
        return -1;
    }

    thr_data->pkt_id = htonl(ph->packet_id);
    thr_data->len = packet_len;
    thr_data->buf = (unsigned char *)malloc(packet_len);
    if (!thr_data->buf){
            debugs(0, DBG_CRITICAL, "cb: error during malloc");
            return -1;
    }
    memcpy(thr_data->buf, packet, packet_len);

    if(thr_pool_queue(pool, pool_handler, (void *)thr_data) < 0) {
        debugs(0, DBG_CRITICAL, "cb: error during thr_pool_queue");
        return -1;
    }
    return 0;
}


void open_duplicate_conns(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port)
{
    char cmd[200];
    int ret;

    memset(cmd, 0, 200);
    sprintf(cmd, "sudo iptables -A OUTPUT -p tcp -d %s --dport %d -m mark --mark %d -j ACCEPT", remote_ip, remote_port, MARK);
    ret = system(cmd);
    debugs(11, 2, cmd << ret);

    memset(cmd, 0, 200); //TODO: iptables too broad??
    sprintf(cmd, "sudo iptables -A INPUT -p tcp -s %s --sport %d --dport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, local_port, NF_QUEUE_NUM);
    ret = system(cmd);
    debugs(11, 2, cmd << ret);

    memset(cmd, 0, 200);
    sprintf(cmd, "sudo iptables -A OUTPUT -p tcp -d %s --dport %d --sport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, local_port, NF_QUEUE_NUM);
    ret = system(cmd);
    debugs(11, 2, cmd << ret);
 
    // memset(cmd, 0, 200);
    // sprintf(cmd, "sudo iptables -A OUTPUT -t raw -p tcp -d %s --dport %u --tcp-flags RST,ACK RST -j DROP", remote_ip, remote_port);
    // ret = system(cmd);
    // debugs(11, 2, cmd << ret);

    strncpy(g_local_ip, local_ip, 16); //TODO: change position
    strncpy(g_remote_ip, remote_ip, 16);
    inet_pton(AF_INET, local_ip, &g_local_ip_int);
    inet_pton(AF_INET, remote_ip, &g_remote_ip_int);
    g_remote_port = remote_port;

    // pthread_mutex_lock(&mutex_subconn_infos); //TODO: how to deal with conns by other applications?
    struct subconn_info squid_conn;
    memset(&squid_conn, 0, sizeof(struct subconn_info));
    squid_conn.local_port = local_port;//No nfq callback will interfere because iptable rules haven't been added
    squid_conn.ack_pacing = ACKPACING;
    squid_conn.ack_sent = 1; //Assume squid will send ACK
    squid_conn.optim_ack_stop = 1;
    squid_conn.mutex_opa = PTHREAD_MUTEX_INITIALIZER;
    subconn_infos.push_back(squid_conn);
    // pthread_mutex_unlock(&mutex_subconn_infos);


    for (int i = 1; i <= 7; i++){
        unsigned short local_port_new = rand() % 20000 + 30000; 
        int seq = rand();

        memset(cmd, 0, 200); //TODO: iptables too broad??
        sprintf(cmd, "sudo iptables -A INPUT -p tcp -s %s --sport %d --dport %d -j NFQUEUE --queue-num %d", remote_ip, remote_port, local_port_new, NF_QUEUE_NUM);
        ret = system(cmd);
        debugs(11, 2, cmd << ret);

        send_SYN(remote_ip, local_ip, remote_port, local_port_new, empty_payload, 0, seq);
        debugs(1, DBG_IMPORTANT, "Subconn " << i << ": Sent SYN");

        // pthread_mutex_lock(&mutex_subconn_infos);
        struct subconn_info new_subconn;
        memset(&new_subconn, 0, sizeof(struct subconn_info));
        new_subconn.local_port = local_port_new;//No nfq callback will interfere because iptable rules haven't been added
        new_subconn.ini_seq_loc = new_subconn.cur_seq_loc = seq;
        new_subconn.win_size = 29200*128;
        new_subconn.ack_pacing = ACKPACING;
        new_subconn.ack_sent = 0;
        new_subconn.optim_ack_stop = 1;
        new_subconn.mutex_opa = PTHREAD_MUTEX_INITIALIZER;
        subconn_infos.push_back(new_subconn);
        // pthread_mutex_unlock(&mutex_subconn_infos);                
    }
}

/** end **/
