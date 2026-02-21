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
#include <iterator>
#include <new>
#include <fcntl.h>
using namespace std;

#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netlink.h>
#include <libnfnetlink/libnfnetlink.h>

#include <netinet/tcp.h>
#include "socket.h"
#include "util.h"
#include "checksum.h"
// #include "Debug.h"
#include "logging.h"

// for http parsing
// #include <cstring>
// #include <algorithm>
// #include "squid.h" //otherwise open_ssl_conns is undefined
#include <sys/select.h>
#include "Optimack.h"
#include "range_request_module.h"

/** Our code **/
const int debug_rb = false;
const int debug_recvseq = false;
const int print_per_sec_on = true;

// #define COLLETIVE_MODE 1

#ifndef CONN_NUM
#define CONN_NUM 3
#endif

#ifndef ACKPACING
#define ACKPACING 1000
#endif

#define MAX_STALL_TIME 240
#define MAX_RESTART_COUNT 3

#define LOGSIZE 10240
#define IPTABLESLEN 128

// nfq
#define NF_QUEUE_NUM 6
#define NFQLENGTH 204800
#define BUFLENGTH 4096

#ifndef RANGE_MODE
#define RANGE_MODE 1
#endif

#ifndef BACKUP_MODE
#define BACKUP_MODE 0
#endif

#ifndef MSS
#define MSS 1460
#endif

#ifndef SPEEDUP_CONFIG
#define SPEEDUP_CONFIG 0
#endif

#ifndef SLOWDOWN_CONFIG
#define SLOWDOWN_CONFIG 0
#endif

#ifndef DEBUG_PRINT_LEVEL
#define DEBUG_PRINT_LEVEL 0
#endif

std::map<uint, struct subconn_info*> allconns;


// Utility
double get_current_epoch_time_second(){
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
}

double get_current_epoch_time_nanosecond(){
    return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count()/1000000000.0;
}

double elapsed(std::chrono::time_point<std::chrono::system_clock> start){
    auto now = std::chrono::system_clock::now();
    // if (now > start)
        return std::chrono::duration<double>(now - start).count();
    // else 
    //     return 0;
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
    if (!pipe)
        return ""; 
        // throw std::runtime_error("popen() failed!");
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

char* get_cur_time_str(char* time_str, const char* format_str){
    struct tm timeinfo;
    // timeval cur_timeval;
    // gettimeofday (&cur_timeval, NULL);
    // timeinfo = localtime(&cur_timeval.tv_sec);
    // strftime(time_str, 20, format_str, timeinfo);

    std::time_t now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    localtime_r(&now, &timeinfo);
    std::strftime(time_str, 64, format_str, &timeinfo);
    
    return time_str;
}

char* print_chrono_time(std::chrono::time_point<std::chrono::system_clock> time_point, char* time_str){
    struct tm timeinfo;
    std::time_t time_t = std::chrono::system_clock::to_time_t(time_point);
    localtime_r(&time_t, &timeinfo);
    std::strftime(time_str, 64, "%Y-%m-%d %H:%M:%S", &timeinfo);
    return time_str;
}

char* time_in_YYYY_MM_DD(char* time_str){
    return get_cur_time_str(time_str, "%Y-%m-%d");
}

char* time_in_HH_MM_SS(char* time_str){
    return get_cur_time_str(time_str, "%Y-%m-%d %H:%M:%S");
}

char* time_in_HH_MM_SS_nospace(char* time_str){
    return get_cur_time_str(time_str, "%Y-%m-%dT%H:%M:%S");
}

char* time_in_YYYYMMDDHHMMSS(char* time_str){
    return get_cur_time_str(time_str, "%Y%m%d%H%M%S");
}

char* time_in_HH_MM_SS_US(char* time_str){
    struct tm * timeinfo;
    timeval cur_timeval;
    gettimeofday(&cur_timeval, NULL);
    timeinfo = localtime(&cur_timeval.tv_sec);
    char base_time[32] = {0};
    strftime(base_time, sizeof(base_time), "%Y-%m-%d %H:%M:%S", timeinfo);
    snprintf(time_str, 64, "%s.%06ld", base_time, static_cast<long>(cur_timeval.tv_usec));
    return time_str;
}

// void*
// nfq_loop(void *arg)
// {
//     int rv;
//     char buf[65536];
//     //void * placeholder = 0;

//     Optimack* obj = (Optimack*)arg;
//     log_info("nfq_loop thread starts");
//     while (!(obj->nfq_stop)) {
//         rv = recv(obj->g_nfq_fd, buf, sizeof(buf), MSG_DONTWAIT);
//         if (rv >= 0) {
//             //debugs(0, DBG_CRITICAL,"%d", rv);
//             //hex_dump((unsigned char *)buf, rv);
//             //log_debugv("pkt received");
//             nfq_handle_packet(obj->g_nfq_h, buf, rv);
//         }
//         else {
//             if (errno != EAGAIN && errno != EWOULDBLOCK) {
//                 // debugs(0, DBG_CRITICAL,"recv() ret " << rv << " errno " << errno);
//                 // print_func("recv() ret %d errno %d\n", rv, errno);
//             }
//             usleep(100); //10000
//         }
//     }
//     log_info("nfq_loop thread ends");
//     return NULL;
//     //return placeholder;
// }


void adjust_optimack_speed(struct subconn_info* conn, int id, int mode, int offset){
    //mode: 1 - speedup, -1 - slowdown
    if(conn->ack_pacing > 500 && conn->ack_pacing - offset > 10){
        conn->ack_pacing -= mode*offset;
        if(mode == 1)
            print_func("S%d-%d: adjust - speed up by ack_interval by %d to %d!\n", id, conn->local_port, offset, conn->ack_pacing);
        else if(mode == -1)
            print_func("S%d-%d: adjust - slow down by ack_interval by %d to %d!\n", id, conn->local_port, offset, conn->ack_pacing);
        else
            print_func("S%d-%d: unknown mode!\n", id, conn->local_port);
    }
    else {
        conn->payload_len += mode*offset;
        if(mode == 1)
            print_func("S%d-%d: adjust - speed up by ack_pace by %d to %d!\n", id, conn->local_port, offset, conn->ack_pacing);
        else if(mode == -1)
            print_func("S%d-%d: adjust - slow down by ack_pace by %d to %d!\n", id, conn->local_port, offset, conn->ack_pacing);
        else
            print_func("S%d-%d: unknown mode!\n", id, conn->local_port);
        }
}

void adjust_optimack_speed_by_ack_interval(struct subconn_info* conn, int id, int offset)
{
    if(conn->ack_pacing - offset > 10){
        conn->ack_pacing -= offset;
        print_func("S%d-%d: speed up by ack_interval by %d to %d!\n", id, conn->local_port, offset, conn->ack_pacing);
    }
}

void adjust_optimack_speed_by_ack_step(struct subconn_info* conn, int id, int offset)
{
    conn->payload_len += offset;
    print_func("S%d-%d: speed up by ack_step by %d to %d!\n", id, conn->local_port, offset, conn->payload_len);
}


bool Optimack::is_nfq_full(FILE* out_file){
    std::string rst_str = exec("cat /proc/net/netfilter/nfnetlink_queue");
    fprintf(out_file, "cat /proc/net/netfilter/nfnetlink_queue: %s", rst_str.c_str());
    // cout << "cat /proc/net/netfilter/nfnetlink_queue:\n " << rst_str << endl;
    std::vector<std::string> fields = split(rst_str, ' ');
    if(fields.size() > 7){
        if(fields.at(5) != "0" || fields.at(6) != "0"){
            fprintf(out_file, "\n\n###################\nNetfilter Queue too full!\n###################\n");
            return true;
        }
    }
    else
        fprintf(out_file, "Error! nfnetlink_queue result is shorter than 7 fields!");
    return false;
}

void Optimack::print_ss(FILE* out_file){
    char cmd[100];
    snprintf(cmd, 100, "ss -o state established '( sport = %d )' -tnm", squid_port);
    system(cmd);
    // std::string rst_str = exec(cmd);
    // fprintf(out_file, "%s", rst_str.c_str());
    // cout << "cat /proc/net/netfilter/nfnetlink_queue:\n " << rst_str << endl;
    return;
}

bool Optimack::does_packet_lost_on_all_conns(){
    // get_server_write_key(NULL, NULL);
    return false;
}
//     // Packet lost on all connections
//     bool is_all_lost = true;
    
//     // log_debugv("does_packet_lost_on_all_conns: mutex_seq_gaps - trying lock"); 
//     // pthread_mutex_lock(&mutex_seq_gaps);
//     for(size_t i = 0; i < subconn_infos.size(); i++){
//         pthread_mutex_lock(&subconn_infos[i].mutex_opa);
//         // print_func("next_seq_rem %u, cur_ack_rel %u, payload_len %u\n", subconn_infos[i].next_seq_rem, cur_ack_rel, subconn_infos.begin()->payload_len);
//         if (subconn_infos[i].next_seq_rem <= cur_ack_rel){//Why seq_gaps? because squid might drop some packets forwarded to it
//             if(!subconn_infos[i].recved_seq.getIntervalList().empty() && subconn_infos[i].next_seq_rem < subconn_infos[i].recved_seq.getFirstEnd_withLock()){
//                 print_func("Error: subconn_infos[i].next_seq_rem(%u) < subconn_infos[i].seq_gaps.at(0).start(%u)\n", subconn_infos[i].next_seq_rem, subconn_infos[i].seq_gaps.at(0).start);
//             }
            
//             if (subconn_infos[i].next_seq_rem != subconn_infos[i].last_next_seq_rem){
//                 log_debug("S%u: next_seq_rem %u, subconn_infos[i].seq_gaps[0].start %u", i, subconn_infos[i].next_seq_rem, subconn_infos[i].seq_gaps[0].start);  
//                 subconn_infos[i].last_next_seq_rem = subconn_infos[i].next_seq_rem;
//             }
//             is_all_lost = false;
//             pthread_mutex_unlock(&subconn_infos[i].mutex_opa);
//             break;
//         }
//         else if(!subconn_infos[i].seq_gaps.empty() && subconn_infos[i].next_seq_rem == subconn_infos[i].seq_gaps.at(0).start){
//             log_error("S%u: Didn't remove [%u, %u], next_seq_rem %u", i, subconn_infos[i].seq_gaps[0].start, subconn_infos[i].seq_gaps[0].end, subconn_infos[i].next_seq_rem);
//         }
//         pthread_mutex_unlock(&subconn_infos[i].mutex_opa);
//     }

//     if (is_all_lost){
//         // is_nfq_full();

//         print_func("\n\n###################\nPacket lost on all connections. \n###################\n\nlast ack:%d\n", cur_ack_rel);
//         for(size_t i = 1; i < subconn_infos.size(); i++){
//             print_func("S%d-%d: %d\n", i, subconn_infos[i].next_seq_rem);
//         }
//         // if(seq_gaps[0].start < cur_ack_rel){
//         //     print_func("ACK packet, gap removal wrong!!!\n");
//         // }
//         // printIntervals(seq_gaps);
//         log_seq_gaps();
//         // for (int i = 0; i < seq_gaps.size(); i++)
//         //     log_debugv("[%u, %u], ", seq_gaps[i].start, seq_gaps[i].end);

//         // logIntervals(seq_gaps, )
//         sleep(5);
//         exit(-1);
//     }
//     // pthread_mutex_unlock(&mutex_seq_gaps);
//     // log_debugv("does_packet_lost_on_all_conns: mutex_seq_gaps - unlock"); 
    
//     return is_all_lost;    
// }

char empty_payload[] = "";

int Optimack::get_adjusted_rwnd(int cur_ack){
    // return rwnd;
    int cur_rwnd = rwnd * 8 + cur_ack_rel - cur_ack;
    // cur_rwnd = cur_rwnd / squid_MSS * squid_MSS;
    int diff = (int)(cur_rwnd - squid_MSS);
    if (diff <= 0)
        return 0;
    return cur_rwnd;
}

int Optimack::get_adjusted_rwnd_backup(int cur_ack){
    int cur_rwnd = 65535*4 + cur_ack_rel - cur_ack;
    int diff = (int)(cur_rwnd - squid_MSS);
    if (diff <= 0)
        return 0;
    return cur_rwnd;
}

void Optimack::send_optimistic_ack(struct subconn_info* conn, int cur_ack, int adjusted_rwnd){
    if(adjusted_rwnd < conn->win_scale)
        return;
    if(static_cast<uint>(cur_ack) > max_opt_ack)
        max_opt_ack = cur_ack;
    uint cur_win_scaled = adjusted_rwnd / conn->win_scale;
    send_ACK(g_remote_ip, g_local_ip, g_remote_port, conn->local_port, empty_payload, conn->ini_seq_rem + cur_ack, conn->ini_seq_loc + conn->next_seq_loc, cur_win_scaled);
    // printf("[send_optimistic_ack] S%u: sent ack %u, seq %u, tcp_win %u, tcp_win(scaled) %u, payload_len %u, next_seq_rem %u\n", conn->local_port, cur_ack, conn->next_seq_loc, adjusted_rwnd, cur_win_scaled, conn->payload_len, conn->next_seq_rem);
    // log_info("[send_optimistic_ack] S%u: sent ack %u, seq %u, tcp_win %u, tcp_win(scaled) %u, payload_len %u, next_seq_rem %u", conn->local_port, cur_ack, conn->next_seq_loc, adjusted_rwnd, cur_win_scaled, conn->payload_len, conn->next_seq_rem);
    return;
}

void Optimack::send_optimistic_ack_with_SACK(struct subconn_info* conn, int cur_ack, int adjusted_rwnd, IntervalList* recved_seq){
    if(adjusted_rwnd < conn->win_scale)
        return;
    uint cur_win_scaled = adjusted_rwnd / conn->win_scale;
    // send_ACK(g_remote_ip, g_local_ip, g_remote_port, conn->local_port, empty_payload, conn->ini_seq_rem + cur_ack, conn->ini_seq_loc + conn->next_seq_loc, cur_win_scaled);

    unsigned char sack_str[33] = {0};
    int len = generate_sack_blocks(sack_str, 32, recved_seq, conn->ini_seq_rem);//TODO:bug
    char buf[65] = {0};
    int offset = 0;
    for (unsigned char *byte = (unsigned char*)sack_str; byte < ((unsigned char*)sack_str)+len; byte++){ 
        if (offset >= static_cast<int>(sizeof(buf)) - 1) {
            break;
        }
        offset += snprintf(buf + offset, sizeof(buf) - offset, "%02x", *byte);
    }
    log_info("SACK str: %s, len %d", buf, len);
    char empty_payload_local[] = "";
    send_ACK_with_SACK(g_remote_ip, g_local_ip, g_remote_port, conn->local_port, sack_str, len, empty_payload_local, conn->ini_seq_rem + cur_ack, conn->ini_seq_loc + conn->next_seq_loc, cur_win_scaled);
    log_info("[send_optimistic_ack_with_SACK] S%u: sent ack %u, seq %u, tcp_win %u", conn->local_port, cur_ack, conn->next_seq_loc, cur_win_scaled);
    return;
}

int Optimack::send_ACK_adjusted_rwnd(struct subconn_info* conn, int cur_ack){ //std::chrono::time_point<std::chrono::system_clock>& last_send_ack, std::chrono::time_point<std::chrono::system_clock>& last_zero_window){
    // cur_win_scale = obj->rwnd / obj->win_scale;
    int cur_rwnd = rwnd/2 + cur_ack_rel - cur_ack;
    conn->rwnd = cur_rwnd;
    int diff = (int)(cur_rwnd - (int)conn->payload_len*2);
    uint cur_win_scaled = diff <= 0? 0 : cur_rwnd / conn->win_scale;
    send_ACK(g_remote_ip, g_local_ip, g_remote_port, conn->local_port, empty_payload, cur_ack + conn->ini_seq_rem, conn->opa_seq_start, cur_win_scaled);
    log_info("[send_ACK_adjusted_rwnd] S%u: sent ack %u, seq %u, win %d, win_end %u, tcp_win %u", conn->local_port, cur_ack, conn->opa_seq_start - conn->ini_seq_loc, cur_rwnd, rwnd/2 + cur_ack_rel, cur_win_scaled);
    if (diff <= 0)
        return -1;
    return 0;

    // if(conn->is_backup)
        // print_func("obj->rwnd %u, subconn_cur_ack %u, cur_ack_rel %u, conn->rwnd %u\n", obj->rwnd, cur_ack, obj->cur_ack_rel, conn->rwnd);

        // if (conn->is_backup)        
            // print_func("O-bu: ack %u, seq %u, win_scaled %d\n", cur_ack, conn->opa_seq_start - conn->ini_seq_loc, cur_win_scaled);
}


int Optimack::send_optimistic_ack_with_timer(struct subconn_info* conn, int cur_ack, std::chrono::time_point<std::chrono::system_clock>& last_send_ack, std::chrono::time_point<std::chrono::system_clock>& last_zero_window){
    last_send_ack = std::chrono::system_clock::now();
    if(send_ACK_adjusted_rwnd(conn, cur_ack) == 0){
        last_zero_window = std::chrono::system_clock::now();
        return 0;
    }
    else {
        if (!RANGE_MODE && is_timeout_and_update(last_zero_window, 2)){
            log_info("S%u: cur_win_scale == 0", conn->local_port);
            // obj->does_packet_lost_on_all_conns();
            // printIntervals(obj->seq_gaps);
        }
        return -1;
    }
}

void Optimack::update_optimistic_ack_timer(bool is_zero_window, std::chrono::time_point<std::chrono::system_clock>& last_send_ack, std::chrono::time_point<std::chrono::system_clock>& last_zero_window){
    last_send_ack = std::chrono::system_clock::now();
    if(is_zero_window){
        last_zero_window = std::chrono::system_clock::now();
        // log_info("[optack]: set zero window timer to %s\n", print_chrono_time(last_zero_window, time_str));
        return;
    }
    // else {
    //     if (is_timeout_and_update(last_zero_window, 2)){
    //         // log_info("cur_win_scale == 0");
    //     }
    //     return;
    // }    
}

void Optimack::backup_try_fill_gap(){
    struct subconn_info* conn = subconn_infos[backup_port];
    uint last_recved_seq = conn->recved_seq->getFirstStart();
    if(last_recved_seq < cur_ack_rel){
        if(conn->recved_seq->size() > 1){
            // pthread_mutex_lock(conn->recved_seq->getMutex());
            // for (auto it = next(conn->recved_seq->begin()); it != conn->recved_seq->end() && cur_send_seq < cur_ack_rel;it++){
            //     while(it->lower() > cur_send_seq && cur_send_seq+squid_MSS < cur_ack_rel){
            //         send_data_to_backup(cur_send_seq, dummy_payload, squid_MSS);
            //         cur_send_seq += squid_MSS;
            //         // usleep(1500);
            //     }
            //     if(cur_send_seq < cur_ack_rel)
            //         cur_send_seq = it->upper();
            // }
            // pthread_mutex_unlock(conn->recved_seq->getMutex());
        }
    }
}

void* dummy_recv(void* arg){
    long sockfd =(long)arg;
    int rv;
    u_char recv_buf[10000] = {0};
    do{
        rv = recv(sockfd, recv_buf, 10000, 0);
    } while(rv > 0);
    print_func("Sockfd %d: dummy recv exits...\n", sockfd);
    return NULL;
}

#ifdef USE_OPENSSL
void* dummy_recv_ssl(void* arg)
{
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);

    Optimack* obj = (Optimack*)arg;
    obj->dummy_recv_tls();
    // SSL* ssl = (SSL*)arg;
    // if(!ssl)
    //     return NULL;

    // int len=100;
    // char buf[4001];
    // do {
    //     len=SSL_read(ssl, buf, 4000);
    //     if(len == 0)
    //         break;
    //     if(len<0){
    //         print_func("Receive error\n");
    //         usleep(100);
    //         break;
    //     }
    //     buf[len]=0;
    // } while(ssl);
    log_info("Dummy recv ssl ends");
    return NULL;
}

#endif

void* selective_optimistic_ack_trick (void* arg){
    struct int_thread* ack_thr = (struct int_thread*)arg;
    int id = ack_thr->thread_id;
    Optimack* obj = ack_thr->obj;
    struct subconn_info* conn = (obj->subconn_infos[id]);
    free(ack_thr);
    ack_thr = NULL;

    unsigned char recv_buf[1461] = {0};

    std::chrono::time_point<std::chrono::system_clock> last_send_ack, last_data_update, last_log_adjust_rwnd, last_zero_window, last_dup_ack_time;
    last_send_ack = last_data_update = last_log_adjust_rwnd = last_zero_window = last_dup_ack_time = std::chrono::system_clock::now();

    while(!conn->optim_ack_stop){
        obj->backup_try_fill_gap();
        recv(conn->sockfd, recv_buf, 1460, MSG_DONTWAIT);
        usleep(100);
    }
    return NULL;
}

void* selective_optimistic_ack(void* arg){
    struct int_thread* ack_thr = (struct int_thread*)arg;
    int id = ack_thr->thread_id;
    Optimack* obj = ack_thr->obj;
    struct subconn_info* conn = (obj->subconn_infos[id]);
    unsigned int payload_len = conn->payload_len;
    free(ack_thr);
    ack_thr = NULL;

    double send_ack_pace = 1500 / 1000000.0;

    std::chrono::time_point<std::chrono::system_clock> last_send_ack, last_data_update, last_log_adjust_rwnd, last_zero_window, last_dup_ack_time;
    last_send_ack = last_data_update = last_log_adjust_rwnd = last_zero_window = last_dup_ack_time = std::chrono::system_clock::now();
    // bool is_zero_window = true;

    std::set<uint> acks_to_be_sent;
    IntervalList sent_ranges;
    // uint opa_ack_start = 1, opa_ack_end = obj->cur_ack_rel - payload_len;
    uint last_recved_seq = 1, last_dup_ack = 1;
    while(!conn->optim_ack_stop){

        // Add optimack ranges
        if(elapsed(obj->last_ack_time) <= 1){
            if(acks_to_be_sent.empty() || (!acks_to_be_sent.empty() && *acks_to_be_sent.rbegin() < obj->cur_ack_rel)){
                last_recved_seq = conn->recved_seq->getFirstStart();
                if(last_recved_seq && obj->cur_ack_rel >= last_recved_seq+payload_len){
                    uint insert_start = last_recved_seq;//-2*payload_len
                    if(conn->next_seq_rem < obj->cur_ack_rel)
                        insert_start = conn->next_seq_rem - 2*payload_len;
                    uint sent_range_end = sent_ranges.getLastEnd();
                    log_debug("[Backup]: insert_start %u, sent_range_end %u", insert_start, sent_range_end);
                    if (sent_range_end && last_recved_seq < sent_range_end)
                        insert_start = sent_range_end;
                    for(uint i = insert_start; i < obj->cur_ack_rel; i += payload_len){
                        if(i > sent_range_end)
                            acks_to_be_sent.insert(i);
                    }
                    conn->recved_seq->removeInterval(1, obj->cur_ack_rel);
                    log_debug("[Backup]: add optim range [%u,%u], conn->recved_seq after %s\n", insert_start, obj->cur_ack_rel, conn->recved_seq->Intervals2str().c_str());
                }
            }
        }

        //start optimistic ack to recved_seq[0].end, after recved packets to recved_seq[0].end, add [conn->seq_gaps[0].end, obj->recved_seq[0].end]
        // if(elapsed(last_send_ack) >= send_ack_pace){
        //     uint last_inorder_seq = conn->recved_seq->getFirstEnd();

        //     if(opa_ack_cur < last_inorder_seq) //Don't start from 1
        //         opa_ack_cur = last_inorder_seq;

        //     if(last_recved_seq && obj->cur_ack_rel >= last_recved_seq+5*payload_len){
        //         if(opa_ack_cur < last_recved_seq)
        //             opa_ack_cur = last_recved_seq;
        //     }

        //     if(opa_ack_cur < obj->cur_ack_rel){
        //         int adjusted_rwnd = obj->get_adjusted_rwnd(opa_ack_cur);
        //         if(adjusted_rwnd > conn->win_scale){
        //             obj->send_optimistic_ack(conn, opa_ack_cur, adjusted_rwnd);
        //             opa_ack_cur += obj->squid_MSS;
        //         }
        //         obj->update_optimistic_ack_timer(adjusted_rwnd <= 0, last_send_ack, last_zero_window);
        //     }
        // }

        if (!acks_to_be_sent.empty() && elapsed(last_send_ack) >= send_ack_pace){
            uint cur_ack = *acks_to_be_sent.begin();
            int adjusted_rwnd = obj->get_adjusted_rwnd_backup(cur_ack);
            obj->update_optimistic_ack_timer(adjusted_rwnd <= 0, last_send_ack, last_zero_window);
            if(adjusted_rwnd > conn->win_scale){
                obj->send_optimistic_ack(conn, cur_ack, adjusted_rwnd);
                log_info("[Backup]: sent optack %u\n", cur_ack);
                // print_func("[Backup]: sent optack %u\n", cur_ack);
                acks_to_be_sent.erase(acks_to_be_sent.begin());
                sent_ranges.insertNewInterval(cur_ack, cur_ack+payload_len);
                if(cur_ack > obj->backup_max_opt_ack)
                    obj->backup_max_opt_ack = cur_ack;
            }
        }

        // Ignore gaps in optimack_ranges and before
        char tmp[256];
        if(!sent_ranges.getIntervalList().empty()) {
            uint last_recved_seq_end = conn->next_seq_rem;
        //  uint last_recved_seq_end = conn->recved_seq->getLastEnd();
            if (last_recved_seq_end){// && last_cur_ack_rel != last_recved_seq_end){ //&& inIntervals(sent_ranges, cur_ack_rel)){
        //         last_cur_ack_rel = last_recved_seq_end;

                uint sent_range_last_end = sent_ranges.getLastEnd();
                int tmp_offset = snprintf(tmp, sizeof(tmp), "Padding gaps: last_recved_seq_end-%u, sent_ranges.getLastEnd()-%u", last_recved_seq_end, sent_range_last_end);
                if (tmp_offset < 0) {
                    tmp_offset = 0;
                }
                if (last_recved_seq_end > sent_range_last_end){
                    sent_ranges.getIntervalList().clear();
                    for(; !acks_to_be_sent.empty() && *acks_to_be_sent.begin() < last_recved_seq_end; acks_to_be_sent.erase(acks_to_be_sent.begin()));
                    if (static_cast<size_t>(tmp_offset) < sizeof(tmp)) {
                        tmp_offset += snprintf(tmp + tmp_offset, sizeof(tmp) - tmp_offset, " < , ");
                    }
                }
                else if (last_recved_seq_end > sent_ranges.getFirstStart()){
                    sent_ranges.removeInterval(1, last_recved_seq_end);
                    if (static_cast<size_t>(tmp_offset) < sizeof(tmp)) {
                        tmp_offset += snprintf(tmp + tmp_offset, sizeof(tmp) - tmp_offset, " > , ");
                    }
                //     insert_interval_end = last_recved_seq_end; 
                }
                // log_debug(tmp);
                // else // last_recved_seq_end < sent_ranges.begin()->start, not in optimack range, but doesn't matter anymore
                //     insert_interval_end = last_recved_seq_end;
                // conn->recved_seq->insertNewInterval_withLock(1, insert_interval_end);
        //         if (is_timeout_and_update(last_log_adjust_rwnd,2)){
        //             if(!acks_to_be_sent.empty()){
        //                 print_func("%s sent ranges [%u, %u], acks_to_sent[%u, %u]\n", tmp, sent_ranges.getFirstEnd(), sent_ranges.getLastEnd(), *acks_to_be_sent.begin(), *acks_to_be_sent.rbegin());
        //                 log_info("%s sent ranges [%u, %u], acks_to_sent[%u, %u]\n", tmp, sent_ranges.getFirstEnd(), sent_ranges.getLastEnd(), *acks_to_be_sent.begin(), *acks_to_be_sent.rbegin());
        //             }
        //             // conn->recved_seq->printIntervals_withLock();
        //         }
            } 
        }

        if(elapsed(conn->last_data_received) > 2){
            uint inorder_seq_end = conn->recved_seq->getFirstStart();
            if(inorder_seq_end < conn->next_seq_rem && !(inorder_seq_end == last_dup_ack && elapsed(last_dup_ack_time) < 5)){//optack, don't need retranx
                int backup_rwnd_tmp = obj->backup_dup_ack_rwnd;
                if(inorder_seq_end != obj->backup_dup_ack || backup_rwnd_tmp <= conn->win_scale)
                    backup_rwnd_tmp = obj->backup_dup_ack + obj->backup_dup_ack_rwnd - inorder_seq_end;
                if(backup_rwnd_tmp <= conn->win_scale)
                    backup_rwnd_tmp = conn->win_scale*2;
                if(inorder_seq_end < obj->backup_max_opt_ack){
                    print_func("[Backup]: Error! Duplicate ACK(%u) < backup_max_opt_ack(%u)\n\n", inorder_seq_end, obj->backup_max_opt_ack);
                    log_error("[Backup]: Error! Duplicate ACK(%u) < backup_max_opt_ack(%u)\n", inorder_seq_end, obj->backup_max_opt_ack);
                }
                else if(backup_rwnd_tmp > conn->win_scale && inorder_seq_end != last_dup_ack){ // 
                    if(inorder_seq_end > obj->backup_max_opt_ack)
                        obj->backup_max_opt_ack = inorder_seq_end;
                    for (int j = 0; j < 10; j++){
                        // obj->send_optimistic_ack(conn, inorder_seq_end, backup_rwnd_tmp);
                        if(obj->recved_seq.size() >= 2)
                            obj->send_optimistic_ack_with_SACK(conn, inorder_seq_end, obj->rwnd, &obj->recved_seq);
                        else
                            obj->send_optimistic_ack_with_SACK(conn, inorder_seq_end, obj->rwnd, conn->recved_seq);
                        usleep(1000);
                        // send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn->local_port, empty_payload, subconn->ini_seq_rem + inorder_seq_end, ack, cur_win_scale);
                    }
                    print_func("[Backup]: O-bu: retrx - Sent ack %u\n\n", inorder_seq_end);
                    log_info("[Backup]: O-bu: retrx - Sent ack %u\n", inorder_seq_end);
                    last_dup_ack = inorder_seq_end;
                    last_dup_ack_time = std::chrono::system_clock::now();
                }
                else if (backup_rwnd_tmp <= conn->win_scale){
                    print_func("[Backup]: O-bu: retrx - Didn't send ack %u, window < 0\n\n", inorder_seq_end);
                    log_info("[Backup]: O-bu: retrx - Didn't send ack %u, window < 0\n", inorder_seq_end);
                }
            }
        }

        // Overrun detection
        if(is_timeout_and_update(conn->last_data_received, 4)){
            uint ack_restart_start, ack_restart_end;
            if(!sent_ranges.getIntervalList().empty()){
                uint min_ack_sent = sent_ranges.getFirstStart();
                if(min_ack_sent == 0)
                    min_ack_sent = 1;
                ack_restart_start = std::min(min_ack_sent, last_recved_seq); 
                ack_restart_end = *acks_to_be_sent.begin();
                sent_ranges.removeInterval(ack_restart_start, ack_restart_end);
            // else {//Can't use it because it can add normal range to optimistic acks
                // ack_restart_start = conn->next_seq_rem - 2*payload_len;
                // ack_restart_end = obj->cur_ack_rel;
            // }
                int tmp_offset = snprintf(tmp, sizeof(tmp), "O-bu: overrun, restart %u to %u\n", ack_restart_start, ack_restart_end);
                if (tmp_offset < 0) {
                    tmp_offset = 0;
                }
                if(!acks_to_be_sent.empty())
                    if (static_cast<size_t>(tmp_offset) < sizeof(tmp)) {
                        tmp_offset += snprintf(tmp + tmp_offset, sizeof(tmp) - tmp_offset, "Before: [%u, %u]\n", *acks_to_be_sent.begin(), *acks_to_be_sent.rbegin());
                    }
                // std::copy(,acks_to_be_sent.end(), std::ostream_iterator<uint>(std::cout, " "));
                for(uint i = ack_restart_start; i < ack_restart_end; i += payload_len)
                    acks_to_be_sent.insert(i);
                if(!acks_to_be_sent.empty())
                    if (static_cast<size_t>(tmp_offset) < sizeof(tmp)) {
                        snprintf(tmp + tmp_offset, sizeof(tmp) - tmp_offset, "After: [%u, %u]\n", *acks_to_be_sent.begin(), *acks_to_be_sent.rbegin());
                    }
                print_func("%s", tmp);
                log_debug(tmp);
            // delete overruned range from sent_ranges
            }
        }

        // usleep(10);
    }
    conn->optim_ack_stop = 0;
    log_info("S%d-%d-bu: optimistic ack ends", id, conn->local_port);
    return NULL;
}



void* 
Optimack::full_optimistic_ack_altogether()
{
    // pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);

    // struct int_thread* ack_thr = (struct int_thread*)arg;
    // uint id = ack_thr->thread_id;
    // Optimack* obj = ack_thr->obj;
    uint mss = squid_MSS;
    // struct subconn_info* conn = (obj->subconn_infos[id]);
    // free(ack_thr);
    // ack_thr = NULL;

    printf("Optimistic ack started\n");

    auto last_send_ack = std::chrono::system_clock::now(), last_zero_window = std::chrono::system_clock::now(), 
         last_restart  = std::chrono::system_clock::now(), last_overrun_check = std::chrono::system_clock::now();
    unsigned int opa_ack_start = 1,  last_opa_ack = 1, last_stall_seq = 1, last_stall_port = 1;
    long zero_window_start = 0;
    double send_ack_pace = ACKPACING / 1000000.0;
    int adjusted_rwnd_lc = 0;
    struct timespec deadline;

    while (!optim_ack_stop) {
        if (elapsed(last_send_ack) >= send_ack_pace){
            //calculate adjusted window size
            adjusted_rwnd_lc = get_adjusted_rwnd(opa_ack_start);
            adjusted_rwnd = adjusted_rwnd_lc;
            for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
                if(!it->second->is_backup && !it->second->fin_or_rst_recved){
                    // printf("[send_optimistic_ack] S%u: rwnd %d, adjusted_rwnd %d\n", it->second->local_port, it->second->win_scale, adjusted_rwnd);
                    if (adjusted_rwnd < it->second->win_scale){
                            adjusted_rwnd = 0;
                            continue;
                    }
                    
                    // if ((opa_ack_start >= max_opt_ack || (opa_ack_start < max_opt_ack && it->second->next_seq_rem <= opa_ack_start+10*squid_MSS))){ //&& same_restart_cnt < 3 -> this will cause normal optimistic acks are not sent and server missing lots of acks
                        if (ack_end > 1 && opa_ack_start >= ack_end)
                            continue;
                        if(opa_ack_start == last_opa_ack)
                            continue;
                        send_optimistic_ack(it->second, opa_ack_start, adjusted_rwnd);
                        // printf("[send_optimistic_ack] S%u: sent ack %u, seq %u, tcp_win %u\n", it->second->local_port, opa_ack_start, it->second->next_seq_loc, adjusted_rwnd);
                        // log_info("[send_optimistic_ack] S%u: sent ack %u, seq %u, tcp_win %u", it->second->local_port, opa_ack_start, it->second->next_seq_loc, adjusted_rwnd);
                        it->second->opa_ack_start = opa_ack_start;
                    // }
                }
            }
            if(adjusted_rwnd > 0){
                if(opa_ack_start > max_opt_ack){
                    max_opt_ack = opa_ack_start;
                    zero_window_start = 0;
                }
            }
            update_optimistic_ack_timer(adjusted_rwnd <= 0,last_send_ack, last_zero_window);
            if(adjusted_rwnd <= 0){
                zero_window_start = opa_ack_start;
            }
            else {
                last_opa_ack = opa_ack_start;
                if(ack_end > 1 && cur_ack_rel == ack_end && opa_ack_start == ack_end){
                    continue;
                }
                if(zero_window_start == opa_ack_start){
                    struct subconn_info* slowest = get_slowest_subconn(); 
                    if(slowest)
                        opa_ack_start = get_slowest_subconn()->next_seq_rem;
                }
                else
                    opa_ack_start += mss;
            }

            if (SPEEDUP_CONFIG){
                uint min_next_seq_rem = get_min_next_seq_rem();
                if(cur_ack_rel > opa_ack_start && min_next_seq_rem > opa_ack_start){
                    opa_ack_start = cur_ack_rel;
                    print_func("speedup: cur ack %u, to %u\n", opa_ack_start, cur_ack_rel);
                }
            }
        }

        //Overrun detection
        if (elapsed(last_overrun_check) >= 0.1){
            uint min_next_seq_rem = -1;            
            uint stall_seq = 0, stall_port = 0;
            double last_data_received_timeout = 0.5;
            bool is_stall = false;
            pthread_mutex_lock(&mutex_subconn_infos);
            // Get slowest subconn
            struct subconn_info* slowest_subconn = get_slowest_subconn();
            if(slowest_subconn){
                min_next_seq_rem = slowest_subconn->next_seq_rem;
// #ifdef USE_OPENSSL
//                 if(obj->is_ssl)
//                     min_next_seq_rem = slowest_subconn->next_seq_rem_tls; //for tls's optimack overrun recover, otherwise recover won't work
// #endif               

                if(elapsed(slowest_subconn->last_data_received) >= last_data_received_timeout){
                    is_stall = true;
                    stall_port = slowest_subconn->local_port;
                    stall_seq = min_next_seq_rem;

                    // print_func("[Optimack]: S%d-%d stalls at %u\n", stall_port, stall_seq);
                    // snprintf(log, LOGSIZE, "O: S%d-%d stalls at %u\n", slowest_subconn->id, stall_port, stall_seq);
                    if(slowest_subconn->stall_seq != stall_seq){
                        slowest_subconn->restart_counter = 0;
                        slowest_subconn->stall_seq = stall_seq;
                        log_debug("[Optimack]: S%d-%d stalls at %u, min_next_seq_rem %u", slowest_subconn->id, stall_port, stall_seq, min_next_seq_rem);
                        print_func("[Optimack]: S%d-%d stalls at %u, min_next_seq_rem %u\n", slowest_subconn->id, stall_port, stall_seq, min_next_seq_rem);
                    }
                    // last_stall_seq = stall_seq;
                }
            }
            pthread_mutex_unlock(&mutex_subconn_infos);

            if (is_stall){ //zero_window_start - conn->next_seq_rem > 3*conn->payload_len && 
                
                if(abs(int(zero_window_start-stall_seq)) <= 3*mss && elapsed(last_zero_window) <= 0.7){ //zero window, exhausted receive window, waiting for new squid ack   
                    continue;
                }
                if((stall_seq == last_stall_seq && stall_port == last_stall_port && elapsed(last_restart) <= 2) || (stall_seq > last_stall_seq && elapsed(last_restart) <= 2)){
                    continue;
                }

                if(slowest_subconn->restart_counter >= MAX_RESTART_COUNT){
                    if(CONN_NUM == 1 && slowest_subconn->restart_counter == 6){
                        slowest_subconn->restart_counter = 0;//Give one connection more chance
                    }
                    else if(slowest_subconn->restart_counter == MAX_RESTART_COUNT){ //Giving up, retreat it as no overrun
                        opa_ack_start = max_opt_ack;
                        slowest_subconn->stall_seq = max_opt_ack;
                        slowest_subconn->last_data_received = std::chrono::system_clock::now();
                    }
                    slowest_subconn->restart_counter++;
                    continue;
                }

                if(!SPEEDUP_CONFIG && opa_ack_start != ack_end && opa_ack_start <= stall_seq+10*mss){ //
                    continue;
                }

                for (auto it = subconn_infos.begin(); it != subconn_infos.end();it++){
                    
                    if(elapsed(it->second->last_data_received) >= last_data_received_timeout && it->second->restart_counter < MAX_RESTART_COUNT){           
                        uint next_seq_rem = it->second->next_seq_rem;
// #ifdef USE_OPENSSL                
//                         if(obj->is_ssl)
//                             next_seq_rem = it->second->next_seq_rem_tls;
// #endif
                        long next_seq_rem_long = next_seq_rem, stall_seq_long = stall_seq;
                        if(abs(next_seq_rem_long - stall_seq_long) < 5*mss){
                            for(int i = 0; i < 2; i++)
                                send_optimistic_ack(it->second, next_seq_rem, get_adjusted_rwnd(next_seq_rem));
                        }
                        else if(it->second == slowest_subconn){
                            print_func("next_seq_rem %u, stall_seq %u, abs diff %ld\n", next_seq_rem, stall_seq, abs(next_seq_rem_long - stall_seq_long));
                        }
                    }
                }
                usleep(10000);//One RTT, wait for server to send out packets
                uint restart_seq = slowest_subconn->restart_counter < MAX_RESTART_COUNT? stall_seq / mss * mss + 1 + mss : max_opt_ack;//Find the closest optimack we have sent
                opa_ack_start = restart_seq > mss? restart_seq - mss : 1; // - 5*mss to give the server time to send the following packets
                slowest_subconn->restart_counter++;
                    overrun_cnt++;
                    if(stall_seq != last_stall_seq){
                        overrun_penalty += elapsed(slowest_subconn->last_data_received);
                        // same_restart_cnt = 0;
                    }
                    else{
                        overrun_penalty += elapsed(last_restart);
                    }

                last_stall_port = stall_port;
                last_stall_seq = stall_seq;
                last_restart = std::chrono::system_clock::now();
            }
            last_overrun_check = std::chrono::system_clock::now();
        }

        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_nsec += ACKPACING*100/4;
        if(deadline.tv_nsec >= 1000000000) {
            deadline.tv_nsec -= 1000000000;
            deadline.tv_sec++;
        }
        clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
        // usleep(ACKPACING/4);
    }
 
    // conn->optim_ack_stop = 0;
    log_info("Optimistic ack ends");
    // pthread_exit(NULL);
    return NULL;
}

int Optimack::start_optim_ack_backup(uint id, unsigned int opa_ack_start, unsigned int opa_seq_start, unsigned int payload_len, unsigned int seq_max)
{
    subconn_infos[id]->opa_seq_start = opa_seq_start;
    subconn_infos[id]->opa_ack_start = opa_ack_start;
    subconn_infos[id]->opa_seq_max_restart = seq_max;
    subconn_infos[id]->opa_retrx_counter = 0;
    // subconn_infos[id]->payload_len = payload_len;
    // set to running
    subconn_infos[id]->optim_ack_stop = 0;

    // ack thread data
    // TODO: Remember to free in cleanup
    struct int_thread* ack_thr = (struct int_thread*)malloc(sizeof(struct int_thread));
    if (!ack_thr)
    {
        // debugs(0, DBG_CRITICAL, "optimistic_ack: error during thr_data malloc");
        return -1;
    }
    memset(ack_thr, 0, sizeof(struct int_thread));
    ack_thr->thread_id = id;
    ack_thr->obj = this;

    if (pthread_create(&(subconn_infos[id]->thread), NULL, selective_optimistic_ack_trick, (void *)ack_thr) != 0) {
        //debugs(0, DBG_CRITICAL, "Fail to create optimistic_ack thread");
        print_func("S%d: Fail to create optimistic_ack thread\n", id);
        return -1;
    }
    //debugs(1, DBG_CRITICAL, "S" << id <<": optimistic ack thread created");   
    // print_func("S%d-%d: optimistic ack thread created\n", id);
    return 0;
}

int Optimack::start_optim_ack(uint id, unsigned int opa_ack_start, unsigned int opa_seq_start, unsigned int payload_len, unsigned int seq_max)
{
    // subconn_infos[id]->opa_seq_start = opa_seq_start;
    // subconn_infos[id]->opa_ack_start = opa_ack_start;
    // subconn_infos[id]->opa_seq_max_restart = seq_max;
    // subconn_infos[id]->opa_retrx_counter = 0;
    // // subconn_infos[id]->payload_len = payload_len;
    // // set to running
    // subconn_infos[id]->optim_ack_stop = 0;

    // // ack thread data
    // // TODO: Remember to free in cleanup
    // struct int_thread* ack_thr = (struct int_thread*)malloc(sizeof(struct int_thread));
    // if (!ack_thr)
    // {
    //     // debugs(0, DBG_CRITICAL, "optimistic_ack: error during thr_data malloc");
    //     return -1;
    // }
    // memset(ack_thr, 0, sizeof(struct int_thread));
    // ack_thr->thread_id = id;
    // ack_thr->obj = this;

    // if (pthread_create(&(subconn_infos[id]->thread), NULL, full_optimistic_ack, (void *)ack_thr) != 0) {
    //     //debugs(0, DBG_CRITICAL, "Fail to create optimistic_ack thread");
    //     print_func("S%d: Fail to create optimistic_ack thread\n", id);
    //     return -1;
    // }
    // //debugs(1, DBG_CRITICAL, "S" << id <<": optimistic ack thread created");   
    // // print_func("S%d-%d: optimistic ack thread created\n", id);
    return 0;
}

int Optimack::start_optim_ack_altogether(unsigned int opa_ack_start, unsigned int opa_seq_start, unsigned int payload_len, unsigned int seq_max)
{
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        if(!it->second->is_backup){
            it->second->opa_seq_start = opa_seq_start;
            it->second->opa_ack_start = opa_ack_start;
            it->second->opa_seq_max_restart = seq_max;
            it->second->opa_retrx_counter = 0;
            it->second->optim_ack_stop = 0;
        }
    }

    // ack thread data
    // TODO: Remember to free in cleanup
    struct int_thread* ack_thr = (struct int_thread*)malloc(sizeof(struct int_thread));
    if (!ack_thr)
    {
        // debugs(0, DBG_CRITICAL, "optimistic_ack: error during thr_data malloc");
        return -1;
    }
    memset(ack_thr, 0, sizeof(struct int_thread));
    ack_thr->thread_id = 0;
    ack_thr->obj = this;

    std::thread optim_ack_thread(&Optimack::full_optimistic_ack_altogether, getptr());
    optim_ack_thread.detach();
    // if (pthread_create(&optim_ack_thread, NULL, full_optimistic_ack_altogether, (void *)ack_thr) != 0) {
    //     //debugs(0, DBG_CRITICAL, "Fail to create optimistic_ack thread");
    //     print_func("Fail to create optimistic_ack thread\n");
    //     return -1;
    // }
    //debugs(1, DBG_CRITICAL, "S" << id <<": optimistic ack thread created");   
    // print_func("S%d-%d: optimistic ack thread created\n", id);
    return 0;
}

int Optimack::restart_optim_ack(uint id, unsigned int opa_ack_start, unsigned int opa_seq_start, unsigned int payload_len, unsigned int seq_max, std::chrono::time_point<std::chrono::system_clock> &timer)
{
    struct subconn_info* subconn = subconn_infos[id];
    uint seq_rel = opa_ack_start - subconn->ini_seq_rem;

    subconn->optim_ack_stop = 1;
    // subconn->ack_pacing *= 2;
    pthread_join(subconn->thread, NULL);
    print_func("S%d-%d: Restart optim ack from %u\n\n", id, subconn->local_port, seq_rel);
    log_info("S%d-%d: Restart optim ack from %u", id, subconn->local_port, seq_rel);
    start_optim_ack(id, opa_ack_start, opa_seq_start, payload_len, seq_max);//subconn->next_seq_rem
    timer += std::chrono::seconds(8);
    return 0;
}


void Optimack::log_seq_gaps(){
    // Print out all seq_gaps, in rows, transpose later
    print_func("enter log_seq_gaps\n");
    // system("sudo kill -SIGKILL `pidof tcpdump`");
    // system("sudo kill -SIGKILL `pidof tshark`");
    // system("bash /root/squid_copy/src/optimack/test/ks.sh loss_rate");
    // system("bash /root/squid_copy/src/optimack/test/ks.sh mtr");
    // pclose(tcpdump_pipe);

    // pthread_mutex_lock(&mutex_seq_next_global);
    // uint seq_next_global_copy = seq_next_global;
    // pthread_mutex_unlock(&mutex_seq_next_global);
    
    // pthread_mutex_lock(&mutex_subconn_infos);
    // int counts_len = seq_next_global_copy/1460+1;
    // int* counts = (int*)malloc(counts_len*sizeof(int));
    // memset(counts, 0, counts_len);

    // for(size_t j = 1; j < seq_next_global_copy; j+=1460){ //first row
    //     counts[j/1460] = 0;
    // }


    if(is_ssl){
#ifdef USE_OPENSSL
        decrypted_records_map->print_result();
        if(debug_subconn_recvseq){
            for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
                print_func("%d: %s\n", it->first, it->second->recved_seq->Intervals2str().c_str());
            }
        }
        // sleep(10);
#endif
    }
    // map<string, int> lost_per_second;
    // for(size_t k = 0; k < subconn_infos.size(); k++){
    //     size_t n = 1;
    //     pthread_mutex_lock(&subconn_infos[k].mutex_opa);
    //     for(size_t m = 0; m < subconn_infos[k].recved_seq.getIntervalList().size(); m++){
    //         for (; n < subconn_infos[k].seq_gaps[m].start; n+=1460);
    //         for (; n < subconn_infos[k].seq_gaps[m].end; n+=1460){
    //             counts[n/1460]++;
    //             // lost_per_second[subconn_infos[k].seq_gaps[m].timestamp]++;
    //         }
    //         int len = subconn_infos[k].seq_gaps[m].end - subconn_infos[k].seq_gaps[m].start;
    //         if(len < 100){
    //             // print_func("len < 100, S%d-%d: seq_gaps[%u] (%u, %u)\n", k, m, subconn_infos[k].seq_gaps[m].start, subconn_infos[k].seq_gaps[m].end);
    //         }
    //         lost_per_second[subconn_infos[k].seq_gaps[m].timestamp] += len;
    //         // fprintf(lost_per_second_file, "%s, 1\n", subconn_infos[k].seq_gaps[m].timestamp.c_str());
    //     }
    //     pthread_mutex_unlock(&subconn_infos[k].mutex_opa);
    // }

    // std::string line = "";
    // bool lost_on_all = false;
    // for(size_t j = 1; j < seq_next_global_copy; j+=1460){ //first row
    //     if(counts[j/1460] > subconn_infos.size()-9){
    //         lost_on_all = true;
    //         print_func("Packet lost on all connections: %d\n", j/1460);
    //         break;
    //     }
    // }
    // lost_on_all = true;

    // char cmd[2000];
    // char* dir_name = cur_time.time_in_YYYY_MM_DD();
    // sprintf(cmd, "cd /root/rs/large_file_succ_rate/%s; echo >> seq_gaps_count_all.csv; echo Start: $(date -u --rfc-3339=second) >> seq_gaps_count_all.csv; cat seq_gaps_count.csv >> seq_gaps_count_all.csv",dir_name);
    // print_func(cmd);
    // print_func("\n");
    // system(cmd);    

    char time_str[30];
    if(subconn_infos.size() && info_file){

        fprintf(info_file, "Start: %s\n", start_time);
        fprintf(info_file, "Stop: %s\n", time_in_HH_MM_SS_nospace(time_str));
        fprintf(info_file, "Duration: %.2fs\n", elapsed(start_timestamp));
        fprintf(info_file, "IP: %s\nPorts: ", g_remote_ip);
        for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++)
            fprintf(info_file, "%d, ", it->second->local_port);
        fprintf(info_file, "\n");
        fprintf(info_file, "Num of Conn: %d\n", CONN_NUM);
        fprintf(info_file, "ACK Pacing: %d\n", ACKPACING);
        if(RANGE_MODE)
            fprintf(info_file, "Mode: range\n");
        else if(BACKUP_MODE)
            fprintf(info_file, "Mode: backup\n");
        fprintf(info_file, "Overrun count: %d\n", overrun_cnt);
        fprintf(info_file, "Overrun penalty: %.2f\n", overrun_penalty);
        fprintf(info_file, "Range timeout count: %d\n", range_timeout_cnt);
        fprintf(info_file, "Range timeout penalty: %.2f\n", range_timeout_penalty);
        fprintf(info_file, "We2Squid loss count: %d\n", we2squid_lost_cnt);
        fprintf(info_file, "We2Squid loss penalty: %.2f\n", we2squid_penalty);
        if (RANGE_MODE){
            fprintf(info_file, "Packet lost on all: %d\n", all_lost_seq.total_bytes());
            fprintf(info_file, "%s\n", all_lost_seq.Intervals2str().c_str());
            fprintf(info_file, "Packet lost between us and squid: %d\n", we2squid_lost_seq.total_bytes());
            fprintf(info_file, "Range requested: %u\n", requested_bytes);
        }
        fprintf(info_file, "\n");
        is_nfq_full(info_file);
        fprintf(info_file,"\n");
        // fprintf(info_file, "Request: %s\n", request);
        // if(response)
            // fprintf(info_file, "Response: %s\n", response);
        fclose(info_file);
    }

    // free(counts);
    // counts = NULL;
    print_func("Finished writing seq_gaps.\n");
    // pthread_mutex_unlock(&mutex_subconn_infos);
}


void Optimack::remove_iptables_rules(){
    if(iptables_rules.empty())
        return;

    for (size_t i=0; i<iptables_rules.size(); i++) {
        exec_iptables('D', iptables_rules[i]);
        free(iptables_rules[i]);
        iptables_rules[i] = NULL;
    }
    iptables_rules.clear();
}

Optimack::Optimack()
{
    main_fd = 0;
    iptables_rules.clear();
    subconn_infos.clear();
    bytes_per_second.clear();
    recv_buffer_mgr.resetSender(1);
    recved_seq.insertNewInterval(1,UINT_MAX);
    range_stop = -1;
    seq_next_global = 1;
    subconn_count = 0;
    request = response = NULL;
    request_len = response_len = 0;
    g_nfq_qh = NULL;
    g_nfq_h = NULL;
    optim_ack_stop = nfq_stop = overrun_stop = cb_stop = range_stop = -1;
    subconn_infos.clear();
    
    if(use_boost_pool){
        boost_pool = new boost::asio::thread_pool(2);
        if (!boost_pool) {
            print_func("couldn't create boost thread pool\n");
            return;             
        }
    }
    else{
        oracle_pool = thr_pool_create(2, 6, 300, NULL);
        printf("use oracle pool\n");
    }

    range_request_module_.reset(new RangeRequestModule(*this));

#ifdef USE_OPENSSL
    SSL_library_init();
    SSLeay_add_ssl_algorithms();
    SSL_load_error_strings();
    tls_record_seq_map = NULL;
    decrypted_records_map = NULL;
#endif

}


void
Optimack::cleanup()
{
    if(cleaned_up)
        return;

    // print_func("S%d: enter cleanup. Closed.\n", squid_port);
    // log_info("S%d: enter cleanup", squid_port);
    cleaned_up = true;
    
    cb_stop = 1;
    if(!nfq_stop){
        nfq_stop = 1;
        // pthread_cancel(nfq_thread);
    }

    if(!overrun_stop){
        overrun_stop++;
        // pthread_cancel(overrun_thread);
        // log_info("ask overrun_thread to exit");    
        print_func("ask overrun_thread to exit\n");    
    }

    if (range_request_module_) {
        print_func("ask range_watch_thread to exit\n");
        range_request_module_->stop();
    } else if(!range_stop){
        range_stop++;
    }


    if(!optim_ack_stop){
        optim_ack_stop++;
        // pthread_cancel(optim_ack_thread);
        // log_info("ask optimack_altogether_thread to exit");    
        print_func("ask optimack_altogether_thread to exit\n");
    }

#ifdef USE_OPENSSL
    if(!recv_tls_stop){
        recv_tls_stop++;
        // pthread_cancel(recv_thread);
        // log_info("ask dummy_recv_tls to exit");
        print_func("ask dummy_recv_tls to exit\n");
    }
#endif

    if(BACKUP_MODE && backup_port && !subconn_infos[backup_port]->optim_ack_stop){
        subconn_infos[backup_port]->optim_ack_stop++;
        // log_info("ask selective_optimack_thread to exit");
    }

    recv_buffer_mgr.requestStop();

    // if(ask_nfq_stop){
    //     pthread_join(nfq_thread, NULL);
    //     log_info("NFQ %d nfq_thread exited", nfq_queue_num);
    //     print_func("NFQ %d nfq_thread exited", nfq_queue_num);
    // }

    // if(ask_overrun_stop){
    //     pthread_join(overrun_thread, NULL);
    //     print_func("Overrun_thread exit\n");    
    // }

    // if(ask_range_stop){
    //     pthread_join(range_thread, NULL);
    //     print_func("Range_watch_thread exit\n");
    // }

    // if(ask_optim_stop){
    //     pthread_join(optim_ack_thread, NULL);
    //     print_func("Optimack_altogether_thread exit\n");
    // }


    // if(ask_recv_tls_stop){
    //     pthread_join(recv_thread, NULL);
    //     print_func("dummy_recv_tls exited\n");
    // }

    // delete pool;
    if(use_boost_pool){
        if(boost_pool){
            print_func("S%d: cleanup: thr_pool before stop\n", squid_port);
            //pool->shutdown();
            // pool->destroy();
            boost_pool->stop();
            print_func("S%d: cleanup: thr_pool after stop\n", squid_port);
            boost_pool->join();
            print_func("S%d: cleanup: thr_pool after join\n", squid_port);
            delete boost_pool;
            print_func("S%d: cleanup: after thr_pool delete\n", squid_port);
            boost_pool = nullptr;

        }
    }
    else{
        thr_pool_destroy(oracle_pool);
        oracle_pool = NULL;
        log_info("destroy thr_pool");

    }

    if(log_result)
        log_seq_gaps();
    
    if(processed_seq_file)
        fclose(processed_seq_file);

    if(info_file)
        fclose(info_file);

    // stop other optimistic_ack threads and close fd
    // pthread_mutex_lock(&mutex_subconn_infos);
    // for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
    // // for (size_t i=0; i < subconn_infos.size(); i++) {
    //     // TODO: mutex?
    //     if (!it->second->optim_ack_stop) {
    //         it->second->optim_ack_stop++;
    //         pthread_join(it->second->thread, NULL);
    //         close(it->second->sockfd);
    //     }
    // }
    // log_info("NFQ %d all optimistic threads exited", nfq_queue_num);
    // pthread_mutex_unlock(&mutex_subconn_infos);

    // sleep(2);

    // pthread_mutex_lock(&mutex_subconn_infos);
//     for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
//         if(is_ssl){
// #ifdef USE_OPENSSL
//             if(it->second->crypto_coder)
//                 free(it->second->crypto_coder);  
//             // if(it != subconn_infos.begin())
//             //     if(it->second->ssl){
//             //         SSL_shutdown(it->second->ssl);
//             //         SSL_free(it->second->ssl);
//             //         sleep(1);
//             //     }
// #endif
//         }
//         if(it != subconn_infos.begin())
//             close(it->second->sockfd);
//         if(it->second->recved_seq)
//             free(it->second->recved_seq);
//         free(it->second);
//         it->second = NULL;
//     }
//     subconn_infos.clear();
    // clear iptables rules

    // pthread_mutex_unlock(&mutex_subconn_infos);

    // print_func("S%d: cleanup finished\n", squid_port);
    recv_buffer_mgr.clear();
}

Optimack::~Optimack()
{
    print_func("S%d: enter destructor.\n", squid_port);
    // log_info("S%d:enter destructor", squid_port);

    // stop nfq_loop thread
    // pthread_mutex_lock(&mutex_subconn_infos);
    // if(nfq_stop)
    //     return;

    cleanup();

    remove_iptables_rules();
    for (size_t i=0; i<iptables_rules.size(); i++) {
        // exec_iptables('D', iptables_rules[i]);
        free(iptables_rules[i]);
        iptables_rules[i] = NULL;
    }
    iptables_rules.clear();

    request_recved = false;

    if(request){
        free(request);
        request = NULL;
    }
    if(response){
        free(response);
        response = NULL;
    }

    if(is_ssl){
#ifdef USE_OPENSSL
        if(decrypted_records_map)
            delete decrypted_records_map;
        if(tls_record_seq_map)
            delete tls_record_seq_map;
#endif
    }

    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        allconns.erase(it->first);
        if(is_ssl){
#ifdef USE_OPENSSL
            if(it->second->crypto_coder)
                delete (it->second->crypto_coder);  
            if(it->second->tls_rcvbuf)
                delete it->second->tls_rcvbuf;
            if(it != subconn_infos.begin())
                if(it->second->ssl){
                    SSL_shutdown(it->second->ssl);
                    SSL_free(it->second->ssl);
            //         sleep(1);
                }
#endif
        }
        if(it != subconn_infos.begin())
            close(it->second->sockfd);
        if(it->second->recved_seq)
            delete it->second->recved_seq;
        pthread_mutex_destroy(&it->second->mutex_opa);
        delete it->second;
        it->second = NULL;
    }
    subconn_infos.clear();

    // if(open_conns.joinable())
    //     open_conns.join();
    
    // if(range_thread.joinable())
    //     range_thread.join();
    
    // if(open_ssl_thread.joinable())
    //     open_ssl_thread.join();
    
    // if(recv_ssl_thread.joinable())
    //     recv_ssl_thread.join();
    
    // if(request_thread.joinable())
    //     request_thread.join();

    // pthread_mutex_unlock(&mutex_subconn_infos);

     // clear thr_pool
    // if(pool){

    // teardown_nfq();
    // log_info("teared down nfq");

    pthread_mutex_destroy(&mutex_seq_next_global);
    pthread_mutex_destroy(&mutex_subconn_infos);
    pthread_mutex_destroy(&mutex_optim_ack_stop);

    // fclose(seq_gaps_file);
    // fclose(seq_gaps_count_file);
    // exit(2);
    print_func("S%d: ~Optimack completed.\n", squid_port);
}

void
Optimack::init()
{
    // init random seed
    srand(time(NULL));
    
    // init_exp_log("~/rs/exp.log");

    // initializing globals
    sockraw = open_sockraw();
    if (setsockopt(sockraw, SOL_SOCKET, SO_MARK, &MARK, sizeof(MARK)) < 0)
    {
        // debugs(0, DBG_CRITICAL, "couldn't set mark");
        exit(1);
    }

    int portno = 80;
    sockpacket = open_sockpacket(portno);
    if (sockpacket == -1) {
        // debugs(0, DBG_CRITICAL, "[main] can't open packet socket");
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


    char tmp_str[600] = {0}, time_str[64] = {0};
    time_in_YYYY_MM_DD(time_str);
    // home_dir = getenv("HOME");

    strncpy(home_dir, "/root/", sizeof(home_dir) - 1);
    home_dir[sizeof(home_dir) - 1] = 0;
    gethostname(hostname, 20);
    hostname[19] = 0;
    snprintf(output_dir, sizeof(output_dir), "%s/rs/ABtest_onerun/%s/", home_dir, time_str);
    snprintf(tmp_str, sizeof(tmp_str), "mkdir -p %s", output_dir);
    system(tmp_str);
    // print_func("output dir: %s\n", output_dir);

    time_in_YYYYMMDDHHMMSS(start_time);
    char tag[60] = {0};
    snprintf(tag, sizeof(tag), "%s_%doptim+%d*%drange_%s", hostname, CONN_NUM, GROUP_NUM, RANGE_NUM, start_time);

    // char log_file_name[100];
    // sprintf(log_file_name, "/root/off_packet_%s.csv", cur_time.time_in_HH_MM_SS());
    // memset(tmp_str, 0, 600);
    // sprintf(tmp_str, "%s/off_packet_%s.csv", output_dir, hostname);
    // log_file = fopen(tmp_str, "w");
    // fprintf(log_file, "time,off_packet_num\n");
    
    // memset(tmp_str, 0, 600);
    // sprintf(tmp_str, "%s/rwnd_%s.csv", output_dir, hostname);
    // rwnd_file = fopen(tmp_str, "w");
    // fprintf(rwnd_file, "time,rwnd\n");

    // memset(tmp_str, 0, 600);
    // sprintf(tmp_str, "%s/adjust_rwnd_%s.csv", output_dir, tag);
    // adjust_rwnd_file = fopen(tmp_str, "w");
    // fprintf(adjust_rwnd_file, "time,adjust_rwnd\n");

    // memset(tmp_str, 0, 600);
    // sprintf(tmp_str, "%s/range_request_%s_%s.csv", output_dir, hostname, start_time);
    // forward_seq_file = fopen(tmp_str, "w");
    // fprintf(forward_seq_file, "time,fwd_seq_num\n");

    // memset(tmp_str, 0, 600);
    // sprintf(tmp_str, "%s/recv_seq_%s_%s.csv", output_dir, hostname, start_time);
    // recv_seq_file = fopen(tmp_str, "w");
    // fprintf(recv_seq_file, "time,port,recv_seq_num\n");

    // processed_seq_file = NULL;
    snprintf(info_file_name, sizeof(info_file_name), "%s/info_%s.txt", output_dir, tag);
    // sprintf(tmp_str, "%s/%s", output_dir, info_file_name);
    this->info_file = fopen(info_file_name, "w");
    if(!info_file)
        print_func("ERROR: info_file is NULL");
    print_func("info_file is %p", info_file);
    fprintf(this->info_file, "conn,port,id\n");
    fflush(info_file);

    snprintf(tmp_str, sizeof(tmp_str), "%s/processed_seq_%s.csv", output_dir, tag);
    processed_seq_file = fopen(tmp_str, "w");
    fprintf(processed_seq_file, "time,is_range,conn,port,seq_start,seq_end\n");
   
    if(log_squid_ack){
        snprintf(tmp_str, sizeof(tmp_str), "%s/squid_ack_%s.csv", output_dir, tag);
        ack_file = fopen(tmp_str, "w");
        fprintf(ack_file, "time,ack_rel,rwnd\n");
    }

    // sprintf(seq_gaps_count_file_name, "/root/rs/seq_gaps_count_file_%s.csv", cur_time.time_in_HH_MM_SS());
    // sprintf(seq_gaps_count_file_name, "%s/seq_gaps_count_%s_%s.csv", output_dir, start_time, hostname);
    // seq_gaps_count_file = fopen(seq_gaps_count_file_name, "a");


    // sprintf(tmp_str, "%s/lost_per_second_%s.csv", output_dir, hostname);
    // lost_per_second_file = fopen(tmp_str, "a");

    last_speedup_time = last_rwnd_write_time = last_restart_time = last_ack_time = std::chrono::system_clock::now();


    // sprintf(tcpdump_file_name, "tcpdump_%s.pcap", start_time);
    // sprintf(tmp_str,"tcpdump -w %s/%s -s 96 tcp &", output_dir, tcpdump_file_name);
    // sprintf(tmp_str,"tcpdump -w %s/%s -s 96 tcp src port 80 &", output_dir, tcpdump_file_name);
    // system(tmp_str);

    // print_func("test openssl-bio-fetch: %d\n", test_include());
    // sprintf(tcpdump_file_name, "tcpdump_%s.tshark", start_time);
    // sprintf(tmp_str, "tshark -o tcp.calculate_timestamps:TRUE -T fields -e frame.time_epoch -e ip.id -e ip.src -e tcp.dstport -e tcp.len -e tcp.seq -e tcp.ack -e tcp.analysis.out_of_order -E separator=, -Y 'tcp.srcport eq 80 and tcp.len > 0' > %s/%s &", output_dir, tcpdump_file_name);
    // system(tmp_str);
}

void log_seq(FILE* file, uint seq){
    // return;
    fprintf(file, "%f, %u\n", get_current_epoch_time_nanosecond(), seq);
}

void log_seq(FILE* file, int port, uint seq){
    // return;
    fprintf(file, "%f, %d, %u\n", get_current_epoch_time_nanosecond(), port, seq);
}

// int 
// Optimack::setup_nfq(unsigned short id)
// {
//     g_nfq_h = nfq_open();
//     if (!g_nfq_h) {
//         // debugs(0, DBG_CRITICAL,"error during nfq_open()");
//         return -1;
//     }

//     // debugs(0, DBG_CRITICAL,"unbinding existing nf_queue handler for AF_INET (if any)");
//     if (nfq_unbind_pf(g_nfq_h, AF_INET) < 0) {
//         // debugs(0, DBG_CRITICAL,"error during nfq_unbind_pf()");
//         return -1;
//     }

//     // debugs(0, DBG_CRITICAL,"binding nfnetlink_queue as nf_queue handler for AF_INET");
//     if (nfq_bind_pf(g_nfq_h, AF_INET) < 0) {
//         // debugs(0, DBG_CRITICAL,"error during nfq_bind_pf()");
//         return -1;
//     }

//     // set up a queue
//     nfq_queue_num = id;
//     // debugs(0, DBG_CRITICAL,"binding this socket to queue " << nfq_queue_num);
//     g_nfq_qh = nfq_create_queue(g_nfq_h, nfq_queue_num, &cb, (void*)this);
//     if (!g_nfq_qh) {
//         // debugs(0, DBG_CRITICAL,"error during nfq_create_queue()");
//         return -1;
//     }
//     // debugs(0, DBG_CRITICAL,"nfq queue handler: " << g_nfq_qh);

//     // debugs(0, DBG_CRITICAL,"setting copy_packet mode");
//     if (nfq_set_mode(g_nfq_qh, NFQNL_COPY_PACKET, 0x0fff) < 0) {
//         // debugs(0, DBG_CRITICAL,"can't set packet_copy mode");
//         return -1;
//     }

//     unsigned int bufsize = 0x3fffffff, rc = 0;//
//     if (nfq_set_queue_maxlen(g_nfq_qh, bufsize/1024) < 0) {
//         // debugs(0, DBG_CRITICAL,"error during nfq_set_queue_maxlen()\n");
//         return -1;
//     }
//     struct nfnl_handle* nfnl_hl = nfq_nfnlh(g_nfq_h);
//     // for (; ; bufsize-=0x1000){
//     //     rc = nfnl_rcvbufsiz(nfnl_hl, bufsize);
//     //     print_func("Buffer size %x wanted %x\n", rc, bufsize);
//     //     if (rc == bufsize*2)
//     //         break;
//     // }
//     rc = nfnl_rcvbufsiz(nfnl_hl, bufsize);
//     log_info("Buffer size %x wanted %x", rc, bufsize*2);
//     if(rc != bufsize*2){
//         exit(-1);
//     }

//     g_nfq_fd = nfq_fd(g_nfq_h);

//     return 0;
// }

// int 
// Optimack::setup_nfqloop()
// {
//     // pass the Optimack obj
//     nfq_stop = cb_stop = 0;
//     if (pthread_create(&nfq_thread, NULL, nfq_loop, (void*)this) != 0) {
//         // debugs(1, DBG_CRITICAL,"Fail to create nfq thread.");
//         return -1;
//     }
//     return 0;
// }

// int 
// Optimack::teardown_nfq()
// {
//     // log_info("unbinding from queue %d", nfq_queue_num);
//     if (g_nfq_qh && nfq_destroy_queue(g_nfq_qh) != 0) {
//         log_error("error during nfq_destroy_queue()");
//         return -1;
//     }

// #ifdef INSANE
//     /* normally, applications SHOULD NOT issue this command, since
//      * it detaches other programs/sockets from AF_INET, too ! */
//     // debugs(0, DBG_CRITICAL,"unbinding from AF_INET");
//     nfq_unbind_pf(g_nfq_h, AF_INET);
// #endif

//     // debugs(0, DBG_CRITICAL,"closing library handle");
//     if (g_nfq_h && nfq_close(g_nfq_h) != 0) {
//         // debugs(0, DBG_CRITICAL,"error during nfq_close()");
//         return -1;
//     }

//     return 0;
// }



void free_thr_data(struct thread_data* thr_data, const char* str){
    if(thr_data){
        if(thr_data->buf){
            free(thr_data->buf);
            thr_data->buf = NULL;
        }
        // print_func("%s: free thr_data %p\n", str, thr_data);
        delete thr_data;
        thr_data = NULL;
    }
}


void send_partial_optack(char* sip, char* dip, unsigned short srcport, unsigned short dstport, subconn_info* subconn, uint seq, uint ack_start, uint ack_end, uint step){
    for(uint ack_i = ack_start; ack_i < ack_end; ack_i += step){
        send_ACK(dip, sip, 80, subconn->local_port, empty_payload, ack_i, seq, subconn->rwnd);
        usleep(500);
    }
}



#ifndef COLLETIVE_MODE
int 
cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    double cb_start = get_current_epoch_time_nanosecond();
    unsigned char* packet;
    int packet_len = nfq_get_payload(nfa, &packet);

    // sanity check, could be abbr later
    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        printf("cb: can't get_msg_packet_hdr\n");
        return -1;
    }
    int pkt_id = htonl(ph->packet_id);

    struct mytcphdr *tcphdr = tcp_hdr(packet);
    unsigned short sport = ntohs(tcphdr->th_sport);
    unsigned short dport = ntohs(tcphdr->th_dport);
    unsigned short local_port;
    bool incoming = true;
    if(sport == 80 || sport == 443)
        local_port = dport;
    else{
        local_port = sport;
        incoming = false;
    }
    auto find_ret = allconns.find(local_port);
    if (find_ret == allconns.end()) {
        nfq_set_verdict(qh, htonl(ph->packet_id), NF_ACCEPT, packet_len, packet);
        // printf("cb: can't find local port %d\n", local_port);
        // printf("letting through\n");
        return -1;
    }
    subconn_info* subconn = (find_ret->second);
    Optimack* obj = subconn->optack;

    // printf("delay, %d, cb_start, %f, port, %d, obj, %p\n", pkt_id, get_current_epoch_time_nanosecond(), obj->squid_port, obj);


    if(!obj){
        printf("cb: subconn's optmack is null!\n");
        return -1;
    }
    

    struct thread_data* thr_data = new(std::nothrow) struct thread_data();
    if (!thr_data)
    {
        // debugs(0, DBG_CRITICAL, "cb: error during thr_data malloc");
        return -1;
    }
    // print_func("malloc thr_data %p\n", thr_data);
    thr_data->pkt_id = pkt_id;
    thr_data->len = packet_len;
    thr_data->buf = (unsigned char *)malloc(packet_len+1);
    thr_data->incoming = incoming;
    thr_data->subconn = subconn;
    thr_data->obj = subconn->optack;
    thr_data->ttl = 10;
    thr_data->timestamps.push_back(cb_start);
    thr_data->qh = qh;
    if (!thr_data->buf){
            // debugs(0, DBG_CRITICAL, "cb: error during malloc");
        printf("free thr_data %p\n", thr_data);
        delete thr_data;
        return -1;
    }
    memcpy(thr_data->buf, packet, packet_len);
    thr_data->buf[packet_len] = 0;

    if(!forward_packet)
        nfq_set_verdict(qh, thr_data->pkt_id, NF_ACCEPT, packet_len, packet);


    if(multithread == 0)
        pool_handler((void *)thr_data);
    else{
        if(use_boost_pool){
            if(obj->boost_pool)
                boost::asio::post(*obj->boost_pool, [thr_data]{ pool_handler((void *)thr_data); });
        }
        else{
            if(obj->oracle_pool && thr_pool_queue(obj->oracle_pool, pool_handler, (void *)thr_data) < 0) {
                printf("cb: error during thr_pool_queue");
                return -1;
            }
        }
    }
    return 0;
}

#else
int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
    unsigned char* packet;
    int packet_len = nfq_get_payload(nfa, &packet);

    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        printf("cb: can't get_msg_packet_hdr\n");
        return -1;
    }
    // int pkt_id = htonl(ph->packet_id);
    // print_func("cb_range: pkt %d", ph->packet_id);


    struct myiphdr *iphdr = ip_hdr(packet);
    struct mytcphdr *tcphdr = tcp_hdr(packet);
    unsigned char *payload = tcp_payload(packet);
    int payload_len = htons(iphdr->tot_len) - iphdr->ihl*4 - tcphdr->th_off*4;
    unsigned int seq = htonl(tcphdr->th_seq);
    unsigned int ack = htonl(tcphdr->th_ack);

    unsigned short local_port = dport;
    bool incoming = true;
    if(dport == 80 || dport == 443){
        local_port = sport;
        incoming = false;
    }
    

    auto find_ret = allconns.find(local_port);
    if (find_ret == allconns.end()) {
        nfq_set_verdict(qh, htonl(ph->packet_id), NF_ACCEPT, packet_len, packet);
        printf("cb: can't find local port %d\n", local_port);
        printf("letting through\n");
        return -1;
    }
    subconn_info* subconn = (find_ret->second);
    Optimack* obj = subconn->optack;
    if(!obj){
        printf("cb: subconn's optmack is null!\n");
        return -1;
    }

    short protocol = iphdr->protocol;
    if(protocol == 6){
        if(!incoming){
            switch (tcphdr->th_flags) {
                case TH_ACK:
                case TH_ACK | TH_PUSH:
                {
                    pthread_mutex_lock(&subconn->mutex_opa);
                    if(!subconn->seq_init){
                        subconn->ini_seq_rem = ack - 1;
                        subconn->next_seq_rem = ack;
                        subconn->ini_seq_loc = seq - 1;
                        subconn->next_seq_loc = seq + payload_len;
                        subconn->seq_init = true;
                        print_func("R%d-%d: seq_init done - ini_seq_rem 0x%x(%u), ini_seq_loc 0x%x(%u)\n", subconn->id, local_port, subconn->ini_seq_rem, subconn->ini_seq_rem, subconn->ini_seq_loc, subconn->ini_seq_loc);
                        // setsockopt(subconn->sockfd, SOL_SOCKET, SO_MARK, &MARK, sizeof(MARK));
                        
                    }
                    pthread_mutex_unlock(&subconn->mutex_opa);

                    if(subconn->seq_init){
                        subconn->rwnd = htons(tcphdr->th_win);
                        if(subconn->id == 0){
                            obj->cur_ack_rel = ack - subconn->ini_seq_rem;
                        }

                        if(ack > subconn->next_seq_rem){

                            if(ack != subconn->last_next_seq_rem || elapsed(subconn->last_restart_time) > 1){
                                std::thread send_ack_worker = std::thread(send_partial_optack, obj->g_local_ip, obj->g_remote_ip, subconn->local_port, 80, subconn, seq, subconn->next_seq_rem, ack, obj->squid_MSS);
                                send_ack_worker.detach();
                                subconn->last_restart_time = std::chrono::system_clock::now();
                                subconn->last_next_seq_rem = ack;
                            }
                            //  nfq_set_verdict(qh, htonl(ph->packet_id), NF_DROP, packet_len, packet);
                            //  return -1;

                            // tcphdr->th_ack = htonl(subconn->next_seq_rem);
                            // compute_checksums(packet, 20, packet_len);
                            // print_func("[Range]R%d-%d: change ack %x to %x", subconn->id, local_port, ack, subconn->next_seq_rem);
                        }



                    }
                    break;
                }
                default:
                    print_func("[cb_range]R%d-%d: Unknown outgoing packet flag - %d!", subconn->id, local_port, tcphdr->th_flags);
                    break;
            }
        }
        else{
            if(subconn->seq_init && seq > subconn->ini_seq_rem){


                if(subconn->next_seq_loc < ack)
                    subconn->next_seq_loc = ack;
                if(subconn->next_seq_rem < seq + payload_len)
                    subconn->next_seq_rem = seq + payload_len;

                unsigned int seq_rel = seq - subconn->ini_seq_rem;
                // if(subconn->id % 100 == 0){
                //     print_func("[Range]R%d: %d -> %d <%d> seq %d(%x) ack %d(%x) ttl %u plen %d", subconn->id,  sport, dport, (tcphdr->th_flags), seq_rel, seq, ack, ack, iphdr->ttl, payload_len);
                //     nfq_set_verdict(qh, htonl(ph->packet_id), NF_DROP, packet_len, packet);
                //     return -1;
                // }

                switch (tcphdr->th_flags) {
                    case TH_ACK:
                    case TH_ACK | TH_PUSH:
                    case TH_ACK | TH_URG:
                    {
                        if(payload_len){
                            interval_map temp_range = obj->recved_seq.removeInterval(seq_rel, seq_rel + payload_len);
                            // if(temp_range.size()){
                                
                            // }

                            if(temp_range.size()){
                                for (auto it = allconns.begin(); it != allconns.end(); it++)
                                    if(!it->second->is_backup && it->second != subconn){

                                        send_ACK_payload(obj->g_local_ip, obj->g_remote_ip, it->second->local_port, 80, payload, payload_len, it->second->next_seq_loc, it->second->ini_seq_rem+seq_rel);
                                    }
                                print_func("[Range]R%d-%d: [%d, %d] data sent to others", subconn->id, subconn->local_port, seq_rel, seq_rel + payload_len);
                                
                            }
                            //  else if(seq_rel + payload_len < obj->cur_ack_rel) {
                            //     for(uint seq_i = seq_rel+payload_len; seq_i < obj->cur_ack_rel; seq_i += obj->squid_MSS){
				            //     send_ACK(obj->g_remote_ip, obj->g_local_ip, 80, subconn->local_port, empty_payload,subconn->ini_seq_rem+seq_i+payload_len, ack, subconn->rwnd);
                            //     print_func("send_ACK: %s:%d->%s:%d SEQ %x, ACK %x", obj->g_local_ip, subconn->local_port, obj->g_remote_ip, 80, subconn->ini_seq_rem+seq_i+payload_len, ack);
            			    //  }
                        }
                        
                    }
                    break;
                    default:
                        print_func("[cb_range]R%d-%d: Unknown incoming packet flag - %d!",subconn->id, subconn->local_port, tcphdr->th_flags);
                        break;
                }
            }

        }
    }
    nfq_set_verdict(qh, htonl(ph->packet_id), NF_ACCEPT, packet_len, packet);
    return 0;

}
#endif




void* 
pool_handler(void* arg)
{
    //char log[LOGSIZE];
    struct thread_data* thr_data = (struct thread_data*)arg;
    Optimack* obj = (Optimack*)(thr_data->obj);
    u_int32_t id = thr_data->pkt_id;
    int ret = -1;
    // thr_data->timestamps.push_back(get_current_epoch_time_nanosecond());

    // printf("delay, %d, pool_handler_start, %f\n", id, get_current_epoch_time_nanosecond());

    if(!thr_data->buf){
        free_thr_data(thr_data, "pool_handler:2259");
        return NULL;
    }
    // if(obj->cb_stop){
    //     free_thr_data(thr_data, "pool_handler:2263");
    //     return NULL;
    // }

    short protocol = ip_hdr(thr_data->buf)->protocol;
    if (protocol == 6){
        // thr_data->timestamps.push_back(get_current_epoch_time_nanosecond());
        // printf("delay, %d, process_tcp_packet_start, %f\n", id, get_current_epoch_time_nanosecond());
        ret = obj->process_tcp_packet(thr_data);
        // thr_data->timestamps.push_back(get_current_epoch_time_nanosecond());
        // printf("delay, %d, process_tcp_packet_end, %f\n", id, get_current_epoch_time_nanosecond());

    }
    else{ 
        print_func("pool_handler: Invalid protocol: 0x%04x, len %d", protocol, thr_data->len);
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
        // char* hex_str = hex_dump_str(thr_data->buf, thr_data->len);
        //debugs(0, DBG_CRITICAL, hex_str);
        // free(hex_str);
        // hex_str = NULL;
    }

    if(!forward_packet){
        if (ret == 0){
            nfq_set_verdict(thr_data->qh, id, NF_ACCEPT, thr_data->len, thr_data->buf);
            // log_info("Verdict: Accept");
            //debugs(0, DBG_CRITICAL, "Verdict: Accept");
        }
        else{
            nfq_set_verdict(thr_data->qh, id, NF_DROP, 0, NULL);
            // log_info("Verdict: Drop");
            //debugs(0, DBG_CRITICAL, "Verdict: Drop");
        }
    }

    if(ret == -5 && multithread){
        thr_data->ttl--;
        if(thr_data->ttl > 0){
            if(thr_data->ttl == 9){
                print_func("P%d: record_seq_info for seq not found!\n", id);
                // obj->tls_record_seq_map->print_record_seq_map();
            }
            print_func("pool_handler: Seq info not found: reshuffle to work pool, ttl %d\n", thr_data->ttl);
            if(use_boost_pool)
                boost::asio::post(*obj->boost_pool, [thr_data]{ pool_handler((void *)thr_data); });
            // printf("delay, %d, pool_handler_end, %f\n", id, get_current_epoch_time_nanosecond());
            return NULL;
        }
    }

    free_thr_data(thr_data, "pool_handler:2317");
    // double cb_start = thr_data->timestamps[0];
    // printf("delay, %d, %f, %f, %f, %f, %f, ", id, cb_start, ph_start-cb_start, ptp_start-cb_start, ptp_end-cb_start, get_current_epoch_time_nanosecond()-cb_start);
    // for(uint i = 1; i < thr_data->timestamps.size(); i++)
    //     printf("%f, ", thr_data->timestamps.at(i) - cb_start);
    // printf("\n");
    // printf("delay, %d, pool_handler_end, %f\n", id, get_current_epoch_time_nanosecond());
    return NULL;
}


void Optimack::print_seq_table(){
    char time_str[30];
    printf("%s\n", time_in_HH_MM_SS_US(time_str));

    printf("%12s%12s","ID","squid");
    for(uint i = 0; i < subconn_count; i++){
        printf("%12u", i);
    }
    printf("\n");

    printf("%12s%12u","Port", cur_ack_rel);
    
    // for (auto const& [port, subconn] : subconn_infos){
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        printf("%12u", it->second->local_port);
    }
    printf("\n");

    printf("%12s%12u", "Next_seq_rem", recved_seq.getFirstStart());
    // for (auto const& [port, subconn] : subconn_infos){
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
#ifndef COLLETIVE_MODE
        printf("%12u", it->second->next_seq_rem);
#else
        printf("%12u", it->second->next_seq_rem - it->second->ini_seq_rem);
#endif
    }
    printf("\n");

    if(is_ssl){
#ifdef USE_OPENSSL
        printf("%12s%12u", "Next_seq_tls", recved_seq.getFirstStart());
        // for (auto const& [port, subconn] : subconn_infos){
        for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
            printf("%12u", it->second->next_seq_rem_tls);
        }
        printf("\n");
#endif
    }


    printf("%12s%12u", "Restart_cont", ack_end);
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        printf("%12d", it->second->restart_counter);
    }
    printf("\n");

    printf("%12s%12u", "FIN/RST", 0);
    bool is_all_fin_or_rst = true;
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        if(it->second->fin_or_rst_recved)
            printf("%12s", "true");
        else{
            printf("%12s","false");
            is_all_fin_or_rst = false;
        }
    }
    printf("\n");

    printf("SACK: ");
    sack_list.printIntervals();

    printf("Recv_seq: ");
    recved_seq.printIntervals();

    // if(adjust_rwnd_file)
    //     log_seq(adjust_rwnd_file, adjusted_rwnd);

    if(BACKUP_MODE){
        printf("Backup: ");
        subconn_infos[backup_port]->recved_seq->printIntervals();
    }

    if(is_all_fin_or_rst){
        printf("All received FIN/ACK. Send FIN/ACK to %u\n", squid_port);
        // send_FIN_ACK(g_local_ip, g_remote_ip, squid_port, g_remote_port, "", subconn_infos[squid_port]->next_seq_loc, subconn_infos[squid_port]->next_seq_rem);
        // sleep(10);
        // exit(-1);
    }
    // for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
    //     it->second->recved_seq.printIntervals();
    // 
    // for(uint i = 0; i < num_conns; i++){
    //     print_func("%12u", subconn_infos[i].local_port);
    // }
    // print_func("\n");


    // print_func("%12s%12u", "next_seq_rem", recved_seq.getFirstEnd_withLock());
    // for(uint i = 0; i < num_conns; i++){
    //     print_func("%12u", subconn_infos[i].next_seq_rem);
    // }
    // print_func("\n");

    // print_func("%12s%12u", "rwnd", rwnd);
    // for(uint i = 0; i < num_conns; i++){
    //     print_func("%12d", subconn_infos[i].rwnd);
    // }
    // print_func("\n");
    // print_func("\n");
}




void* overrun_detector(void* arg){

    // return NULL;
    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS,NULL);
    
    Optimack* obj = (Optimack* )arg;
    // std::shared_ptr<std::map<uint, struct subconn_info*>> subconn_infos_shared_copy = obj->subconn_infos_shared;

    // std::chrono::time_point<std::chrono::system_clock> *timers = new std::chrono::time_point<std::chrono::system_clock>[num_conns];

    // bool is_all_seq_ini = true;
    // do {
    //     is_all_seq_ini = true;
    //     pthread_mutex_lock(&obj->mutex_subconn_infos);
    //     for (auto it = obj->subconn_infos.begin(); it != obj->subconn_infos.end(); it++){
    //         is_all_seq_ini &= it->second->seq_init;     
    //     }
    //     pthread_mutex_unlock(&obj->mutex_subconn_infos);
    //     sleep(1);
    // } while(!is_all_seq_ini && !obj->overrun_stop);

    // sleep(2);//Wait for the packets to come
    log_info("Start overrun_detector thread");
    print_func("Start overrun_detector thread");


    // auto last_print_seqs = std::chrono::system_clock::now();
    uint count = 0;
    uint last_cur_ack_rel = 0, last_cur_ack_rel_change_sec = 0;

    while(!obj->overrun_stop){
        // if(is_timeout_and_update(last_print_seqs, 1)){
            obj->print_seq_table();
            // obj->is_nfq_full(stdout);
            obj->print_ss(stdout);
            printf("\n");
        // }

        // if (RANGE_MODE) {
        //     // if(is_timeout_and_update(obj->last_ack_time, 2))
        //     obj->try_for_gaps_and_request();
        // }
        struct timespec deadline;
        for(int sec = 0; sec < 1 && !obj->overrun_stop; sec++){
            clock_gettime(CLOCK_MONOTONIC, &deadline);
            deadline.tv_sec++;
            clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
        }
#ifndef COLLETIVE_MODE        
        if(++count == 10){
            for (auto it = obj->subconn_infos.begin(); it != obj->subconn_infos.end(); it++){
                if(it->second->next_seq_rem < 2){
                    print_func("ERROR: Optimistic ACK lost first packet!!!");
                    exit(-1);
                }
            }
        }
        else if(count > 10){
            clock_gettime(CLOCK_REALTIME, &deadline);
            print_func("last_cur_ack_rel %u, deadline.tv_sec %u, last_change_sec %u", last_cur_ack_rel, deadline.tv_sec, last_cur_ack_rel_change_sec);
            if(last_cur_ack_rel < obj->cur_ack_rel){
                last_cur_ack_rel = obj->cur_ack_rel;
                last_cur_ack_rel_change_sec = deadline.tv_sec;
            }
            else if(deadline.tv_sec - last_cur_ack_rel_change_sec >= 15){
                print_func("ERROR: Local packet loss!!!");
                exit(-1);
            }
        }
#endif    
    }

    // free(timers);
    log_info("overrun_detector thread ends");
    print_func("overrun_detector thread ends\n");
    return NULL;
}



uint Optimack::get_min_next_seq_rem(){
    uint min_next_seq_rem = -1;
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        if(!it->second->is_backup && !it->second->fin_or_rst_recved && it->second->restart_counter < MAX_RESTART_COUNT){
            min_next_seq_rem = std::min(min_next_seq_rem, it->second->next_seq_rem);
        }
    }
    return min_next_seq_rem;
}

struct subconn_info* Optimack::get_slowest_subconn(){
    uint min_next_seq_rem = -1;
    struct subconn_info* slowest_subconn = NULL;

    for (auto it = subconn_infos.begin(); it != subconn_infos.end();it++){
        uint next_seq_rem = it->second->next_seq_rem;
// #ifdef USE_OPENSSL
//         if(is_ssl)
//             next_seq_rem = it->second->next_seq_rem_tls;
// #endif
        if(!it->second->is_backup && !it->second->fin_or_rst_recved && next_seq_rem < min_next_seq_rem && it->second->restart_counter < MAX_RESTART_COUNT){
            slowest_subconn = it->second;
            min_next_seq_rem = next_seq_rem;
        }
    }
    return slowest_subconn;
}



int Optimack::generate_sack_blocks(unsigned char * buf, int len, IntervalList* seq_list, uint ini_seq_rem){
    int offset = 0;
    // pthread_mutex_lock(seq_list->getMutex());
    // auto seq_intvl_list = seq_list->getIntervalList();
    // for(int i = 1; i < seq_list->size() && i < 4 && offset+8 <= len; i++){
    //     *((uint32_t*) (buf + offset)) = htonl(seq_intvl_list.at(i).start+ini_seq_rem);
    //     *((uint32_t*) (buf + offset + 4)) = htonl(seq_intvl_list.at(i).end+ini_seq_rem);
    //     log_info("SACK: left %u(%x) - (%x), right %u(%x) - (%x)", seq_intvl_list.at(i).start, seq_intvl_list.at(i).start, *((uint32_t*) (buf + offset)), seq_intvl_list.at(i).end, seq_intvl_list.at(i).end, *((uint32_t*) (buf + offset + 4)));
    //     offset += 8;
    //     // memcpy(buf+offset, &seq_intvl_list.at(i).start, 4);
    //     // offset += 4;
    //     // memcpy(buf+offset, &seq_intvl_list.at(i).end, 4);
    //     // offset += 4;
    // }
    // pthread_mutex_unlock(seq_list->getMutex());
    return offset;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//extract_sack_blocks(): searches for SACK blocks in data packet (kind = 5, length =X)
//	and writes them to sack array sorted in ascending order. 
//	entry sack[0] is reserved for [old SAN-1, new SAN-1]
//	buf points at beginning of TCP options, 
//	nb_sack provides the number of SACK entries found
//++++++++++++++++++++++++++++++++++++++++++++++++
void Optimack::extract_sack_blocks(unsigned char * const buf, const uint16_t len, IntervalList& sack_list, unsigned int ini_seq) {
	//find sack offset
	int offset = find_offset_of_tcp_option(buf, len, 5);
	if(offset == -1){
		return;
	}

	int sack_len = *(buf + offset + 1);
    // print_func("sack_len: %d\n", sack_len);
	offset += 2;
	for (; offset < sack_len; offset += 8)
	{
		unsigned int left = ntohl( *((uint32_t*) (buf + offset)) );
		unsigned int right = ntohl( *((uint32_t*) (buf + offset + 4)) );
        // print_func("left: %x, right %x\n", left, right);
		sack_list.insertNewInterval(left - ini_seq, right - ini_seq);
	}
}

void Optimack::send_request(char* rq, int rq_len){
    if(request)
        free(request);

    request = (char*)malloc(rq_len+1);
    if(!request){
        log_error("send_request: Fail to malloc(%d)\n", rq_len);
        return;
    }
    memcpy(request, rq, rq_len);
    request[rq_len] = 0;
    request_len = rq_len;
    request_recved = true;

    print_func("S%d-%d: send_request(%p): send request len %d, request:\n%s\n", 0, squid_port, this, rq_len, rq);

    if(CONN_NUM > 1){
        send_all_requests();
        log_info("Squid-out: sent request to all connections\n");
    }
}


void Optimack::start_altogether_optimack(){

    // while(optim_ack_stop){
//         std::map<uint, struct subconn_info*>::iterator it;
//         for (it = ++subconn_infos.begin(); it != subconn_infos.end(); it++){
//             uint next_seq_rem_tmp = it->second->next_seq_rem;
//             if(is_ssl)
// #ifdef USE_OPENSSL
//                 // next_seq_rem_tmp = it->second->next_seq_rem_tls;
// #endif
//             if (!it->second->is_backup && it->second->seq_init && next_seq_rem_tmp <= 1){
//                 send_optimistic_ack(it->second, 1, get_adjusted_rwnd(1));
//                 break;
//             }
//         }

//         if(is_ssl){
// #ifdef USE_OPENSSL
//             if(it == subconn_infos.end() && recved_seq.getFirstEnd() > 1) // && elapsed(seq_ini_time) >= 2
//                 start_optimack = true;
// #endif
//         }
//         else if (it == subconn_infos.end() && recved_seq.getFirstEnd() > 1){ //&& elapsed(seq_ini_time) > 2
//             start_optimack = true;
//         }
        
        if(optim_ack_stop == -1){
            optim_ack_stop = 0;
            recv_buffer_mgr.resetSender(cur_ack_rel ? cur_ack_rel : 1);
            std::thread send_squid_worker = std::thread(&Optimack::send_data_to_squid_thread, getptr());
            send_squid_worker.detach();
            if(use_optimack){
                subconn_info* subconn = subconn_infos.begin()->second;
                print_func("Try to start optimistic_ack\n");
                start_optim_ack_altogether(subconn->ini_seq_rem + 1, subconn->next_seq_loc+subconn->ini_seq_loc, squid_MSS, 0); //TODO: read MTU
                print_func("Start optimistic_ack_altogether\n");
                // break;
            }
        }
        // usleep(10);
    // }
}


void Optimack::send_all_requests(){
    // for (size_t i=0; i<obj->subconn_infos.size(); i++) {
    int rv = -1;

    bool all_subconns_created = false;
    while(!all_subconns_created){
        pthread_mutex_lock(&mutex_subconn_infos);
        if(subconn_infos.size() == CONN_NUM)
            all_subconns_created = true;
        pthread_mutex_unlock(&mutex_subconn_infos);
        usleep(10);
    }

    for (auto it = ++subconn_infos.begin(); it != subconn_infos.end(); it++){
        do {
            while(!it->second->tcp_handshake_finished)
                usleep(100);

            if(is_ssl){
#ifdef USE_OPENSSL
                int count;
                for(count = 0; count < 10 && !it->second->tls_handshake_finished; count++)
                    usleep(100);
                if(count == 10)
                    break;

                if(it->second->ssl){
                //     pthread_t recv_thread;
                //     if (pthread_create(&recv_thread, NULL, dummy_recv_ssl, (void*)it->second->ssl) != 0) {
                //         log_error("Fail to create send_all_requests thread.");
                //     }
                    rv = SSL_write(it->second->ssl, request, request_len);
                    print_func("S%d-%d: Push request len=%d to ssl send\n", it->second->id, it->second->local_port, request_len);
                }
#endif
            }
            else{
                pthread_t recv_thread;
                if (pthread_create(&recv_thread, NULL, dummy_recv, reinterpret_cast<void*>(static_cast<intptr_t>(it->second->sockfd))) != 0) {
                    log_error("Fail to create send_all_requests thread.");
                }

                rv = send(it->second->sockfd, request, request_len, 0);
                print_func("S%d-%d: Push request len=%d to sockfd %d.\n", it->second->id, it->second->local_port, request_len, it->second->sockfd);
                // print_func("S%d-%d: Push request len=%d to sockfd %d. Mainconn is sockfd %d, port %d\nRequest: %s\n", it->second->id, it->second->local_port, obj->request_len, it->second->sockfd, obj->subconn_infos.begin()->second->sockfd, obj->subconn_infos.begin()->second->local_port, obj->request);
            }
            if(rv <= 0){
                print_func("S%d-%d: Send request failed, error %d, sockfd %d\n", it->second->id, it->second->local_port, errno, it->second->sockfd);
                break;
            }
        } while(rv < 0);

    }

    print_func("Send request end\n");

    log_info("send_all_requests: leave...");
    return;    
}


int Optimack::process_tcp_packet(struct thread_data* thr_data){
    char log[LOGSIZE+1] = {0};

    struct myiphdr *iphdr = ip_hdr(thr_data->buf);
    struct mytcphdr *tcphdr = tcp_hdr(thr_data->buf);
    unsigned char *tcp_opt = tcp_options(thr_data->buf);
    unsigned int tcp_opt_len = tcphdr->th_off*4 - TCPHDR_SIZE;
    unsigned char *payload = tcp_payload(thr_data->buf);
    int payload_len = htons(iphdr->tot_len) - iphdr->ihl*4 - tcphdr->th_off*4;
    unsigned int seq = htonl(tcphdr->th_seq);
    unsigned int ack = htonl(tcphdr->th_ack);

    subconn_info* subconn = thr_data->subconn;
    bool incoming = thr_data->incoming;

    if (g_remote_ip_int == iphdr->saddr) {
        incoming = true;
    }
    else if (g_remote_ip_int == iphdr->daddr) {
        incoming = false;
    }

    return process_tcp_plaintext_packet(thr_data, tcphdr, seq, ack, tcp_opt, tcp_opt_len, payload, payload_len, incoming, subconn, log);
}



int Optimack::process_tcp_plaintext_packet(
    thread_data* thr_data,
    struct mytcphdr* tcphdr,
    unsigned int seq, unsigned int ack,
    unsigned char *tcp_opt, unsigned int tcp_opt_len,
    unsigned char* payload, int payload_len,
    bool from_server,
    subconn_info* subconn,
    char* log)
{
    (void)tcp_opt;
    (void)tcp_opt_len;

    if(!subconn->tcp_handshake_finished){
        pthread_mutex_lock(&subconn->mutex_opa);
        if(!subconn->tcp_handshake_finished){
            pthread_mutex_unlock(&subconn->mutex_opa);
            return 0;
        }
        pthread_mutex_unlock(&subconn->mutex_opa);
    }

    if(is_ssl){
#ifdef USE_OPENSSL
        if(!subconn->tls_handshake_finished){
            pthread_mutex_lock(&subconn->mutex_opa);
            if(!subconn->tls_handshake_finished){
                pthread_mutex_unlock(&subconn->mutex_opa);
                return 0;
            }
            pthread_mutex_unlock(&subconn->mutex_opa);
        }
#endif
    }

    if (!from_server) {
        return process_tcp_plaintext_outgoing_packet(thr_data, tcphdr, seq, ack, payload, payload_len, subconn, log);
    }
    return process_tcp_plaintext_incoming_packet(thr_data, tcphdr, seq, ack, payload, payload_len, subconn, log);
}

int Optimack::process_tcp_plaintext_outgoing_packet(
    thread_data* thr_data,
    struct mytcphdr* tcphdr,
    unsigned int seq,
    unsigned int ack,
    unsigned char* payload,
    int payload_len,
    subconn_info* subconn,
    char* log)
{
    int pkt_id = thr_data->pkt_id;
    unsigned char* packet = thr_data->buf;
    int packet_len = thr_data->len;
    int subconn_i = subconn->id;
    unsigned short local_port = subconn->local_port;

    switch (tcphdr->th_flags) {
        case TH_ACK:
        case TH_ACK | TH_PUSH:
        case TH_ACK | TH_URG:
        {
            if(!subconn->seq_init){
                log_debugv("P%d-S%d-out: process_tcp_packet:685: subconn->mutex_opa - trying lock", pkt_id, subconn_i);
                pthread_mutex_lock(&subconn->mutex_opa);
                if (!subconn->seq_init) {
                    subconn->ini_seq_rem = ack - 1;
                    subconn->next_seq_rem = 1;
                    subconn->ini_seq_loc = seq - 1;
                    subconn->next_seq_loc = 1 + payload_len;
                    subconn->seq_init = true;
                    seq_ini_time = std::chrono::system_clock::now();
                    print_func("S%d: seq_init done - ini_seq_rem 0x%x(%u), ini_seq_loc 0x%x(%u)\n", local_port, subconn->ini_seq_rem, subconn->ini_seq_rem, subconn->ini_seq_loc, subconn->ini_seq_loc);
                    log_info("S%d: seq_init done - ini_seq_rem 0x%x(%u), ini_seq_loc 0x%x(%u)\n", local_port, subconn->ini_seq_rem, subconn->ini_seq_rem, subconn->ini_seq_loc, subconn->ini_seq_loc);
                }
                pthread_mutex_unlock(&subconn->mutex_opa);
                log_debugv("P%d-S%d-out: process_tcp_packet:685: subconn->mutex_opa - unlock", pkt_id, subconn_i);
            }

            unsigned int seq_rel = seq - subconn->ini_seq_loc;
            log_info(log);

            if (payload_len) {
                try_update_uint_with_lock(&subconn->mutex_opa, subconn->next_seq_loc, seq_rel + payload_len);
                bool pass = false;
                if(seq - subconn->ini_seq_loc == 1){
                    print_func("S%d-%d: Resend first request\n", subconn_i, local_port);
                    pass = true;
                }
                else {
                    pass = true;
                    print_func("S%d-%d: Send request %u\n", subconn_i, local_port, seq_rel);

                    if(is_ssl){
#ifdef USE_OPENSSL
                        struct mytlshdr *tlshdr = (struct mytlshdr*)(payload);
                        int tlshdr_len = htons(tlshdr->length);
                        if(tlshdr->version == subconn->crypto_coder->get_version_reversed()){
                            if(tlshdr->type == TLS_TYPE_APPLICATION_DATA && tlshdr_len > 8){
                                print_func("S%d-%d-out: TLS request, seq %u(%x), len %d\n", subconn_i, local_port, seq - subconn->ini_seq_loc, seq - subconn->ini_seq_loc, payload_len);
                            }
                        }
#endif
                    }
                    tcphdr->th_ack = htonl(subconn->ini_seq_rem + subconn->next_seq_rem);
                    compute_checksums(packet, 20, packet_len);
                }
                if(pass)
                    return 0;
                else
                    return 0;
            }

            if(BACKUP_MODE && !payload_len && subconn->is_backup){
                subconn->recved_seq->removeInterval(1, ack - subconn->ini_seq_rem);
                log_info("[backup]: forward ACK %u", seq_rel);
                return 0;
            }

            if (subconn_i == 0) {
                recv_buffer_mgr.notifyOne();
                this->rwnd = ntohs(tcphdr->th_win) * win_scale;
                if(rwnd > max_win_size)
                    max_win_size = rwnd;
                uint cur_ack_rel_local = ack - subconn->ini_seq_rem;
                this->win_end = cur_ack_rel + rwnd;

                if(log_squid_ack){
                    fprintf(ack_file, "%f, %u, %d\n", get_current_epoch_time_nanosecond(), cur_ack_rel_local, rwnd);
                }
            }
            else{
                log_info("P%d-S%d-out: ack %u, win %d", pkt_id, subconn_i, ack - subconn->ini_seq_rem, ntohs(tcphdr->th_win) * subconn->win_scale);
            }
            return -1;
        }

        case TH_ACK | TH_FIN:
        case TH_ACK | TH_FIN | TH_PUSH:
        {
            char empty_payload[] = "";
            print_func("S%d: received FIN from squid.\n", local_port);
            log_info("%s, received FIN from squid.\n", log);
            send_ACK(g_local_ip, g_remote_ip, local_port, g_remote_port, empty_payload, seq+1, ack);
            return -1;
        }

        default:
            return -1;
    }
}

int Optimack::process_tcp_plaintext_incoming_packet(
    thread_data* thr_data,
    struct mytcphdr* tcphdr,
    unsigned int seq,
    unsigned int ack,
    unsigned char* payload,
    int payload_len,
    subconn_info* subconn,
    char* log)
{
    int pkt_id = thr_data->pkt_id;
    int subconn_i = subconn->id;
    unsigned short local_port = subconn->local_port;

    for(int s = 0; !subconn->seq_init && s < 10; s++)
        usleep(10);

    if(!subconn->seq_init)
        return -1;

    if(seq < subconn->ini_seq_rem)
        return -1;

    unsigned int seq_rel = seq - subconn->ini_seq_rem;

    switch (tcphdr->th_flags) {

        case TH_ACK | TH_FIN:
        case TH_ACK | TH_FIN | TH_PUSH:
        case TH_ACK:
        case TH_ACK | TH_PUSH:
        case TH_ACK | TH_URG:
        {
            if((!payload_len || payload_len == 1) && seq_rel != 1){
                if(!subconn->is_backup){
                    int adjust_rwnd_tmp = get_adjusted_rwnd(seq_rel+1);
                    if(static_cast<uint>(adjust_rwnd_tmp) <= squid_MSS)
                        adjust_rwnd_tmp = squid_MSS;
                    if(seq_rel+1 < max_opt_ack)
                        max_opt_ack = seq_rel + 1;
                }
            }

            if (!payload_len) {
                recved_seq.removeInterval(seq_rel, seq_rel);
                update_subconn_next_seq_rem(subconn, seq_rel + payload_len, tcphdr->th_flags | TH_FIN);
                if (subconn_i)
                    return 0;

                log_info("P%d-S%d-in: server or our ack %u", pkt_id, subconn_i, ack - subconn->ini_seq_loc);
                return -1;
            }

            if(BACKUP_MODE){
                if(subconn->is_backup && subconn->optim_ack_stop){
                    pthread_mutex_lock(&subconn->mutex_opa);
                    if(subconn->is_backup && subconn->optim_ack_stop){
                        start_optim_ack_backup(local_port, subconn->ini_seq_rem + 1, subconn->next_seq_loc + subconn->ini_seq_loc, payload_len, 0);
                        print_func("S%d-%d: Backup connection, not optim ack\n", subconn_i, local_port);
                    }
                    pthread_mutex_unlock(&subconn->mutex_opa);
                }
            }

            if(is_ssl){
#ifdef USE_OPENSSL
                if(subconn->ssl){
                    if(debug_subconn_recvseq)
                        subconn->recved_seq->removeInterval(seq_rel, seq_rel + payload_len);
                    std::map<uint, struct record_fragment> plaintext_buf_local;
                    int verdict = process_incoming_tls_appdata(true, seq_rel, payload, payload_len, subconn, plaintext_buf_local);
                    if(verdict == -5)
                        return verdict;

                    for(auto it = plaintext_buf_local.begin(); it != plaintext_buf_local.end();){
                        unsigned char *ciphertext = it->second.data;
                        int ciphertext_len = it->second.data_len;
                        if(ciphertext_len > 0){
                            log_info("Process cipher packet: seq %u, len %u", it->first, ciphertext_len);
                            process_tcp_packet_with_payload(tcphdr, it->first, ciphertext, ciphertext_len, subconn, log);
                            free(it->second.data);
                            plaintext_buf_local.erase(it++);
                        }
                    }
                    update_subconn_next_seq_rem(subconn, seq_rel + payload_len, tcphdr->th_flags | TH_FIN);
                }
#endif
            }
            else{
                process_tcp_packet_with_payload(tcphdr, seq_rel, payload, payload_len, subconn, log);
            }

            if(TH_FIN & tcphdr->th_flags){
                char empty_payload[] = "";
                print_func("S%d-%d: Received FIN/ACK. Sent FIN/ACK. %u\n", subconn_i, local_port, seq_rel);
                log_info("S%d-%d: Received FIN/ACK. Sent FIN/ACK.", subconn_i, local_port);
                subconn->fin_or_rst_recved = true;
                send_ACK(g_remote_ip, g_local_ip, g_remote_port, local_port, empty_payload, seq+1, ack);
            }
            else
                subconn->fin_or_rst_recved = false;

            if(forward_packet)
                return 0;
            else if(subconn->is_backup)
                return 0;
            else
                return -1;
        }

        case TH_RST:
        case TH_RST | TH_ACK:
        {
            if(!subconn->fin_or_rst_recved){
                print_func("S%d-%d: Received RST. Ignore. Do nothing.\n", subconn_i, local_port);
                subconn->fin_or_rst_recved = true;
            }
        }
        default:
            break;
    }
    return -1;
}
int Optimack::process_tcp_packet_with_payload(struct mytcphdr* tcphdr, unsigned int seq_rel, unsigned char* payload, int payload_len, struct subconn_info* subconn, char* log){

    if(seq_rel == ack_end){
        if(is_ssl){
#ifdef USE_OPENSSL
            print_func("use ssl version get_http_response_header_len\n");
            unsigned char plaintext[MAX_FRAG_LEN+1];
            int plaintext_len = subconn_infos[squid_port]->crypto_coder->decrypt_record(get_record_num(seq_rel), payload, payload_len, plaintext);
            if(plaintext_len > 0)
                get_http_response_header_len(subconn, plaintext, plaintext_len);
#endif
        }
        else
            get_http_response_header_len(subconn, payload, payload_len);
    }


    bool is_new_segment = store_and_send_data(seq_rel, payload, payload_len, subconn, subconn->is_backup, subconn->id);

    update_subconn_next_seq_rem(subconn, seq_rel+payload_len, tcphdr->th_flags & TH_FIN);
    if(subconn->recved_seq->getFirstStart() == 1)
        subconn->recved_seq->removeInterval(seq_rel, seq_rel+payload_len);

    if(recved_seq.getFirstStart() > 1 && optim_ack_stop == -1){
        bool all_received = true;
        for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++)
            if(!it->second->is_backup && it->second->recved_seq->getFirstStart() == 1){
                // print_func("S%d-%d: recved_seq %s", it->second->id, it->second->local_port, it->second->recved_seq->Intervals2str().c_str());
                all_received = false;
                if(it != subconn_infos.begin()){
                    send_optimistic_ack(it->second, 1, get_adjusted_rwnd(1));
                    send_optimistic_ack(it->second, 1, get_adjusted_rwnd(1));
                    send_optimistic_ack(it->second, 1, get_adjusted_rwnd(1));
                }
                else{
                    send_ACK_payload(g_remote_ip, g_local_ip, g_remote_port, it->second->local_port, reinterpret_cast<unsigned char *>(request), request_len, it->second->ini_seq_rem + 1, it->second->ini_seq_loc + 1);
                }
            }
        if(all_received)
            start_altogether_optimack();
    }

    if (BACKUP_MODE && subconn->is_backup){
        //Normal Mode
        subconn->recved_seq->removeInterval(seq_rel, seq_rel+payload_len);
        log_info("[Backup]: insert [%u, %u], after %s\n", seq_rel, seq_rel+payload_len, subconn->recved_seq->Intervals2str().c_str());
    }





    // send_optimistic_ack(subconn, seq_rel+payload_len, get_adjusted_rwnd(seq_rel+payload_len));
    if( (payload_len != static_cast<int>(squid_MSS) && !subconn->is_backup) || (!is_new_segment) ){
        // snprintf(log, LOGSIZE, "%s -unusual payload_len!%d-%d,", log, payload_len, squid_MSS);
        // print_func("%s - unusual payload_len!%d-%d,", log, payload_len, subconn_infos[squid_port]->payload_len);
        // if(elapsed(subconn->last_data_received) > 1.5 && seq_rel+payload_len == subconn->next_seq_rem && seq_rel+payload_len == get_min_next_seq_rem()){
        if(seq_rel+payload_len <= max_opt_ack ){
            // snprintf(log, LOGSIZE, "%s - opt_ack(%u) has passed this point, send ack to unusal len %u", log, max_opt_ack, seq_rel+payload_len);
            // print_func("%s - opt_ack(%u) has passed this point, send ack to unusal len %u", log, max_opt_ack, seq_rel+payload_len);
            int rwnd_tmp = get_adjusted_rwnd(seq_rel+payload_len);
            if(rwnd_tmp > 0)
                send_optimistic_ack(subconn, seq_rel+payload_len, rwnd_tmp);
        // send_ACK_adjusted_rwnd(subconn, seq_rel + payload_len);
        // send_ACK(g_remote_ip, g_local_ip, g_remote_port, subconn->local_port, empty_payload, subconn->ini_seq_rem + seq_rel + payload_len, ack, (cur_ack_rel + rwnd/2 - seq_rel - payload_len)/subconn->win_scale);
        }
        else{
            // snprintf(log, LOGSIZE, "%s - not window full, elapsed(subconn->last_data_received) = %f < 1.5 || seq_rel+payload_len(%u) != subconn->next_seq_rem(%u) || seq_rel+payload_len(%u) != get_min_next_seq_rem(%u)", log, elapsed(subconn->last_data_received), seq_rel+payload_len, subconn->next_seq_rem, seq_rel+payload_len, get_min_next_seq_rem());
        }
    }

    // Too many packets forwarded to squid will cause squid to discard right most packets
    if(!is_new_segment && !subconn->is_backup){
    // if (seq_rel + payload_len <= cur_ack_rel) {
        // print_func("P%d-S%d-%d: discarded\n", pkt_id, subconn_i); 
        log_debug("%s - discarded\n", log);
        return -1;
    }
    return -1;
}


bool Optimack::store_and_send_data(uint seq_rel, unsigned char* payload, int payload_len, struct subconn_info* subconn, bool is_backup, int id){
    
    bool is_new_segment = false;

    uint first_end = recved_seq.getFirstStart();
    if(seq_rel + payload_len <= first_end)
        return false;

    interval_map temp_range = recved_seq.removeInterval(seq_rel, seq_rel + payload_len);
    if(temp_range.size()){
        is_new_segment = true;
        for(auto it = temp_range.begin(); it != temp_range.end(); it++){
            int inserted = insert_to_recv_buffer_withLock(it->first.lower(), payload+it->first.lower()-seq_rel, it->first.upper()-it->first.lower());
            if(inserted){
                if(processed_seq_file){
                    if(!is_backup)
                        fprintf(processed_seq_file, "%f,optim_recv,%d,%u,%u,%u\n", get_current_epoch_time_nanosecond(), id, subconn->local_port, it->first.lower(),it->first.upper());
                   else
                        fprintf(processed_seq_file, "%f,range_recv,%d,%lu,%u,%u\n", get_current_epoch_time_nanosecond(), id, (unsigned long)subconn, it->first.lower(),it->first.upper());
                }
            }
            if(it->second != static_cast<double>(OUT_OF_ORDER)){
                if (!is_backup && subconn)
                    subconn->last_inorder_data_time = std::chrono::system_clock::now();
                recv_buffer_mgr.notifyOne();
                // send_out_of_order_recv_buffer_withLock(first_end);
            }
        }
    }

    return is_new_segment;
}


void Optimack::update_subconn_next_seq_rem(struct subconn_info* subconn, uint num, bool is_fin){
    bool updated = false;
    uint old_next_seq_rem = 0;
    pthread_mutex_lock(&subconn->mutex_opa);
    old_next_seq_rem = subconn->next_seq_rem;
    if (subconn->next_seq_rem < num) {//overlap: seq_next_global:100, seq_rel:95, payload_len = 10
        subconn->next_seq_rem = num;
        updated = true;
        subconn->last_data_received = std::chrono::system_clock::now();
        log_info("S%d: update next_seq_rem to %u", subconn->id, subconn->next_seq_rem);
        if(!is_fin)
            subconn->restart_counter = 0;
        // log_seq(processed_seq_file, local_port, seq_rel);
    }
    pthread_mutex_unlock(&subconn->mutex_opa);

    if (updated) {
        // Fast path: if this subconn was already above the last notified minimum,
        // it cannot raise the global minimum.
        const uint last_notified = range_last_min_next_seq_rem_notified_.load(std::memory_order_relaxed);
        if (old_next_seq_rem > last_notified) {
            return;
        }
        const uint min_next_seq_rem = get_min_next_seq_rem();
        const uint prev = range_last_min_next_seq_rem_notified_.exchange(min_next_seq_rem, std::memory_order_relaxed);
        if (prev != min_next_seq_rem) {
            range_min_next_seq_event_.fetch_add(1, std::memory_order_relaxed);
            range_min_next_seq_cv_.notify_one();
        }
    }
}

bool Optimack::try_update_uint(uint &src, uint target){
    if (src < target) {
        src = target;
        return true;
    }
    return false;
}

bool Optimack::try_update_uint_with_lock(pthread_mutex_t* mutex, uint &src, uint target){
    pthread_mutex_lock(mutex);
    try_update_uint(src, target);
    pthread_mutex_unlock(mutex);
    return true;
}


int Optimack::modify_to_main_conn_packet(struct subconn_info* subconn, struct mytcphdr* tcphdr, unsigned char* packet, unsigned int packet_len, unsigned int seq_rel){
    if(subconn->local_port == squid_port)//Main subconn, return directly
        return 0; 

    tcphdr->th_dport = htons(subconn_infos.begin()->second->local_port);
    tcphdr->th_seq = htonl(subconn_infos.begin()->second->ini_seq_rem + seq_rel);
    tcphdr->th_ack = htonl(subconn_infos.begin()->second->ini_seq_loc + subconn_infos.begin()->second->next_seq_loc);
    compute_checksums(packet, 20, packet_len);
    return 0;
}

int get_localport(int fd){

    struct sockaddr_in my_addr;
    socklen_t len = sizeof(my_addr);
    bzero(&my_addr, len);
    if (getsockname(fd, (struct sockaddr*)&my_addr, &len) < 0) {
        perror("getsockname error");
        close(fd);
        return -1;
    }
    return ntohs(my_addr.sin_port);
}



int
Optimack::exec_iptables(char action, char* rule)
{
    char cmd[IPTABLESLEN+32];
    sprintf(cmd, "/sbin/iptables -%c %s", action, rule);
    FILE* fp = popen(cmd, "r");
    int status = pclose(fp);
    return status;
}

int Optimack::insert_to_recv_buffer_withLock(uint seq, unsigned char* data, int len)
{
    return recv_buffer_mgr.insert(seq, data, len, true) ? 1 : 0;
}

int Optimack::insert_to_recv_buffer(uint seq, unsigned char* data, int len)
{
    return recv_buffer_mgr.insert(seq, data, len, false) ? 1 : 0;
}

int Optimack::send_out_of_order_recv_buffer_withLock(uint seq){
    return send_out_of_order_recv_buffer(seq);
}

int Optimack::send_out_of_order_recv_buffer_withLock(uint start, uint end, int max_count){
    return send_out_of_order_recv_buffer(start, end, max_count);
}

int Optimack::send_out_of_order_recv_buffer_withLock(uint start, uint end){
    return send_out_of_order_recv_buffer(start, end);
}

int Optimack::send_out_of_order_recv_buffer(uint start, uint end, int max_count)
{
    return recv_buffer_mgr.sendOutOfOrder(start, end, max_count, [this](uint seq, unsigned char* payload, int payload_len) {
        send_data_to_squid(seq, payload, payload_len);
    });
}


int Optimack::send_out_of_order_recv_buffer(uint start, uint end)
{
    return recv_buffer_mgr.sendOutOfOrder(start, end, [this](uint seq, unsigned char* payload, int payload_len) {
        send_data_to_squid(seq, payload, payload_len);
    });
}


int Optimack::send_last_inorder_recv_buffer_withLock(uint end)
{
    return recv_buffer_mgr.sendLastInorder(end, [this](uint seq, unsigned char* payload, int payload_len) {
        send_data_to_squid(seq, payload, payload_len);
    });
}


int Optimack::send_data_to_squid_thread(){
    return recv_buffer_mgr.senderLoop(
        debug_rb,
        [this](uint seq, unsigned char* payload, int payload_len) {
            send_data_to_squid(seq, payload, payload_len);
        },
        [this](uint ack_seq) {
            cur_ack_rel = ack_seq;
        }
    );
}


int Optimack::send_out_of_order_recv_buffer(uint seq)
{
    return recv_buffer_mgr.sendOutOfOrder(seq, [this](uint seq_start, unsigned char* payload, int payload_len) {
        send_data_to_squid(seq_start, payload, payload_len);
    });
}

int Optimack::remove_recved_recv_buffer_withLock(uint seq){
    return remove_recved_recv_buffer(seq);
}


int Optimack::remove_recved_recv_buffer(uint seq)
{
    return recv_buffer_mgr.removeReceived(seq);
}

void Optimack::send_data_to_backup(unsigned int seq, unsigned char* payload, int payload_len){
    send_data_to_subconn(subconn_infos[backup_port], true, seq, payload, payload_len);
}

void Optimack::send_data_to_squid(unsigned int seq, unsigned char* payload, int payload_len){
    if(debug_rb) print_func("send_data_to_squid: try to send [%d, %d] to squid", seq, seq+payload_len);
    // ((Client*)squid_client_conn)->addVirginReplyBody(payload, payload_len);
    while(true){
        int rv = send(client_fd, payload, payload_len, 0);
        if (rv > 0){
            if(debug_rb) print_func("send_data_to_squid: sent [%d, %d] to squid", seq, seq+payload_len);
            break;
        }
        else{
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK || errno == 9){
                usleep(10);
                continue;
            }
            else{
                print_func("send_data_to_squid: try to send [%d, %d] to squid failed, %d", seq, seq+payload_len, errno);
                break;
            }
        }
    }
}

void Optimack::send_data_to_subconn(struct subconn_info* conn, bool to_client, unsigned int seq, unsigned char* payload, int payload_len){
    if(!payload || !payload_len){
        print_func("send_data_to_subconn: payload is NULL or payload_len == 0\n");
        return;
    }

    int packet_len = 0;
    for(int unsent = payload_len, sent = 0; unsent > 0; unsent -= packet_len, sent += packet_len){
        packet_len = static_cast<uint>(unsent) >= squid_MSS ? static_cast<int>(squid_MSS) : unsent;
        unsigned char* payload_to_send = payload+sent;
        if(to_client){
            unsigned int seq_to_send = conn->ini_seq_rem + seq + sent;
            send_ACK_payload(g_local_ip, g_remote_ip, conn->local_port, g_remote_port, payload_to_send, packet_len, conn->ini_seq_loc + conn->next_seq_loc, seq_to_send);
            log_info("send_data_to_subconn: seq %u, ack %u, len %d, seq_next %u", seq+sent, conn->next_seq_loc, packet_len, seq+sent+packet_len);
        }
        else{
            unsigned int seq_to_send = conn->ini_seq_loc + seq + sent;
            send_ACK_payload(g_remote_ip, g_local_ip, g_remote_port, conn->local_port, payload_to_send, packet_len, conn->ini_seq_rem + conn->next_seq_rem, seq_to_send);
            log_info("send_data_to_server: seq %u, ack %u, len %d, seq_next %u", seq+sent, conn->next_seq_rem, packet_len, seq+sent+packet_len);
        }
        // usleep(100);
    }
}

void Optimack::send_data_to_server_and_update_seq(struct subconn_info* conn, unsigned char* payload, int payload_len){
    send_data_to_subconn(conn, false, conn->next_seq_loc, payload, payload_len);
    conn->next_seq_loc += payload_len;
}

struct subconn_info* Optimack::create_subconn_info(int sockfd, bool is_backup){
    struct tcp_info tcp_info = {};
    socklen_t tcp_info_length = sizeof(tcp_info);
    if ( getsockopt(sockfd, SOL_TCP, TCP_INFO, (void *)&tcp_info, &tcp_info_length ) == 0 ) {
    //     print_func("Squid: snd_wscale-%u, rcv_wscale-%u, snd_mss-%u, rcv_mss-%u, advmss-%u, %u %u %u %u %u %u %u %u %u %u %u %u\n",
    //         tcp_info.tcpi_snd_wscale,
    //         tcp_info.tcpi_rcv_wscale,
    //         tcp_info.tcpi_snd_mss,
    //         tcp_info.tcpi_rcv_mss,
    //         tcp_info.tcpi_advmss,
    //         tcp_info.tcpi_last_data_sent,
    //         tcp_info.tcpi_last_data_recv,
    //         tcp_info.tcpi_snd_cwnd,
    //         tcp_info.tcpi_snd_ssthresh,
    //         tcp_info.tcpi_rcv_ssthresh,
    //         tcp_info.tcpi_rtt,
    //         tcp_info.tcpi_rttvar,
    //         tcp_info.tcpi_unacked,
    //         tcp_info.tcpi_sacked,
    //         tcp_info.tcpi_lost,
    //         tcp_info.tcpi_retrans,
    //         tcp_info.tcpi_fackets
    //         );
    }
    
    struct subconn_info *new_subconn = new(std::nothrow) struct subconn_info();
    if(!new_subconn){
        print_func("create_subconn_info: Can't allocate subconn_info\n");
        return NULL;
    }
    new_subconn->sockfd = sockfd;
    new_subconn->local_port = get_localport(sockfd);
    new_subconn->ini_seq_loc = new_subconn->next_seq_loc = 0;
    new_subconn->ini_seq_rem = new_subconn->next_seq_rem = 0;
    new_subconn->last_next_seq_rem = 0;
    new_subconn->win_scale = 1 << tcp_info.tcpi_rcv_wscale;
    new_subconn->payload_len = tcp_info.tcpi_snd_mss;
    new_subconn->ack_pacing = ACKPACING;
    new_subconn->ack_sent = 0;
    new_subconn->optim_ack_stop = 1;
    pthread_mutex_init(&new_subconn->mutex_opa, NULL);
    new_subconn->last_data_received = new_subconn->timer_print_log = std::chrono::system_clock::now();
    new_subconn->is_backup = is_backup;
    new_subconn->seq_init = false;
    new_subconn->fin_or_rst_recved = false;
    new_subconn->tcp_handshake_finished = true;
    new_subconn->recved_seq = new IntervalList();
    new_subconn->recved_seq->insertNewInterval(1,UINT_MAX);
    new_subconn->optack = this;

    // fprintf(processed_seq_file, "%d ", new_subconn->local_port);

    if(is_ssl){
#ifdef USE_OPENSSL
        new_subconn->tls_handshake_finished = false;
#endif
    }

    return new_subconn;
}

int Optimack::insert_subconn_info(std::map<uint, struct subconn_info*> &subconn_infos_, uint& subconn_count_, struct subconn_info* new_subconn){
    new_subconn->id = subconn_count_++;
    subconn_infos_.insert(std::pair<uint, struct subconn_info*>(new_subconn->local_port, new_subconn));
    allconns.insert(std::pair<uint, struct subconn_info*>(new_subconn->local_port, new_subconn));
    print_func("S%d-%d: established, inserted into allconns\n", subconn_count-1, new_subconn->local_port);

    int nfq_queue_num = 333;
    char *cmd = (char*) malloc(IPTABLESLEN);
    sprintf(cmd, "PREROUTING -t mangle -p tcp -s %s --sport %d --dport %d -j NFQUEUE --queue-num %d", g_remote_ip, g_remote_port, new_subconn->local_port, nfq_queue_num);
    exec_iptables('A', cmd);
    iptables_rules.push_back(cmd);

    cmd = (char*) malloc(IPTABLESLEN);
    sprintf(cmd, "OUTPUT -p tcp -d %s --dport %d --sport %d -j NFQUEUE --queue-num %d", g_remote_ip, g_remote_port, new_subconn->local_port, nfq_queue_num);
    exec_iptables('A', cmd);
    iptables_rules.push_back(cmd);

    if(!new_subconn->is_backup){
        if(processed_seq_file) fprintf(processed_seq_file, "%f,creation,%d,%u,-1,-1\n", get_current_epoch_time_nanosecond(), new_subconn->id, new_subconn->local_port);

        if(info_file) fprintf(info_file, "Optim_conn, %d, %d\n", new_subconn->local_port, new_subconn->id);
        fflush(info_file);
    }


    return 0;
}



void Optimack::open_one_duplicate_conn(std::map<uint, struct subconn_info*> &subconn_info_dict, bool is_backup){
    int sockfd = establish_tcp_connection(0, g_remote_ip, g_remote_port);
    if(sockfd <= 0){
        print_func("S%d: open_one_duplicate_conn: establish tcp connection failed\n", squid_port);
        return;
    }
    struct subconn_info* new_subconn = create_subconn_info(sockfd, is_backup);

    pthread_mutex_lock(&mutex_subconn_infos);
    insert_subconn_info(subconn_infos, subconn_count, new_subconn);
    pthread_mutex_unlock(&mutex_subconn_infos);

    if(BACKUP_MODE && is_backup){
        backup_port = new_subconn->local_port;
    }

}


void 
Optimack::set_main_subconn(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port, int fd)
{
    print_func("open_duplicate_conns: remote %s:%u, local %s:%u, CONN_NUM %d, ACK PACE %d\n", remote_ip, remote_port, local_ip, local_port, CONN_NUM, ACKPACING);

    if(main_fd){
        print_func("open_duplicate_conns: main_fd has already been assigned! new(%d) - old(%u)\n", main_fd, fd);
    }


    time_in_HH_MM_SS_nospace(start_time);
    start_timestamp = std::chrono::system_clock::now();


    // unsigned int size = 6291456/2;
    // if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (char *) &size, sizeof(size)) < 0) {
    //     print_func("Error: can't set SOL_SOCKET to %u!\n", size);
    // }


    main_fd = fd;
 
    strncpy(g_local_ip, local_ip, 16); //TODO: change position
    strncpy(g_remote_ip, remote_ip, 16);
    g_local_ip[15] = 0;
    g_remote_ip[15] = 0;
    inet_pton(AF_INET, local_ip, &g_local_ip_int);
    inet_pton(AF_INET, remote_ip, &g_remote_ip_int);
    g_remote_port = remote_port;
    squid_port = local_port;
    
    dstAddr.sin_family = AF_INET;
    memcpy((char*)&dstAddr.sin_addr, &g_remote_ip_int, sizeof(g_remote_ip_int));


    subconn_infos.clear();
    struct subconn_info* squid_conn = create_subconn_info(fd, false);
    insert_subconn_info(subconn_infos, subconn_count, squid_conn);
    squid_MSS = squid_conn->payload_len;
    log_info("[Squid Conn] port: %d, win_scale %d", squid_port, squid_conn->win_scale);

    open_conns = std::thread(&Optimack::open_duplicate_conns, getptr());
    open_conns.detach();
}

void* open_duplicate_conns_handler(void* arg){
    Optimack* obj = (Optimack*)arg;
    obj->open_duplicate_conns();
    return NULL;
}


int Optimack::open_duplicate_conns(){
    print_func("S%d: open_duplicate_conns\n", squid_port);

    for (int i = 1; i < CONN_NUM; i++) {
        std::thread open_conn(&Optimack::open_one_duplicate_conn, getptr(), std::ref(subconn_infos), false);
        open_conn.detach();
        // open_one_duplicate_conn(subconn_infos, false);
    }

#ifndef COLLETIVE_MODE
    if (RANGE_MODE) {
        if (range_request_module_) {
            range_request_module_->start();
        }
    }

    if (BACKUP_MODE){
        int backup_num = 1;
        for (int i = 0; i < backup_num; i++) {
            std::thread open_conn(&Optimack::open_one_duplicate_conn, getptr(), std::ref(subconn_infos), true);
            open_conn.detach();
            // open_one_duplicate_conn(subconn_infos, true);
        }
    }
#endif
    if(print_per_sec_on && overrun_stop == -1){
        overrun_stop++;
        if (pthread_create(&overrun_thread, NULL, overrun_detector, (void*)this) != 0) {
            log_error("Fail to create overrun_detector thread.");
        }
        print_func("S%d: overrun thread created\n", squid_port);
    }

    print_func("open_duplicate_conns: exiting...\n");
    return 0;
}


bool is_static_object(std::string request){

    bool static_object = false;
    std::vector<std::string> whitelist = {"image", "video", "audio", "font", "x-7z-compressed", "pdf", "json", "x-tar", "gzip", "zip", "*"};
    
    std::vector<std::string> request_fields = split(request, '\n');
    for(auto const& s : request_fields){

        std::vector<std::string> s_fields = split(s, ':');
        if(s_fields.at(0).compare("Host") == 0){
            if(s_fields.at(1).find("mozilla.com") != std::string::npos){
                print_func("pre-loaded URI: %s, skipped\n", s_fields.at(1).c_str());
                return false;
            }
        }
        else if(s_fields.at(0).compare("Accept") == 0){
            std::vector<std::string> accept_fields = split(s_fields.at(1).substr(1, s_fields.at(1).size()-1), ',');
            std::cout << accept_fields.at(0) << std::endl;
            std::vector<std::string> first_type = split(accept_fields.at(0),'/');
            std::cout << first_type.at(0) << std::endl;
            if(std::find(whitelist.begin(), whitelist.end(), first_type.at(0)) != whitelist.end() ||
               std::find(whitelist.begin(), whitelist.end(), first_type.at(1)) != whitelist.end()){
                   static_object = true;
                   std::cout << "Is static_object: " << accept_fields.at(0) << std::endl; 
            }
            else if(first_type.at(0) == "text" && first_type.at(1) == "ccs"){
                static_object = true;
                std::cout << "Is static_object: " << accept_fields.at(0) << std::endl;
            }
        }
    }
    return static_object;
}


#ifdef USE_OPENSSL
int Optimack::set_main_subconn_ssl(SSL *squid_ssl){
    if(is_ssl){
        return 0;
    }    
    print_func("enter open_duplicate_ssl_conns, ssl %p\n", squid_ssl);
    is_ssl = true;

    struct subconn_info* squid_subconn = subconn_infos[squid_port];
    set_subconn_ssl_credentials(squid_subconn, squid_ssl);
    squid_MSS = squid_subconn->payload_len;
    decrypted_records_map = new TLS_Decrypted_Records_Map(squid_subconn->crypto_coder);
    tls_record_seq_map = new TLS_Record_Number_Seq_Map();
    tls_record_seq_map->set_localport(squid_port);
    recved_seq.clear();
    recved_seq.insertNewInterval(1,UINT_MAX);

    open_ssl_thread = std::thread(&Optimack::open_duplicate_ssl_conns, Optimack::getptr());
    open_ssl_thread.detach();
    print_func("S%d: open_duplicate_ssl_conns thread created. set_main_subconn_ssl exits.\n", squid_port);


    return 0;
}


int Optimack::open_duplicate_ssl_conns(){
    /*** bug: if we combine three blocks into one for loop, 
       * previous connections are set to be handshake finished, 
       * when retranx of previous connections' handshake packets arrive,
       * it will block at obtaining mutex_subconn_infos, which is in use by current for loop,
       * because not all ssl connnections have been opened, which caused all threads in deadlock,
       * preventing the handshake packets of current opening connections to pass
    ***/
    // pthread_mutex_lock(&mutex_subconn_infos);
    // for(auto it = ++subconn_infos.begin(); it != subconn_infos.end(); it++){
    //     it->second->handshake_finished = false;
    // }
    // pthread_mutex_unlock(&mutex_subconn_infos);
    // std::shared_ptr<std::map<uint, struct subconn_info*>> subconn_infos_shared_copy = subconn_infos_shared;

    if(subconn_infos.size() < 2){
        print_func("open_duplicate_ssl_conns: subconn_infos.size() < 2\n");
        return -1;
    }

    print_func("S%d: create open_duplicate_ssl_conns\n", squid_port);
    for(auto it = ++subconn_infos.begin(); it != subconn_infos.end(); it++){
        if(it->second){
            SSL* ssl = open_ssl_conn(it->second->sockfd, false);
            if(ssl){
                set_subconn_ssl_credentials(it->second, ssl);
                it++;
            }
            else{
                it->second->is_ssl = false;
                allconns.erase(it->first);
            }
        }
    }
                             
    recv_tls_stop = 0;
    print_func("S%d: create dummy_recv_ssl\n", squid_port);
    recv_ssl_thread = std::thread(&Optimack::dummy_recv_tls, Optimack::getptr());
    recv_ssl_thread.detach();
    return 0;
}


int Optimack::set_subconn_ssl_credentials(struct subconn_info *subconn, SSL *ssl){
    if(!ssl){
        print_func("Set subconn ssl credentials: S%d-%d, null ssl.\n", subconn->id, subconn->local_port);
        return -1;
    }

    unsigned char write_key_buffer[100],iv_salt[5];
    const EVP_MD *digest_algorithm = SSL_CIPHER_get_handshake_digest(SSL_SESSION_get0_cipher(SSL_get_session(ssl)));
    const EVP_CIPHER *evp_cipher = EVP_get_cipherbyname("AES-128-GCM"); // Temporary Ugly hack here for Baidu.

    get_write_key(ssl, digest_algorithm, evp_cipher, iv_salt, write_key_buffer);

    subconn->lock();
    subconn->ssl = ssl;
    subconn->seq_init = false;
    subconn->tls_handshake_finished = true;
    subconn->crypto_coder = new TLS_Crypto_Coder(evp_cipher, iv_salt, write_key_buffer, 0x0303, subconn->local_port);
    subconn->tls_rcvbuf = new TLS_Encrypted_Record_Reassembler(MAX_FULL_GCM_RECORD_LEN, 0x0303, subconn->crypto_coder);
    subconn->record_size = MAX_FULL_GCM_RECORD_LEN;
    if(subconn->record_size < static_cast<int>(subconn->payload_len))
        subconn->payload_len = subconn->record_size;

    subconn->unlock();
    return 0;
}


void Optimack::dummy_recv_tls(){
    fd_set readfds;
    int ret = 0;
    int maxfdp1 = -1;
#define BUFSIZE 4001
    char buf[BUFSIZE] = {0};

    print_func("S%d: dummy recv tls starts\n", squid_port);

    std::vector<int> sockfds;
    std::vector<SSL*> ssls;
    for(auto it = ++subconn_infos.begin(); it != subconn_infos.end(); it++){
        fcntl(it->second->sockfd, F_SETFL, O_NONBLOCK);
        sockfds.push_back(it->second->sockfd);
        ssls.push_back(it->second->ssl);
    }
    int sockfd_size = sockfds.size();

    while(recv_tls_stop == 0){
        FD_ZERO(&readfds);
        for(int i = 0; i < sockfd_size; i++){
            FD_SET(sockfds.at(i), &readfds);
            maxfdp1 = max(sockfds.at(i), maxfdp1);
        }
        maxfdp1++;

        struct timeval timeout = {1,0};
        ret = select(maxfdp1, &readfds, NULL, NULL, &timeout);//timeout

        if(recv_tls_stop)
            break;

        if(ret == 0)
            continue;
        
    
        for(int i = 0; i < sockfd_size; i++){
            if(FD_ISSET(sockfds.at(i), &readfds)){
                SSL* ssl = ssls.at(i);
                if(ssl){
                    do {
                        ret = SSL_read(ssl, buf, BUFSIZE);
                        switch(SSL_get_error(ssl, ret)){
                            case SSL_ERROR_NONE:
                                break;
                            case SSL_ERROR_ZERO_RETURN:
                                /* End of data */
                                // SSL_shutdown(ssl);
                                break;
                            case SSL_ERROR_WANT_READ:
                                break;
                            
                            case SSL_ERROR_WANT_WRITE:
                                break;
                            default:
                                // print_func("dummy_recv_tls: SSL read problem!\n");
                                break;
                        }
                        if(ret <= 0)
                            break;
                    }while (SSL_pending(ssl));
                }
            }
        }
        sleep(1);
    }

    print_func("dummy_recv_tls exits...\n");
    return;
}

#endif
