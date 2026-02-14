#ifndef OPTIMACK_H
#define OPTIMACK_H


#include "thr_pool.h"
#include <set>
#include <map>
#include <vector>
#include <chrono>
#include <ctime>
#include <sys/time.h>
#include "interval_boost.h"
#include "interval.h"
#include <netinet/in.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <semaphore>

//#define GPROF_CHECK 0
#ifndef GPROF_CHECK
    #include "autoconf.h"
#else
    #define USE_OPENSSL 1
#endif

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include <memory> //shared_ptr

#ifdef USE_OPENSSL
#include <openssl/ssl.h>
#include "tls.h"
#include <functional> 

class TLS_Crypto_Coder;
class TLS_Encrypted_Record_Reassembler;
class TLS_Decrypted_Records_Map;
class TLS_Record_Number_Seq_Map;
#endif
// #include "comm/Connection.h"
// #include "../comm/forward.h"
// #include <bits/stdc++.h>
// using namespace std;

#define USE_OPTIMACK 1

extern struct nfq_q_handle *g_nfq_qh;

const int multithread = 1;
const int debug_subconn_recvseq = 0;
const int use_optimack = 1;
const int forward_packet = 0;
const int log_squid_ack = 0;
const int log_result = 0;
const int use_boost_pool = 1;
extern const int GROUP_NUM;
extern const int RANGE_NUM;
const int MARK = 666;
const int MARK_RANGE = 999;

class NFQ;

class NFQ{
    public:
        NFQ(unsigned short nfq_queue_num, void* data, int (*func)(struct nfq_q_handle *, struct nfgenmsg *, struct nfq_data *, void *));
        void stop() { nfq_stop = 1; }
        ~NFQ();

    private:
        struct nfq_q_handle *g_nfq_qh;
        struct nfq_handle *g_nfq_h;
        int g_nfq_fd;
        int nfq_stop, cb_stop;
        pthread_t nfq_thread;
        unsigned short nfq_queue_num;

        int setup_nfq(void* data, int (*func)(struct nfq_q_handle *, struct nfgenmsg *, struct nfq_data *, void *));
        void nfq_loop();
        int setup_nfqloop();
        int teardown_nfq();
};



class Optimack;

struct subconn_info
{
    Optimack* optack;
    int id;
    int sockfd;
    unsigned short local_port;
    unsigned int ini_seq_rem;  //remote sequence number
    unsigned int ini_seq_loc;  //local sequence number
    unsigned int next_seq_rem;  //rel
    unsigned int last_next_seq_rem;
    unsigned int next_seq_loc;  //TODO: rel
    short ack_sent;
    bool seq_init;

    pthread_t thread;
    pthread_mutex_t mutex_opa;
    unsigned int optim_ack_stop;
    unsigned int opa_seq_start;  // local sequence number for optim ack to start
    unsigned int opa_ack_start;  // local ack number for optim ack to start
    unsigned int opa_seq_max_restart;
    unsigned int opa_retrx_counter;
    std::chrono::time_point<std::chrono::system_clock> last_restart_time, last_data_received, timer_print_log, last_inorder_data_time;
    int rwnd;
    int win_scale;
    int ack_pacing;
    unsigned int payload_len;
    float off_pkt_num;
    unsigned int stall_seq;
    int restart_counter;

    std::map<uint, uint> dup_seqs;
    IntervalList* recved_seq;
    // std::vector<Interval> seq_gaps;
    // pthread_mutex_t mutex_seq_gaps;

    bool is_backup;
    bool fin_or_rst_recved;
    bool tcp_handshake_finished;
#ifdef USE_OPENSSL
    bool tls_handshake_finished;

    bool is_ssl;
    SSL *ssl;
    TLS_Crypto_Coder* crypto_coder;
    TLS_Encrypted_Record_Reassembler* tls_rcvbuf;
    // TLS_Record_Number_Seq_Map* tls_record_seq_map;
    int record_size;
    unsigned int next_seq_rem_tls; //for tls's optimack overrun recover, otherwise recover won't work
    // uint ini_seq_tls_data;
    // unsigned char *iv_salt, *session_key;
#endif
    void lock(){
        pthread_mutex_lock(&mutex_opa);
    }

    void unlock(){
        pthread_mutex_unlock(&mutex_opa);
    }
};

extern std::map<uint, struct subconn_info*> allconns;


// Multithread
struct thread_data {
    struct nfq_q_handle *qh;
    unsigned int  pkt_id;
    unsigned int  len;
    unsigned char *buf;
    int ttl;
    bool incoming;
    subconn_info* subconn;
    Optimack* obj;
    std::vector<double> timestamps;
};

struct int_thread {
    int thread_id;
    Optimack* obj;
};


struct http_header {
    int start;
    int end;
    int parsed;
    int remain;
    int recved;
};

#define MAX_RANGE_SIZE 10000

struct range_conn{
    int id, sockfd, sockfd_old, range_request_count, requested_bytes, erase_count, port;
    unsigned int ini_seq_rem;  //remote sequence number
    unsigned int ini_seq_loc;  //local sequence number
    unsigned int next_seq_rem;  //rel
    unsigned int next_seq_loc;  //TODO: rel
    unsigned int last_next_seq_rem;
    IntervalList *group_recved_seq;

    http_header* header;
    char response[MAX_RANGE_SIZE+1];
    int recv_offset;

    int in_use;
    uint ranges[10];
    pthread_mutex_t mutex_opa;
    std::mutex std_mutex;
    std::counting_semaphore<10> *smph;
    // std::unique_lock<std::mutex> lock((std_mutex));//std::defer_lock
    std::chrono::time_point<std::chrono::system_clock> last_send;
#ifdef USE_OPENSSL
    SSL *ssl, *ssl_old;
#endif

    range_conn(): id(0), sockfd(0), sockfd_old(0), range_request_count(0), requested_bytes(0), erase_count(0), port(0), in_use(0) {}
};

// Thread wrapper
// void* nfq_loop(void *arg);
int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
void* pool_handler(void* arg);
void* optimistic_ack(void* arg);
void* overrun_detector(void* arg);
void* send_all_requests(void* arg);
void* open_duplicate_conns_handler(void* arg);
void* open_duplicate_ssl_conns_handler(void* arg);

// void* range_watch(std::shared_ptr<Optimack> obj);
// void* range_recv(void* arg);


class Optimack : public std::enable_shared_from_this<Optimack>
{
public:
    // [[nodiscard]] static std::shared_ptr<Optimack> create() {
    //     return std::shared_ptr<Optimack>(new Optimack());
    // }
    using TFunc = std::function<void (const char*, ssize_t)>;
    TFunc fp_to_client_write;

    Optimack();
    ~Optimack();

    std::shared_ptr<Optimack> getptr(){
        return shared_from_this();
    }

    void init();
    int setup_nfq(unsigned short id);
    int setup_nfqloop();
    struct subconn_info *create_subconn_info(int sockfd, bool is_backup); 
    int insert_subconn_info(std::map<uint, struct subconn_info*> &subconn_infos, uint& subconn_count, struct subconn_info* new_subconn);
    void open_one_duplicate_conn(std::map<uint, struct subconn_info*> &subconn_info_list, bool is_backup);
    int open_duplicate_conns();
    void set_main_subconn(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port, int fd);

    int teardown_nfq();
    int exec_iptables(char action, char* rule);
    void cleanup();
    void log_seq_gaps();
    void print_seq_table();

    struct nfq_handle *g_nfq_h;
    struct nfq_q_handle *g_nfq_qh;
    int g_nfq_fd;
    int nfq_stop, overrun_stop, cb_stop, optim_ack_stop;
    pthread_t nfq_thread, overrun_thread, optim_ack_thread;
    std::thread open_conns, open_ssl_thread, recv_ssl_thread, request_thread;

    bool is_nfq_full(FILE* out_file);
    void print_ss(FILE* out_file);
    bool does_packet_lost_on_all_conns();

    // int find_seq_gaps(unsigned int seq);
    // void insert_seq_gaps(unsigned int start, unsigned int end, unsigned int step);
    // void delete_seq_gaps(unsigned int val);
    void start_altogether_optimack();
    void* full_optimistic_ack_altogether();

    int start_optim_ack(uint id, unsigned int seq, unsigned int ack, unsigned int payload_len, unsigned int seq_max);
    int start_optim_ack_backup(uint id, unsigned int seq, unsigned int ack, unsigned int payload_len, unsigned int seq_max);
    int start_optim_ack_altogether(unsigned int opa_ack_start, unsigned int opa_seq_start, unsigned int payload_len, unsigned int seq_max);
    int restart_optim_ack(uint id, unsigned int seq, unsigned int ack, unsigned int payload_len, unsigned int seq_max, std::chrono::time_point<std::chrono::system_clock> &timer);
    int send_ACK_adjusted_rwnd(struct subconn_info* conn, int cur_ack);
    int send_optimistic_ack_with_timer(struct subconn_info* conn, int cur_ack, std::chrono::time_point<std::chrono::system_clock>& last_send_ack, std::chrono::time_point<std::chrono::system_clock>& last_zero_window);
    int process_tcp_packet(struct thread_data* thr_data);
    int process_tcp_packet_with_payload(struct mytcphdr* tcphdr, unsigned int seq_rel, unsigned char* payload, int payload_len, struct subconn_info* subconn, char* log);
    int process_tcp_ciphertext_packet(int pkt_id, struct mytcphdr* tcphdr, unsigned int seq, unsigned int ack, unsigned char *tcp_opt, unsigned int tcp_opt_len, unsigned char* payload, int payload_len, bool incoming, subconn_info* subconn, char* log);
    int process_tcp_plaintext_packet(thread_data* thr_data, struct mytcphdr* tcphdr, unsigned int seq, unsigned int ack, unsigned char *tcp_opt, unsigned int tcp_opt_len, unsigned char* payload, int payload_len, bool incoming, subconn_info* subconn, char* log);
    void send_optimistic_ack_with_SACK(struct subconn_info* conn, int cur_ack, int adjusted_rwnd, IntervalList* recved_seq);
    int modify_to_main_conn_packet(struct subconn_info* subconn, struct mytcphdr* tcphdr, unsigned char* packet, unsigned int packet_len, unsigned int seq_rel);
    void send_optimistic_ack(struct subconn_info* conn, int cur_ack, int adjusted_rwnd);
    int get_adjusted_rwnd(int cur_ack);
    int get_adjusted_rwnd_backup(int cur_ack);
    void update_optimistic_ack_timer(bool is_zero_window, std::chrono::time_point<std::chrono::system_clock>& last_send_ack, std::chrono::time_point<std::chrono::system_clock>& last_zero_window);
    int generate_sack_blocks(unsigned char * buf,int len, IntervalList* sack_list, uint ini_seq_rem);
    void extract_sack_blocks(unsigned char * const buf, const uint16_t len, IntervalList& sack_list,  unsigned int ini_seq);
    void send_data_to_backup(unsigned int seq, unsigned char* payload, int payload_len);
    void send_data_to_squid(unsigned int seq, unsigned char* payload, int payload_len);
    void send_data_to_subconn(struct subconn_info* conn, bool to_client, unsigned int seq, unsigned char* payload, int payload_len);
    void send_data_to_server_and_update_seq(struct subconn_info* conn, unsigned char* payload, int payload_len);
    bool store_and_send_data(uint seq_rel, unsigned char* payload, int payload_len, struct subconn_info* subconn, bool is_backup, int id);
    
    // void update_subconn_next_seq_loc(struct subconn_info* subconn, uint num, bool is_fin);
    void backup_try_fill_gap();
    void send_request(char* request, int len);
    void send_all_requests();

    void update_subconn_next_seq_rem(struct subconn_info* subconn, uint num, bool is_fin);

    bool try_update_uint(uint &src, uint target);
    bool try_update_uint_with_lock(pthread_mutex_t* mutex, uint &src, uint target);

    struct subconn_info* get_slowest_subconn();
    void remove_iptables_rules();


    // variables
    int main_fd, client_fd;
    char g_local_ip[16]; //TODO: different connection from client
    char g_remote_ip[16];
    unsigned int g_local_ip_int;
    unsigned int g_remote_ip_int;
    unsigned short g_remote_port;
    unsigned short squid_port, backup_port;
    char *request, *response;
    unsigned short request_len, response_len;
    struct sockaddr_in dstAddr;
    uint squid_MSS;
    
    // std::shared_ptr<std::map<uint, struct subconn_info*>> subconn_infos_shared = std::make_shared<std::map<uint, struct subconn_info*>>();
    // std::map<uint, struct subconn_info*>* p = new std::map<uint, struct subconn_info*>();
    // std::shared_ptr<std::map<uint, struct subconn_info*>> subconn_infos_shared = std::shared_ptr<std::map<uint, struct subconn_info*>>(new std::map<uint, struct subconn_info*>(),
    //     [](std::map<uint, struct subconn_info*>* p_subconn_infos){
    //         uint port = p_subconn_infos->begin()->second->local_port;
    //         printf("S%d: deleting subconn_infos\n", port);
    //         for (auto it = p_subconn_infos->begin(); it != p_subconn_infos->end(); it++){
    //             if(it->second->is_ssl){
    // #ifdef USE_OPENSSL
    //                     if(it->second->crypto_coder)
    //                         free(it->second->crypto_coder);  
    //                     // if(it != subconn_infos.begin())
    //                     //     if(it->second->ssl){
    //                     //         SSL_shutdown(it->second->ssl);
    //                     //         SSL_free(it->second->ssl);
    //                     //         sleep(1);
    //                     //     }
    // #endif
    //                 }
    //                 if(it != p_subconn_infos->begin())
    //                     close(it->second->sockfd);
    //                 if(it->second->recved_seq)
    //                     free(it->second->recved_seq);
    //                 free(it->second);
    //                 it->second = NULL;            
    //         }
    //         printf("S%d: deleted subconn_infos\n", port);
    //     }
    // );
    std::map<uint, struct subconn_info*> subconn_infos;
    uint subconn_count;
    // std::vector<struct subconn_info> subconn_infos, backup_subconn_infos;

    std::vector<char*> iptables_rules;
    
    // locals
    bool request_recved = false;
    int nfq_queue_num;
    
    boost::asio::thread_pool* boost_pool;
    thr_pool_t* oracle_pool;

    pthread_mutex_t mutex_seq_next_global = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mutex_subconn_infos = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mutex_optim_ack_stop = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_t mutex_cur_ack_rel = PTHREAD_MUTEX_INITIALIZER;
    
    // seq
    IntervalList recved_seq, all_lost_seq, we2squid_lost_seq, sack_list;
    pthread_mutex_t mutex_seq_gaps = PTHREAD_MUTEX_INITIALIZER;
    // std::vector<Interval> seq_gaps, recved_seq;
    std::map<std::string, uint> bytes_per_second;

    // std::std::vector<unsigned int*> seq_gaps;
    unsigned int seq_next_global = 1,
                 cur_ack_rel = 1,
                 last_ack_rel = 0,
                 last_speedup_ack_rel = 1,
                 last_slowdown_ack_rel = 0,
                 max_opt_ack = 0; 
    unsigned int backup_dup_ack = 0, backup_max_opt_ack = 0;
    int win_scale = 1 << 7, 
        rwnd = 64256, adjusted_rwnd = 0, win_end = 1, backup_dup_ack_rwnd = 1,
        max_win_size = 0,
        same_ack_cnt = 0,
        overrun_cnt = 0,
        we2squid_lost_cnt = 0,
        range_timeout_cnt = 0;
    float overrun_penalty = 0, we2squid_penalty = 0, range_timeout_penalty = 0;
    bool cleaned_up = false, static_object = true;

    float last_off_packet = 0.0;
    std::chrono::time_point<std::chrono::system_clock> last_speedup_time, last_rwnd_write_time, last_ack_time, last_restart_time, start_timestamp, seq_ini_time;
    double last_ack_epochtime, last_inorder_data_epochtime;
    FILE *log_file, *rwnd_file, *adjust_rwnd_file, *forward_seq_file, *recv_seq_file, *processed_seq_file, *ack_file, *seq_gaps_file, *seq_gaps_count_file, *lost_per_second_file, *tcpdump_pipe, *info_file;
    char output_dir[100] = {0};
    char home_dir[10] = {0};
    char hostname[20], start_time[20], tcpdump_file_name[100], mtr_file_name[100], loss_file_name[100], seq_gaps_count_file_name[100], info_file_name[100];

    // range

    void range_watch();
    void range_watch_multi();
    int range_recv(struct range_conn* range_conn_this);
    int check_range_conn(struct range_conn* range_conn_this, std::vector<Interval>& range_job_vector);
    void try_for_gaps_and_request();
    bool check_packet_lost_on_all_conns(uint last_recv_inorder);
    uint get_byte_seq(uint tcp_seq);
    uint get_tcp_seq(uint byte_seq);
    int insert_lost_range(uint start, uint end);
    int get_http_response_header_len(subconn_info* subconn, unsigned char* payload, int payload_len);
    //IntervalList* get_lost_range(uint start, uint end);
    int send_http_range_request(struct range_conn* cur_range_conn);
    int send_http_range_request(struct range_conn* cur_range_conn, const char* ranges);
    int send_http_range_request(struct range_conn* cur_range_conn, Interval* range);
    int send_http_range_request(void* sockfd, Interval* range);
    void start_range_recv(IntervalList* list);
    void we2squid_loss_and_start_range_recv(uint start, uint end, IntervalList* intvl_lis);
    void we2squid_loss_and_insert(uint start, uint end);
    uint get_min_next_seq_rem();
    int range_worker(int& sockfd, Interval* it);
    int range_recv_block(int sockfd, Interval* it);
    int process_range_rv(struct range_conn* group_conns, http_header* header, char* response, int rv, int& recv_offset);
    // int send_group_range_request(struct range_conn* cur_range_conn, const int group_start_i, char* ranges_str);
    int send_group_range_request(struct range_conn* group_conns, interval_map gaps);
    int send_group_range_request_worker(struct range_conn** range_conns, int group_i);
    int cb_range(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
    


    std::thread range_thread;
    pthread_mutex_t mutex_range = PTHREAD_MUTEX_INITIALIZER;
    int range_stop, range_sockfd, range_request_count = 0;
    IntervalList ranges_sent;
    uint response_header_len = 0, requested_bytes = 0, file_size = 0, ack_end = 1;
    char range_request_template[1000];
    uint range_request_template_len;

    //receive buffer
    struct data_segment{
        int len;
        unsigned char* data;
        data_segment() 
        { data = NULL; len = 0; }
        data_segment(unsigned char* data_, int len_)
        { data = data_; len = len_; }
    };
    std::map<uint, struct data_segment> recv_buffer;
    pthread_mutex_t mutex_recv_buffer = PTHREAD_MUTEX_INITIALIZER;
    int insert_to_recv_buffer(uint seq, unsigned char* data, int len);
    int insert_to_recv_buffer_withLock(uint seq, unsigned char* data, int len);
    int remove_recved_recv_buffer(uint seq);
    int remove_recved_recv_buffer_withLock(uint seq);
    int send_out_of_order_recv_buffer(uint seq);
    int send_out_of_order_recv_buffer(uint start, uint end);
    int send_out_of_order_recv_buffer(uint start, uint end, int max_count);
    int send_out_of_order_recv_buffer_withLock(uint seq);
    int send_out_of_order_recv_buffer_withLock(uint start, uint end, int max_count);
    int send_out_of_order_recv_buffer_withLock(uint start, uint end);
    int send_last_inorder_recv_buffer_withLock(uint end);
    int resend_cnt = 0;


    std::mutex stdmutex_rb;
    std::condition_variable cv_rb;
    uint last_send = 1;
    bool send_squid_stop = false;
    int send_data_to_squid_thread();
    // void (*fp_to_client_write)(const char*, ssize_t) const = NULL;

    //TLS
    bool is_ssl = false;
#ifdef USE_OPENSSL
    TLS_Decrypted_Records_Map* decrypted_records_map;
    TLS_Record_Number_Seq_Map* tls_record_seq_map;
    // std::shared_ptr<TLS_Record_Number_Seq_Map> tls_record_seq_map = std::make_shared<TLS_Record_Number_Seq_Map>();

    int open_duplicate_ssl_conns();
    int set_main_subconn_ssl(SSL *squid_ssl);
    int set_subconn_ssl_credentials(struct subconn_info *subconn, SSL *ssl);
    int process_incoming_tls_appdata(bool contains_header, unsigned int seq, unsigned char* payload, int payload_len, subconn_info* subconn, std::map<uint, struct record_fragment> &return_buffer);
    int partial_decrypt_tcp_payload(struct subconn_info* subconn, uint seq, unsigned char* payload, int payload_len, std::map<uint, struct record_fragment> &return_buffer);
    void dummy_recv_tls();
    int recv_tls_stop = -1;
    pthread_t recv_thread;

#endif
};

int establish_tcp_connection(int old_sockfd, char* remote_ip, unsigned short remote_port, int mark);
int get_localport(int fd);

double get_current_epoch_time_second();
double get_current_epoch_time_nanosecond();
double elapsed(std::chrono::time_point<std::chrono::system_clock> start);

// auto funcTime = 
//     [](auto&& func, auto&&... params) {
//         // get time before function invocation
//         const auto& start = std::chrono::high_resolution_clock::now();
//         // function invocation using perfect forwarding
//         std::forward<decltype(func)>(func)(std::forward<decltype(params)>(params)...);
//         // get time after function invocation
//         const auto& stop = std::chrono::high_resolution_clock::now();
//         return stop - start;
//      };

std::vector<std::string> split(const std::string &s, char delim);
bool is_static_object(std::string request);

void check_and_free_shared(std::shared_ptr<std::map<uint, struct subconn_info*>> subconn_infos_shared_copy);

int get_content_length(const char* payload, int payload_len);



extern thr_pool_t *thr_pool_create_range(uint_t min_threads, uint_t max_threads,
                uint_t linger, pthread_attr_t *attr, Optimack* obj);
            
extern int thr_pool_queue_range(thr_pool_t *pool, void *arg);

extern void thr_pool_wait_range(thr_pool_t *pool);

extern void thr_pool_destroy_range(thr_pool_t *pool);



#endif
