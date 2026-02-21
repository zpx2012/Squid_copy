#include <string.h>
#include <algorithm>
#include <climits>
#include <cstdarg>
#include <cstdlib>
#include <errno.h>
#include <arpa/inet.h> //ntohl
#include <unistd.h> //close
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <functional>
#include <array>
#include <memory>
#include <unordered_map>
#include <vector>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnfnetlink/libnfnetlink.h>
#include "logging.h"
#include "Optimack.h"
#include "range_request_module.h"
#include "range_gap_dispatcher.h"
#include "socket.h"
#include <condition_variable>
#include <mutex>
#include "checksum.h"

#ifndef GPROF_CHECK
#ifdef assert
#undef assert
#endif
#include "squid.h"
#include "sbuf/SBuf.h"
#include "http/one/ResponseParser.h"
#endif

/*** 
    * TODO List
    1. for multiple ranges in one request, process range rv will wake sender up when it receives one range
***/

// range
#define MAX_REQUEST_LEN 1024
#define MAX_RANGE_REQ_LEN 1536
#define PACKET_SIZE 1460
#define MAX_RANGE_REQ_CNT 90

#define USE_CR 0

const int GROUP_NUM = 12;
const int RANGE_NUM = 1;
const int RANGE_PER_RQ = 1;
#define REQ_STEP 5
#define BASE_RANGE_REQ_CNT MAX_RANGE_REQ_CNT - GROUP_NUM * REQ_STEP

const bool debug_range = false;
const int RANGE_SOCKET_BUF_BYTES = 1 << 20;
const int RANGE_EPOLL_TIMEOUT_MS = 100;
const int RANGE_RECV_HUB_MAX_SHARDS = 8;
const int RANGE_RECV_HUB_DEFAULT_SHARDS = 4;

struct RangeSocketMetrics {
    int sndbuf = -1;
    int rcvbuf = -1;
    uint32_t rtt_us = 0;
    bool has_rtt = false;
};

static int get_socket_opt_int(int sockfd, int level, int optname) {
    int value = -1;
    socklen_t value_len = sizeof(value);
    if (getsockopt(sockfd, level, optname, &value, &value_len) == 0) {
        return value;
    }
    return -1;
}

static RangeSocketMetrics sample_range_socket_metrics(int sockfd) {
    RangeSocketMetrics metrics;
    if (sockfd <= 0) {
        return metrics;
    }
    metrics.sndbuf = get_socket_opt_int(sockfd, SOL_SOCKET, SO_SNDBUF);
    metrics.rcvbuf = get_socket_opt_int(sockfd, SOL_SOCKET, SO_RCVBUF);
    struct tcp_info info = {};
    socklen_t info_len = sizeof(info);
    if (getsockopt(sockfd, IPPROTO_TCP, TCP_INFO, &info, &info_len) == 0) {
        metrics.rtt_us = info.tcpi_rtt;
        metrics.has_rtt = true;
    }
    return metrics;
}

static void tune_range_socket_buffers(const range_conn* conn) {
    if (!conn || conn->sockfd <= 0) {
        return;
    }
    const RangeSocketMetrics before = sample_range_socket_metrics(conn->sockfd);
    int target_buf = RANGE_SOCKET_BUF_BYTES;
    if (setsockopt(conn->sockfd, SOL_SOCKET, SO_SNDBUF, &target_buf, sizeof(target_buf)) < 0) {
        print_func("[Range]R%d-%d: setsockopt(SO_SNDBUF) failed: %s", conn->id, conn->port, strerror(errno));
    }
    if (setsockopt(conn->sockfd, SOL_SOCKET, SO_RCVBUF, &target_buf, sizeof(target_buf)) < 0) {
        print_func("[Range]R%d-%d: setsockopt(SO_RCVBUF) failed: %s", conn->id, conn->port, strerror(errno));
    }
    const RangeSocketMetrics after = sample_range_socket_metrics(conn->sockfd);
    print_func(
        "[Range]R%d-%d: sockbuf snd %d->%d rcv %d->%d rtt_us %u->%u",
        conn->id,
        conn->port,
        before.sndbuf,
        after.sndbuf,
        before.rcvbuf,
        after.rcvbuf,
        before.has_rtt ? before.rtt_us : 0u,
        after.has_rtt ? after.rtt_us : 0u
    );
}


static void clear_range_conn_state(range_conn* conn) {
    conn->sockfd = 0;
    conn->sockfd_old = 0;
    conn->range_request_count = 0;
    conn->requested_bytes = 0;
    conn->erase_count = 0;
    conn->port = 0;
    conn->ini_seq_rem = 0;
    conn->ini_seq_loc = 0;
    conn->next_seq_rem = 0;
    conn->next_seq_loc = 0;
    conn->last_next_seq_rem = 0;
    conn->header = NULL;
    conn->recv_offset = 0;
    conn->in_use = 0;
    memset(conn->ranges, 0, sizeof(conn->ranges));
    memset(conn->response, 0, sizeof(conn->response));
}

static void prepare_group_range_conn(
    range_conn* conn,
    int conn_id,
    std::counting_semaphore<10>* smph,
    IntervalList* group_seq
) {
    clear_range_conn_state(conn);
    conn->id = conn_id;
    conn->smph = smph;
    conn->group_recved_seq = group_seq;
    conn->last_send = std::chrono::system_clock::now();
    conn->erase_count = MAX_RANGE_REQ_CNT;
}

static bool append_to_buffer(char* buf, size_t capacity, int& offset, const char* fmt, ...) {
    if (offset < 0 || static_cast<size_t>(offset) >= capacity) {
        return false;
    }
    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(buf + offset, capacity - static_cast<size_t>(offset), fmt, args);
    va_end(args);
    if (written < 0) {
        return false;
    }
    if (static_cast<size_t>(written) >= capacity - static_cast<size_t>(offset)) {
        offset = static_cast<int>(capacity - 1);
        return false;
    }
    offset += written;
    return true;
}
const bool split_range = false;
const bool single_sender = false;
#define USE_NFQ 1
const int MAX_REQUEST_CNT = 1;
std::condition_variable range_send_cv;
std::mutex range_send_cv_m;

RangeRequestModule::RangeRequestModule(Optimack& owner)
    : owner_(owner), running_(false)
{
}

RangeRequestModule::~RangeRequestModule()
{
    stop();
}

void RangeRequestModule::start()
{
    bool expected = false;
    if (!running_.compare_exchange_strong(expected, true)) {
        return;
    }
    owner_.range_stop = 0;
    dispatch_thread_ = std::thread(&RangeRequestModule::runDispatchLoop, this);
}

void RangeRequestModule::stop()
{
    bool expected = true;
    if (!running_.compare_exchange_strong(expected, false)) {
        return;
    }
    owner_.range_stop = 1;
    if (dispatch_thread_.joinable()) {
        dispatch_thread_.join();
    }
}


int process_range_rv_old(char* response, int rv, Optimack* obj, subconn_info* subconn, http_header* header, int& consumed, int& unread, int& parsed, int& recv_offset, int& unsent) { return 0;}
void cleanup_range(int& range_sockfd, int& range_sockfd_old, http_header* header, int& consumed, int& unread, int& parsed, int& recv_offset, int& unsent);


int establish_tcp_connection(int old_sockfd, const char* remote_ip, unsigned short remote_port, int& port, int mark)
{
    int sockfd = 0;
    struct sockaddr_in server_addr;

    // Open socket
opensocket:
    while(sockfd == 0 || sockfd == old_sockfd){ //|| 
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Can't open stream socket.");
            return -1;
        }
        if(debug_range) print_func("establish_tcp_connection: create sockfd %d\n", sockfd);
    }

    // Set server_addr
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(remote_ip);
    server_addr.sin_port = htons(remote_port);


    // Connect to server
    int count = 0;
    while (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0 && count++ < 5) {
        print_func("establish_tcp_connection: sockfd %d connect error\n", sockfd);
        perror("Connect server error");
    }

    if(count >= 5){
        sockfd = 0;
        goto opensocket;
        close(sockfd);
        return -1;
    }

    port = get_localport(sockfd);
    if(port < 0){
        print_func("establish_tcp_connection: sockfd %d get_localport error\n", sockfd);
        sockfd = 0;
        close(sockfd);
        goto opensocket;
    }

    // print_func("establish_tcp_connection: connect sockfd %d, port %d\n", sockfd, port);

    return sockfd;
}


int establish_tcp_connection(int old_sockfd, char* remote_ip, unsigned short remote_port)
{
    int sockfd = 0;
    struct sockaddr_in server_addr;

    // Open socket
opensocket:
    while(sockfd == 0 || sockfd == old_sockfd){ //|| 
        if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Can't open stream socket.");
            return -1;
        }
        if(debug_range) print_func("establish_tcp_connection: create sockfd %d\n", sockfd);
    }

    // Set server_addr
    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(remote_ip);
    server_addr.sin_port = htons(remote_port);

    struct timeval tv;
    tv.tv_sec = 10;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        /* Set the option active */
    int optval = 1;
    socklen_t optlen = sizeof(optval);
    if(setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) {
        perror("setsockopt()");
    }
    else
        print_func("establish_tcp_connection: sockfd %d SO_KEEPALIVE set on socket", sockfd);

        
    // Connect to server
    int count = 0;
    while (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0 && count++ < 5) {
        print_func("establish_tcp_connection: sockfd %d connect error\n", sockfd);
        perror("Connect server error");
    }

    if(count >= 5){
        sockfd = 0;
        goto opensocket;
        close(sockfd);
        return -1;
    }

    // print_func("establish_tcp_connection: connect sockfd %d, port %d\n", sockfd, port);

    return sockfd;
}


int open_range_conn(struct range_conn* cur_range_conn, const char* remote_ip, unsigned short remote_port){
    cur_range_conn->sockfd_old = cur_range_conn->sockfd;
    int rv = 0;
    int mark_range = MARK_RANGE;
    while( (rv = establish_tcp_connection(cur_range_conn->sockfd_old, remote_ip, remote_port, cur_range_conn->port, mark_range)) <= 0 ) sleep(1);
    cur_range_conn->in_use = 0;
    cur_range_conn->sockfd = rv;
    cur_range_conn->range_request_count = 0;
    tune_range_socket_buffers(cur_range_conn);
    print_func("[Range]R%d-%d: sockfd %d, conn created, erase count %d", cur_range_conn->id, cur_range_conn->port, rv, cur_range_conn->erase_count);

    if(USE_CR){
        char cmd[100] = {0};
        snprintf(cmd, 100, "sudo iptables -A PREROUTING -t mangle -p tcp --dport %d -j NFQUEUE --queue-num 999;", cur_range_conn->port);
        system(cmd);

        memset(cmd, 0, 100);
        snprintf(cmd, 100, "sudo iptables -A OUTPUT -p tcp --sport %d -j NFQUEUE --queue-num 999;", cur_range_conn->port);
        system(cmd);
    }

    return 0;
}

int close_range_conn(struct range_conn* cur_range_conn){
    if(USE_CR){
        char cmd[100] = {0};
        snprintf(cmd, 100, "sudo iptables -D PREROUTING -t mangle -p tcp --dport %d -j NFQUEUE --queue-num 999;", cur_range_conn->port);
        system(cmd);

        memset(cmd, 0, 100);
        snprintf(cmd, 100, "sudo iptables -D OUTPUT -p tcp --sport %d -j NFQUEUE --queue-num 999;", cur_range_conn->port);
        system(cmd);

    }
    return 0;
}

struct RangeRecvConnState {
    int fd = -1;
    range_conn* conn = NULL;
    http_header header = {};
    int recv_offset = 0;
    char response[MAX_RANGE_SIZE + 1] = {0};
    std::atomic<bool> closing = false;
    std::atomic<int> in_flight = 0;
    std::atomic<uint64_t> recv_bytes = 0;
    std::atomic<uint64_t> release_count = 0;
};

struct GlobalRangeRecvHub {
    std::mutex mutex;
    int shard_id = 0;
    int epoll_fd = -1;
    std::thread recv_thread;
    std::atomic<bool> stop = false;
    bool running = false;
    RangeRequestModule* module = NULL;
    Optimack* owner = NULL;
    std::unordered_map<int, std::shared_ptr<RangeRecvConnState>> fd_states;
    std::unordered_map<range_conn*, std::shared_ptr<RangeRecvConnState>> conn_states;
};

static int getActiveRangeRecvHubShards() {
    static int shard_count = []() {
        int configured = RANGE_RECV_HUB_DEFAULT_SHARDS;
        const char* env_val = getenv("OPTIMACK_RANGE_RECV_SHARDS");
        if (env_val && *env_val) {
            char* end_ptr = NULL;
            long parsed = strtol(env_val, &end_ptr, 10);
            if (end_ptr != env_val && *end_ptr == '\0' && parsed > 0) {
                configured = static_cast<int>(parsed);
            }
        }
        configured = std::max(1, std::min(RANGE_RECV_HUB_MAX_SHARDS, configured));
        print_func("[Range]: recv hub shards=%d (env OPTIMACK_RANGE_RECV_SHARDS)", configured);
        return configured;
    }();
    return shard_count;
}

static int getRangeRecvHubShardByConn(const range_conn* conn) {
    if (!conn) {
        return 0;
    }
    int group_idx = conn->id / 100 - 1;
    if (group_idx < 0) {
        group_idx = 0;
    }
    return group_idx % getActiveRangeRecvHubShards();
}

static GlobalRangeRecvHub& getRangeRecvHub(int shard_id) {
    static std::array<GlobalRangeRecvHub, RANGE_RECV_HUB_MAX_SHARDS> hubs;
    int shard_count = getActiveRangeRecvHubShards();
    int idx = shard_id % shard_count;
    if (idx < 0) {
        idx += shard_count;
    }
    return hubs[idx];
}

static void runGlobalRangeRecvLoop(GlobalRangeRecvHub* hub) {
    if (!hub) {
        return;
    }
    RangeRequestModule* module = NULL;
    Optimack* owner = NULL;
    {
        std::lock_guard<std::mutex> lock(hub->mutex);
        module = hub->module;
        owner = hub->owner;
    }
    if (!module || !owner) {
        return;
    }

    const int max_events = 64;
    std::vector<epoll_event> events(static_cast<size_t>(max_events));
    while (!hub->stop.load()) {
        const int epoll_fd = hub->epoll_fd;
        if (epoll_fd < 0) {
            break;
        }
        int event_count = epoll_wait(epoll_fd, events.data(), max_events, RANGE_EPOLL_TIMEOUT_MS);
        if (event_count < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (hub->stop.load()) {
                break;
            }
            print_func("[Range]: global epoll_wait failed: %s", strerror(errno));
            continue;
        }
        if (event_count == 0) {
            continue;
        }

        for (int i = 0; i < event_count; i++) {
            const int fd = events[i].data.fd;
            std::shared_ptr<RangeRecvConnState> state;
            {
                std::lock_guard<std::mutex> lock(hub->mutex);
                auto it = hub->fd_states.find(fd);
                if (it != hub->fd_states.end()) {
                    state = it->second;
                }
            }
            if (!state || state->closing.load()) {
                continue;
            }

            state->in_flight.fetch_add(1);
            if (state->closing.load()) {
                state->in_flight.fetch_sub(1);
                continue;
            }

            int rv = 0;
            int saved_errno = 0;
            bool did_recv = false;
            bool should_close = false;
            if (events[i].events & EPOLLIN) {
                did_recv = true;
                while (true) {
                    if(owner->is_ssl){
#ifdef USE_OPENSSL
                        rv = SSL_read(state->conn->ssl, state->response + state->recv_offset, MAX_RANGE_SIZE - state->recv_offset);
#endif
                    } else {
                        rv = recv(state->fd, state->response + state->recv_offset, MAX_RANGE_SIZE - state->recv_offset, MSG_DONTWAIT);
                    }

                    if (rv > 0) {
                        state->recv_bytes.fetch_add(static_cast<uint64_t>(rv));
                        if((USE_CR == 0) || (state->conn->id % 100 == 0)){
                            state->response[state->recv_offset + rv] = 0;
                            bool is_dummy = module->processRangeResponse(state->conn, &state->header, state->response, rv + state->recv_offset, state->recv_offset);
                            if(state->header.remain == 0 && is_dummy){
                                if(!single_sender){
                                    state->conn->smph->release();
                                    state->release_count.fetch_add(1);
                                } else {
                                    state->conn->range_request_count--;
                                    range_send_cv.notify_one();
                                }
                            }
                        } else {
                            state->recv_offset = 0;
                        }
                        if (owner->is_ssl) {
                            continue;
                        }
                        continue;
                    }

                    if (owner->is_ssl) {
#ifdef USE_OPENSSL
                        const int ssl_err = SSL_get_error(state->conn->ssl, rv);
                        if (ssl_err == SSL_ERROR_WANT_READ || ssl_err == SSL_ERROR_WANT_WRITE) {
                            break;
                        }
#endif
                        should_close = true;
                        break;
                    }

                    if (rv < 0) {
                        saved_errno = errno;
                        if (saved_errno == EINTR) {
                            continue;
                        }
                        if (saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
                            break;
                        }
                    }
                    should_close = true;
                    break;
                }
            }

            if (!should_close && !did_recv && (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP))) {
                should_close = true;
            }

            if (!should_close) {
                state->in_flight.fetch_sub(1);
                continue;
            }

            state->closing.store(true);
            {
                std::lock_guard<std::mutex> lock(hub->mutex);
                auto fd_it = hub->fd_states.find(fd);
                if (fd_it != hub->fd_states.end() && fd_it->second == state) {
                    hub->fd_states.erase(fd_it);
                }
                auto conn_it = hub->conn_states.find(state->conn);
                if (conn_it != hub->conn_states.end() && conn_it->second == state) {
                    hub->conn_states.erase(conn_it);
                }
            }
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
            if (rv == 0 || !did_recv) {
                print_func("[Range]R%d-%d: global recv closed on fd %d", state->conn->id, state->conn->port, fd);
            } else {
                print_func("[Range]R%d-%d: global recv error ret %d on fd %d, errno %d", state->conn->id, state->conn->port, rv, fd, saved_errno);
            }
            state->recv_offset = 0;
            state->in_flight.fetch_sub(1);
        }
    }
}

static void stopGlobalRangeRecvHub(RangeRequestModule* module);

static bool startGlobalRangeRecvHub(RangeRequestModule* module, Optimack* owner) {
    if (!module || !owner) {
        return false;
    }

    const int shard_count = getActiveRangeRecvHubShards();
    for (int shard = 0; shard < shard_count; shard++) {
        GlobalRangeRecvHub& hub = getRangeRecvHub(shard);
        {
            std::lock_guard<std::mutex> lock(hub.mutex);
            if (hub.running) {
                if (hub.module != module) {
                    stopGlobalRangeRecvHub(module);
                    return false;
                }
                continue;
            }
            hub.shard_id = shard;
            hub.epoll_fd = epoll_create1(0);
            if (hub.epoll_fd < 0) {
                print_func("[Range]: failed to create global epoll fd shard %d: %s", shard, strerror(errno));
                stopGlobalRangeRecvHub(module);
                return false;
            }
            hub.stop.store(false);
            hub.module = module;
            hub.owner = owner;
            hub.running = true;
        }
        hub.recv_thread = std::thread(runGlobalRangeRecvLoop, &hub);
    }
    return true;
}

static void stopGlobalRangeRecvHub(RangeRequestModule* module) {
    const int shard_count = getActiveRangeRecvHubShards();
    for (int shard = 0; shard < shard_count; shard++) {
        GlobalRangeRecvHub& hub = getRangeRecvHub(shard);
        int epoll_fd = -1;
        {
            std::lock_guard<std::mutex> lock(hub.mutex);
            if (!hub.running || hub.module != module) {
                continue;
            }
            hub.stop.store(true);
            epoll_fd = hub.epoll_fd;
        }

        if (hub.recv_thread.joinable()) {
            hub.recv_thread.join();
        }

        {
            std::lock_guard<std::mutex> lock(hub.mutex);
            hub.fd_states.clear();
            hub.conn_states.clear();
            hub.module = NULL;
            hub.owner = NULL;
            hub.running = false;
            hub.stop.store(false);
            hub.epoll_fd = -1;
        }
        if (epoll_fd >= 0) {
            close(epoll_fd);
        }
    }
}

static bool registerRangeRecvConn(RangeRequestModule* module, range_conn* conn) {
    if (!module || !conn || conn->sockfd <= 0) {
        return false;
    }

    const int shard = getRangeRecvHubShardByConn(conn);
    GlobalRangeRecvHub& hub = getRangeRecvHub(shard);
    const std::shared_ptr<RangeRecvConnState> state = std::make_shared<RangeRecvConnState>();
    state->fd = conn->sockfd;
    state->conn = conn;

    int epoll_fd = -1;
    {
        std::lock_guard<std::mutex> lock(hub.mutex);
        if (!hub.running || hub.module != module || hub.epoll_fd < 0) {
            return false;
        }
        auto existing = hub.conn_states.find(conn);
        if (existing != hub.conn_states.end()) {
            int old_fd = existing->second->fd;
            existing->second->closing.store(true);
            if (old_fd > 0) {
                epoll_ctl(hub.epoll_fd, EPOLL_CTL_DEL, old_fd, NULL);
            }
            hub.fd_states.erase(old_fd);
            hub.conn_states.erase(existing);
        }
        hub.fd_states[state->fd] = state;
        hub.conn_states[conn] = state;
        epoll_fd = hub.epoll_fd;
    }

    epoll_event ev = {};
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP;
    ev.data.fd = state->fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, state->fd, &ev) != 0) {
        print_func("[Range]R%d-%d: global epoll add failed for fd %d: %s", conn->id, conn->port, state->fd, strerror(errno));
        std::lock_guard<std::mutex> lock(hub.mutex);
        auto fd_it = hub.fd_states.find(state->fd);
        if (fd_it != hub.fd_states.end() && fd_it->second == state) {
            hub.fd_states.erase(fd_it);
        }
        auto conn_it = hub.conn_states.find(conn);
        if (conn_it != hub.conn_states.end() && conn_it->second == state) {
            hub.conn_states.erase(conn_it);
        }
        return false;
    }
    return true;
}

static void unregisterRangeRecvConn(RangeRequestModule* module, range_conn* conn) {
    if (!module || !conn) {
        return;
    }

    const int shard = getRangeRecvHubShardByConn(conn);
    GlobalRangeRecvHub& hub = getRangeRecvHub(shard);
    std::shared_ptr<RangeRecvConnState> state;
    int epoll_fd = -1;
    {
        std::lock_guard<std::mutex> lock(hub.mutex);
        if (!hub.running || hub.module != module || hub.epoll_fd < 0) {
            return;
        }
        auto it = hub.conn_states.find(conn);
        if (it == hub.conn_states.end()) {
            return;
        }
        state = it->second;
        state->closing.store(true);
        hub.fd_states.erase(state->fd);
        hub.conn_states.erase(it);
        epoll_fd = hub.epoll_fd;
    }

    if (epoll_fd >= 0 && state->fd > 0) {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, state->fd, NULL);
    }
    while (state->in_flight.load() > 0) {
        usleep(1000);
    }
}

static void snapshotRangeRecvConnStats(RangeRequestModule* module, range_conn* conn, uint64_t& recv_bytes, uint64_t& release_count) {
    recv_bytes = 0;
    release_count = 0;
    if (!module || !conn) {
        return;
    }
    const int shard = getRangeRecvHubShardByConn(conn);
    GlobalRangeRecvHub& hub = getRangeRecvHub(shard);
    std::lock_guard<std::mutex> lock(hub.mutex);
    if (!hub.running || hub.module != module) {
        return;
    }
    auto it = hub.conn_states.find(conn);
    if (it == hub.conn_states.end()) {
        return;
    }
    recv_bytes = it->second->recv_bytes.load();
    release_count = it->second->release_count.load();
}


int open_group_range_conn(struct range_conn** range_conns, int i, const char* remote_ip, unsigned short remote_port, std::shared_ptr<Optimack> obj, RangeRequestModule* module, IntervalList* group_seq){

    struct range_conn* group_conns = range_conns[i];
    std::counting_semaphore<10> *smph = new std::counting_semaphore<10>(MAX_REQUEST_CNT);

    for(int j = 0; j < RANGE_NUM; j++){
        struct range_conn* cur_range_conn = &(group_conns[j]);
        prepare_group_range_conn(cur_range_conn, (i + 1) * 100 + j, smph, group_seq);
        open_range_conn(cur_range_conn, remote_ip, remote_port);
        if (!registerRangeRecvConn(module, cur_range_conn)) {
            print_func("[Range]R%d-%d: failed to register conn fd %d to global epoll", cur_range_conn->id, cur_range_conn->port, cur_range_conn->sockfd);
        }
        if(obj->info_file){
            if(obj->processed_seq_file) {
                fprintf(obj->processed_seq_file, "%f,creation,%d,%u,-1,-1\n", get_current_epoch_time_nanosecond(), cur_range_conn->id, cur_range_conn->port);
                // fflush(obj->processed_seq_file);
            }
            if(obj->info_file) {
                fprintf(obj->info_file, "Range_conn,%d,%d\n", cur_range_conn->port, cur_range_conn->id);
                fflush(obj->info_file);
            }
        }

    }

    print_func("open_group_range_conn: Group %d, for loop done", i+1);
    
    if(!single_sender){
        std::thread send_worker(&RangeRequestModule::sendGroupRangeRequestWorker, module, range_conns, i);
        send_worker.detach();
    }

    return 0;
}


int RangeRequestModule::rangeRecv(struct range_conn* cur_range_conn){
    // Receiving packet
    int id = cur_range_conn->id, port = cur_range_conn->port;
    http_header header = {};
#ifdef USE_OPENSSL
    SSL* ssl = cur_range_conn->ssl;
#endif
    print_func("[Range]R%d-%d: range_recv thread created", id, port);
    int rv = 0;
    char response[MAX_RANGE_SIZE+1] = {0};

    int recv_offset = 0;
    while(!owner_.range_stop){
        if(owner_.is_ssl){
    #ifdef USE_OPENSSL
            rv = SSL_read(ssl, response+recv_offset, MAX_RANGE_SIZE-recv_offset);
    #endif
        }
        else{
            rv = recv(cur_range_conn->sockfd, response+recv_offset, MAX_RANGE_SIZE-recv_offset, 0);
        }
        if (rv > 0) {//&& rv < MAX_RANGE_SIZE
            // log_error("[Range] recved %d bytes, hand over to process_range_rv", rv);
            // print_func("[Range]R%d-%d: recved %d bytes", cur_range_conn->id, cur_range_conn->port, rv);
            if((USE_CR == 0) || (cur_range_conn->id % 100 == 0)){
                response[recv_offset+rv] = 0;
                // if(processed_seq_file)  fprintf(processed_seq_file, "%f,start recv,%d,-1,-1\n", get_current_epoch_time_nanosecond(), id);
                bool is_dummy = processRangeResponse(cur_range_conn, &header, response, rv + recv_offset, recv_offset);
                // if(processed_seq_file)  fprintf(processed_seq_file, "%f,after recv,%d,-1,-1\n", get_current_epoch_time_nanosecond(), id);
                if(header.remain == 0 && (is_dummy)){ //|| header.start != 1001
                    if(!single_sender){
                        if(debug_range) print_func("[Range]R%d-%d: range received, release one, is_new %d, start %u", id, port, is_dummy, header.start);
                        cur_range_conn->smph->release();
                    }
                    else{
                        cur_range_conn->range_request_count--;
                        range_send_cv.notify_one();
                    }
                }
            }
            else{
                recv_offset = 0;
            }
        }
        else{
            if(rv == 0){
                print_func("[Range]R%d-%d: recv ret %d, sockfd %d closed", id, port, rv, cur_range_conn->sockfd); // errno %d, errno,
            }
            else{
                print_func("[Range]R%d-%d: error: ret %d, sockfd %d closed", id, port, rv, cur_range_conn->sockfd); // errno %d, errno
            }
            recv_offset = 0;
            return -1;
        }
    }
    return 0;
}

int Optimack::range_recv(struct range_conn* cur_range_conn){
    if (!range_request_module_) {
        return -1;
    }
    return range_request_module_->rangeRecv(cur_range_conn);
}

int parse_response(http_header *head, char *response, int unread);

int RangeRequestModule::processRangeResponse(struct range_conn* cur_range_conn, http_header* header, char* response, int unread, int& recv_offset){

    int id = cur_range_conn->id, port = cur_range_conn->port;
    bool is_new_segment = false;
    int consumed = 0;
    int pending_remove_start = -1;
    int pending_remove_end = -1; // right-open interval end
    auto flush_pending_remove = [&]() {
        if (pending_remove_start >= 0 && pending_remove_end > pending_remove_start) {
            cur_range_conn->group_recved_seq->removeInterval(pending_remove_start, pending_remove_end);
        }
        pending_remove_start = -1;
        pending_remove_end = -1;
    };

    while (unread > 0) {
        if (!header->parsed) {
            // parse header
            int parsed = parse_response(header, response+consumed, unread);
            if (parsed <= 0) {
                // incomplete http header
                // keep receiving and parse in next response
                memmove(response, response+consumed, unread);
                recv_offset += unread - recv_offset;
                // log_error("[Range] incomplete http header, len %d\n", unread);
                // if(debug_range)    print_func("[Range]R%d-%d: incomplete http header, len %d, offset %d", id, port, unread, recv_offset);
                unread = 0;
            }
            else {
                // if(debug_range) print_func("[Range]R%d-%d: Header received %d - %d", id, port, header->start, header->end);
                header->start = owner_.get_tcp_seq(header->start);
                header->end = owner_.get_tcp_seq(header->end);
                recv_offset = 0;
                unread -= parsed;
                consumed += parsed;
            }
        }
        else {
            int consuming = header->remain >= unread? unread : header->remain;
            int seq_rel = (header->start + header->recved);
            int seq_rel_end = seq_rel + consuming -1;
            if(debug_range){
                print_func("[Range]R%d-%d: [%d, %d] data retrieved, remain %d, unread %d", id, port, seq_rel, seq_rel_end, header->remain, unread);
                // log_debug("[Range] data retrieved %d - %d, remain %d, unread %d", header->start+header->recved, header->start+header->recved+unread, header->remain, unread);
            }
            if (static_cast<uint>(seq_rel + consuming) > owner_.cur_ack_rel){
                // if(debug_range) print_func("[Range]R%d-%d: [%d, %d] data to send to squid", id, port, seq_rel, seq_rel_end);
                owner_.store_and_send_data(seq_rel, reinterpret_cast<u_char*>(response + consumed), consuming, NULL, true, id);
                if(debug_range) print_func("[Range]R%d-%d: [%d, %d] data sent to squid", id, port, seq_rel, seq_rel_end);
            }
            const int remove_start = seq_rel;
            const int remove_end = seq_rel_end + 1;
            if (pending_remove_start < 0) {
                pending_remove_start = remove_start;
                pending_remove_end = remove_end;
            } else if (remove_start <= pending_remove_end) {
                if (remove_end > pending_remove_end) {
                    pending_remove_end = remove_end;
                }
            } else {
                flush_pending_remove();
                pending_remove_start = remove_start;
                pending_remove_end = remove_end;
            }
            header->recved += consuming;
            header->remain -= consuming;
            unread -= consuming;
            consumed += consuming;

            if(header->remain == 0){
                memset(header, 0, sizeof(struct http_header));
            }

            if(seq_rel != 1001)
                is_new_segment = true;
        }
    }

    flush_pending_remove();
    return is_new_segment;
}

int Optimack::process_range_rv(struct range_conn* cur_range_conn, http_header* header, char* response, int unread, int& recv_offset){
    if (!range_request_module_) {
        return -1;
    }
    return range_request_module_->processRangeResponse(cur_range_conn, header, response, unread, recv_offset);
}



int parse_response(http_header *head, char *response, int unread)
{
    const char range_field[] = "Content-Range: bytes ";
    const char multirange_field[] = "Content-range: bytes ";
    const char tail_field[] = "\r\n\r\n";

    char *recv_end = response + unread;
    char *parse_head = response;
    if (head->parsed) {
        log_debug("[Range] error: header should have been parsed");
        return -1;
    }

    parse_head = std::search(response, recv_end, range_field, range_field+21);
    if(parse_head == recv_end)
        parse_head = std::search(response, recv_end, multirange_field, multirange_field+21);

    if (parse_head < recv_end) {
        parse_head += 21;
        if(parse_head < recv_end){
            head->start = (int)strtol(parse_head, &parse_head, 10);
            parse_head++;
            if(parse_head < recv_end){
                head->end = (int)strtol(parse_head, &parse_head, 10);
                if(head->end < head->start){
                    head->start = 0;
                    head->end = 0;
                    return 0;
                }
                head->remain = head->end - head->start + 1;
                head->recved = 0;
                parse_head = std::search(parse_head, recv_end, tail_field, tail_field+4);
                if (parse_head < recv_end) {
                    parse_head += 4;
                    head->parsed = 1;
                    return parse_head-response;
                }
            }
        }
    }

    return 0;
}

int RangeRequestModule::sendGroupRangeRequestWorker(struct range_conn** range_conns, int group_i){
    struct range_conn* group_conns = range_conns[group_i];
    std::counting_semaphore<10> *smph = group_conns[0].smph;
    IntervalList* group_recved_seq = group_conns[0].group_recved_seq;
    int backup_i = (group_i + GROUP_NUM) % (GROUP_NUM * 2);
    bool switched = false;
    const auto worker_start = std::chrono::steady_clock::now();
    RangeSocketMetrics before_metrics[RANGE_NUM];
    RangeSocketMetrics after_metrics[RANGE_NUM];
    uint64_t before_recv_bytes[RANGE_NUM] = {0};
    uint64_t before_release_count[RANGE_NUM] = {0};
    uint64_t after_recv_bytes[RANGE_NUM] = {0};
    uint64_t after_release_count[RANGE_NUM] = {0};

    print_func("[Group]G%d: backup_i %d", group_i, backup_i);

    for (int j = 0; j < RANGE_NUM; j++) {
        before_metrics[j] = sample_range_socket_metrics(group_conns[j].sockfd);
        snapshotRangeRecvConnStats(this, &group_conns[j], before_recv_bytes[j], before_release_count[j]);
    }

    for(int j=0; j < RANGE_NUM; j++){
        after_metrics[j] = before_metrics[j];
    }


    while(!owner_.range_stop){

        if (owner_.recved_seq.size() < 2 || owner_.recved_seq.getFirstStart() == 1 || !owner_.range_request_template_len){
            usleep(100);
            continue;
        }

        if(group_conns[0].smph->try_acquire_for(std::chrono::seconds(3))){

            interval_map gaps = group_recved_seq->getGapsAndUpdateTimer(owner_.get_min_next_seq_rem(), RANGE_PER_RQ, 4);

            if(gaps.size()){
                sendGroupRangeRequest(group_conns, gaps);


                if(group_conns[0].range_request_count >= 80 && !switched){
                    switched = true;
                    std::thread open_worker(open_group_range_conn, range_conns, backup_i, owner_.g_remote_ip, owner_.g_remote_port, owner_.getptr(), this, group_recved_seq);
                    open_worker.detach();
                    print_func("[Group]G%d: start switching to %d", group_i+1, backup_i+1);
                }
                else if(group_conns[0].range_request_count >= group_conns[0].erase_count){ // || (backup_conns && elapsed(backup_create_time) > 3.8) || (range_conns[backup_i][RANGE_NUM-1].sockfd)
                    break;
                }
            }
            else{
                group_conns[0].smph->release();
                usleep(200);
            }
        }
        else{
            if(!switched){
                switched = true;
                std::thread open_worker(open_group_range_conn, range_conns, backup_i, owner_.g_remote_ip, owner_.g_remote_port, owner_.getptr(), this, group_recved_seq);
                open_worker.detach();
                print_func("[Group]G%d: Timeout, start switching to %d", group_i+1, backup_i+1);
            }
            break;
        }

    }
    // sleep(4);
    for (int j = 0; j < RANGE_NUM; j++) {
        snapshotRangeRecvConnStats(this, &group_conns[j], after_recv_bytes[j], after_release_count[j]);
        after_metrics[j] = sample_range_socket_metrics(group_conns[j].sockfd);
    }

    print_func("[Group]G%d: close conns", group_i+1);
    for(int j=0; j < RANGE_NUM; j++){
        print_func("[Group]R%d: close sockfd %d", group_conns[j].id, group_conns[j].sockfd);
        unregisterRangeRecvConn(this, &group_conns[j]);
        if(group_conns[j].sockfd > 0){
            // Wake any blocking recv()/SSL_read before close().
            shutdown(group_conns[j].sockfd, SHUT_RDWR);
        }
    }

    for(int j=0; j < RANGE_NUM; j++){
        if(group_conns[j].sockfd > 0){
            close(group_conns[j].sockfd);
        }
        close_range_conn(&group_conns[j]);
        clear_range_conn_state(&group_conns[j]);
    }
    delete smph;

    uint64_t worker_recv_bytes = 0;
    uint64_t worker_release_count = 0;
    for (int j = 0; j < RANGE_NUM; j++) {
        if (after_recv_bytes[j] > before_recv_bytes[j]) {
            worker_recv_bytes += (after_recv_bytes[j] - before_recv_bytes[j]);
        }
        if (after_release_count[j] > before_release_count[j]) {
            worker_release_count += (after_release_count[j] - before_release_count[j]);
        }
    }

    const double elapsed_sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - worker_start).count();
    const double recv_mbps = elapsed_sec > 0.0
        ? (static_cast<double>(worker_recv_bytes) * 8.0) / (elapsed_sec * 1000.0 * 1000.0)
        : 0.0;
    print_func(
        "[Group]G%d perf: elapsed %.3fs, recv_bytes %llu, recv_mbps %.2f, semaphore_releases %llu",
        group_i + 1,
        elapsed_sec,
        static_cast<unsigned long long>(worker_recv_bytes),
        recv_mbps,
        static_cast<unsigned long long>(worker_release_count)
    );
    for (int j = 0; j < RANGE_NUM; j++) {
        print_func(
            "[Group]R%d perf: sndbuf %d->%d, rcvbuf %d->%d, rtt_us %u->%u",
            group_conns[j].id,
            before_metrics[j].sndbuf,
            after_metrics[j].sndbuf,
            before_metrics[j].rcvbuf,
            after_metrics[j].rcvbuf,
            before_metrics[j].has_rtt ? before_metrics[j].rtt_us : 0u,
            after_metrics[j].has_rtt ? after_metrics[j].rtt_us : 0u
        );
    }

    print_func("[Group]G%d: send_group_one_range_request, existing...\n", group_i+1);
    return 0;
}

int RangeRequestModule::sendGroupRangeRequest(struct range_conn* group_conns, interval_map gaps){
    group_conns[0].range_request_count += gaps.iterative_size();

    char debug_str[200] = {0};
    char request_str[1000] = {0};
    int offset = 0, debug_offset = 0;
    append_to_buffer(request_str, sizeof(request_str), offset, "%s", owner_.range_request_template);
    for(auto it = gaps.begin(); it != gaps.end(); it++){
        uint start = it->first.lower(), end = it->first.upper()-1;
        if(it != gaps.begin())
            append_to_buffer(request_str, sizeof(request_str), offset, ", ");
        append_to_buffer(request_str, sizeof(request_str), offset, "%u-%u", owner_.get_byte_seq(start), owner_.get_byte_seq(end));
        append_to_buffer(debug_str, sizeof(debug_str), debug_offset, "[%u, %u], ", start, end);
        if(it->second == static_cast<double>(REQUEST_TIMEOUT))
            if(owner_.processed_seq_file)  fprintf(owner_.processed_seq_file, "%f,request timeout,%d,%u, %u,%u\n", get_current_epoch_time_nanosecond(), group_conns[0].id, group_conns[0].port, start, end+1);

    }
    append_to_buffer(request_str, sizeof(request_str), offset, "\r\n\r\n");

    // if(debug_range) print_func("[Range]R%d-%d: %s request to send, No.%d.", group_conns[0].id, group_conns[0].port, debug_str, group_conns[0].range_request_count);

    int request_result = 1;
    for(int conn_idx = 0; conn_idx < RANGE_NUM; conn_idx++){
        struct range_conn* cur_range_conn = &group_conns[conn_idx];

        request_result *= sendHttpRangeRequest(cur_range_conn, request_str);
        if(debug_range) print_func("[Range]R%d-%d: Thread%d, sent No.%d request %s rv %d", group_conns[0].id, group_conns[0].port, conn_idx, group_conns[0].range_request_count, debug_str,  request_result);
        if(gaps.begin()->first.lower() != 1001 && request_result > 0)
            if(owner_.processed_seq_file)   fprintf(owner_.processed_seq_file, "%f,request,%d,%u,%s\n", get_current_epoch_time_nanosecond(), cur_range_conn->id, cur_range_conn->port, debug_str);

    }

    return request_result;
}

int RangeRequestModule::sendHttpRangeRequest(struct range_conn* cur_range_conn, const char* range_request_str){
    if(!range_request_str){
        print_func("send_http_range_request: range_request str is null");
        return 0;
    }

    std::lock_guard<std::mutex> lock(cur_range_conn->std_mutex);

    if(!cur_range_conn->sockfd) {
        print_func("R%d-%d: send_http_range_request: sockfd is 0", cur_range_conn->id, cur_range_conn->port);
        return 0;
    }

    int send_result = -1;
    if(owner_.is_ssl){
    #ifdef USE_OPENSSL
            send_result = SSL_write(cur_range_conn->ssl, range_request_str, strlen(range_request_str));
    #endif
    } else {
        send_result = send(cur_range_conn->sockfd, range_request_str, strlen(range_request_str), MSG_NOSIGNAL);
    }

    if(send_result > 0){
        cur_range_conn->last_send = std::chrono::system_clock::now();
        cur_range_conn->requested_bytes += owner_.request_len;
        send_result = 1;
    }

    if(send_result <= 0){
        print_func("[Range]R%d-%d: send request failed, errno %d", cur_range_conn->id, cur_range_conn->port, errno);
    }

    return send_result;
}

int Optimack::send_http_range_request(struct range_conn* cur_range_conn, const char* range_request_str){
    if (!range_request_module_) {
        return -1;
    }
    return range_request_module_->sendHttpRangeRequest(cur_range_conn, range_request_str);
}

struct cb_range_data{
    std::shared_ptr<Optimack> obj;
    struct range_conn** range_conns;
    cb_range_data(std::shared_ptr<Optimack> obj_, struct range_conn** range_conns) : obj(obj_), range_conns(range_conns) {}
};

int cb_range_wrapper(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
    struct cb_range_data* cb_data = (struct cb_range_data*)data;
    return cb_data->obj->cb_range(qh, nfmsg, nfa, (void*)(cb_data->range_conns));
}

static range_conn* find_range_conn_by_port(range_conn** range_conns, unsigned short local_port) {
    for (int i = 0; i < GROUP_NUM * 2; ++i) {
        for (int j = 0; j < RANGE_NUM; ++j) {
            if (range_conns[i][j].port && range_conns[i][j].port == local_port) {
                return &range_conns[i][j];
            }
        }
    }
    return NULL;
}

static void handle_outgoing_range_packet(
    range_conn* subconn,
    mytcphdr* tcphdr,
    unsigned int seq,
    unsigned int ack,
    int payload_len,
    unsigned char* packet,
    int packet_len,
    unsigned short local_port
) {
    switch (tcphdr->th_flags) {
        case TH_ACK:
        case TH_ACK | TH_PUSH: {
            {
                std::lock_guard<std::mutex> lock(subconn->std_mutex);
                if(!subconn->in_use){
                    subconn->ini_seq_rem = ack - 1;
                    subconn->next_seq_rem = ack;
                    subconn->ini_seq_loc = seq - 1;
                    subconn->next_seq_loc = seq + payload_len;
                    subconn->in_use++;
                    print_func("R%d-%d: seq_init done - ini_seq_rem 0x%x(%u), ini_seq_loc 0x%x(%u)\n", subconn->id, local_port, subconn->ini_seq_rem, subconn->ini_seq_rem, subconn->ini_seq_loc, subconn->ini_seq_loc);
                }
            }

            if(subconn->in_use && payload_len && ack > subconn->next_seq_rem){
                tcphdr->th_ack = htonl(subconn->next_seq_rem);
                compute_checksums(packet, 20, packet_len);
                if(debug_range) {
                    print_func("[Range]R%d-%d: change ack %x to %x", subconn->id, local_port, ack, subconn->next_seq_rem);
                }
            }
            break;
        }
        default:
            print_func("[cb_range]R%d-%d: Unknown outgoing packet flag - %d!", subconn->id, local_port, tcphdr->th_flags);
            break;
    }
}

static void handle_incoming_range_packet(
    range_conn** range_conns,
    range_conn* subconn,
    mytcphdr* tcphdr,
    unsigned char* payload,
    int payload_len,
    unsigned int seq,
    unsigned int ack,
    char* g_local_ip,
    char* g_remote_ip
) {
    if(!(subconn->in_use && seq > subconn->ini_seq_rem)){
        return;
    }

    if(subconn->next_seq_loc < ack) {
        subconn->next_seq_loc = ack;
    }
    if(subconn->next_seq_rem < seq + payload_len) {
        subconn->next_seq_rem = seq + payload_len;
    }

    unsigned int seq_rel = seq - subconn->ini_seq_rem;
    switch (tcphdr->th_flags) {
        case TH_ACK:
        case TH_ACK | TH_PUSH:
        case TH_ACK | TH_URG: {
            if(payload_len){
                interval_map temp_range = subconn->group_recved_seq->removeInterval(seq_rel, seq_rel + payload_len);
                if(temp_range.size()){
                    int group_start_i = (subconn->id / 100 - 1);
                    for(int j = 0; j < RANGE_NUM; j++){
                        struct range_conn* conn = &range_conns[group_start_i][j];
                        if(conn != subconn){
                            send_ACK_payload(g_local_ip, g_remote_ip, conn->port, 80, payload, payload_len, conn->next_seq_loc, conn->ini_seq_rem + seq_rel);
                        }
                    }
                }
            }
            break;
        }
        default:
            print_func("[cb_range]R%d-%d: Unknown incoming packet flag - %d!", subconn->id, subconn->port, tcphdr->th_flags);
            break;
    }
}


int Optimack::cb_range(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data){
    unsigned char* packet;
    int packet_len = nfq_get_payload(nfa, &packet);
    struct range_conn** range_conns = (struct range_conn**)data;

    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfa);
    if (!ph) {
        printf("cb: can't get_msg_packet_hdr\n");
        return -1;
    }

    struct myiphdr *iphdr = ip_hdr(packet);
    struct mytcphdr *tcphdr = tcp_hdr(packet);
    unsigned char *payload = tcp_payload(packet);
    int payload_len = htons(iphdr->tot_len) - iphdr->ihl*4 - tcphdr->th_off*4;
    unsigned short sport = ntohs(tcphdr->th_sport);
    unsigned short dport = ntohs(tcphdr->th_dport);
    unsigned int seq = htonl(tcphdr->th_seq);
    unsigned int ack = htonl(tcphdr->th_ack);

    unsigned short local_port = dport;
    bool is_incoming = true;
    if (dport == 80 || dport == 443) {
        local_port = sport;
        is_incoming = false;
    }
    
    struct range_conn* subconn = find_range_conn_by_port(range_conns, local_port);
    if(!subconn){
        print_func("cb_range: conn not found");
        nfq_set_verdict(qh, htonl(ph->packet_id), NF_ACCEPT, packet_len, packet);
        return -1;
    }

    if(iphdr->protocol == 6){
        if(!is_incoming){
            handle_outgoing_range_packet(subconn, tcphdr, seq, ack, payload_len, packet, packet_len, local_port);
        } else {
            handle_incoming_range_packet(range_conns, subconn, tcphdr, payload, payload_len, seq, ack, g_local_ip, g_remote_ip);
        }
    }
    nfq_set_verdict(qh, htonl(ph->packet_id), NF_ACCEPT, packet_len, packet);
    return 0;

}


//Multi range request
void RangeRequestModule::runDispatchLoop()
{

    memset(owner_.range_request_template, 0 , 1000);
    owner_.range_request_template_len = 0;

    struct range_conn range_conns[GROUP_NUM*2][RANGE_NUM];
    struct range_conn* range_conns_ptrs[GROUP_NUM*2];
    for(int i = 0; i < GROUP_NUM*2;i++)
        range_conns_ptrs[i] = range_conns[i];
    
    IntervalList* group_queue[GROUP_NUM];
    for(int i = 0; i < GROUP_NUM; i++){
        group_queue[i] = new IntervalList();
    }

    if (!startGlobalRangeRecvHub(this, &owner_)) {
        for(int i = 0; i < GROUP_NUM; i++) {
            delete group_queue[i];
        }
        print_func("[Range]: failed to start global recv hub");
        return;
    }

    // create array of range_conns
    std::thread open_conn_threads[GROUP_NUM];
    for(int i = 0; i < GROUP_NUM; i++){
        // open_group_range_conn(range_conns_ptrs, i, g_remote_ip, g_remote_port, getptr());
        open_conn_threads[i] = std::thread(open_group_range_conn, range_conns_ptrs, i, owner_.g_remote_ip, owner_.g_remote_port, owner_.getptr(), this, group_queue[i]);
        open_conn_threads[i].detach();
    }

    // if(USE_CR == 1){ !!!QFQ Not working with if or define
        // printf("USE_CR == 1\n");
        // struct cb_range_data cb_data(getptr(), range_conns_ptrs);
        // NFQ nfq_range(MARK_RANGE, (void*)&cb_data, &cb_range_wrapper);
    // }


    while(!owner_.request_len && !owner_.range_stop) usleep(10);

    if (owner_.range_stop) {
        stopGlobalRangeRecvHub(this);
        for(int i = 0; i < GROUP_NUM; i++) {
            delete group_queue[i];
        }
        return;
    }

    memcpy(owner_.range_request_template, owner_.request, owner_.request_len);
    const char range_hdr[] = "Keep-Alive: timeout=150, max=300\r\nRange: bytes=";
    const int range_hdr_len = strlen(range_hdr);
    if (owner_.request_len >= 2 && static_cast<size_t>(owner_.request_len - 2 + range_hdr_len) < sizeof(owner_.range_request_template)) {
        memcpy(owner_.range_request_template + owner_.request_len - 2, range_hdr, range_hdr_len);
        owner_.range_request_template_len = owner_.request_len - 2 + range_hdr_len;
        owner_.range_request_template[owner_.range_request_template_len] = 0;
    } else {
        owner_.range_request_template_len = 0;
    }

    RangeGapDispatcher gap_dispatcher(GROUP_NUM, debug_range);
    interval_map dummy_range;
    dummy_range += std::make_pair(interval_type::right_open(1001, 1002), 0.01);
    while(!owner_.range_stop) {
        
        // dispatcher
        interval_map gaps = owner_.recved_seq.getGapsAndUpdateTimer(owner_.get_min_next_seq_rem(), 2*GROUP_NUM, 100);
        gap_dispatcher.distribute(gaps, group_queue);

        for(int i = 0; i < GROUP_NUM*2;i++){
                double time_passed = elapsed(range_conns[i][RANGE_NUM-1].last_send);
                if(range_conns[i][RANGE_NUM-1].port && range_conns[i][0].port && (time_passed >= 4.5) && (time_passed < 10) && (range_conns[i][0].range_request_count <= 90)){ //send dummy requests
                    range_conns[i][RANGE_NUM-1].last_send = std::chrono::system_clock::now();
                    std::thread send_thread(&RangeRequestModule::sendGroupRangeRequest, this, range_conns[i], dummy_range);
                    send_thread.detach();
                }
            }
        usleep(100);
    }

    // delete[] range_conns;
    stopGlobalRangeRecvHub(this);
    for(int i = 0; i < GROUP_NUM; i++)
        delete group_queue[i];
    print_func("[Range]: range_watch_multi thread exits...\n");
    // pthread_exit(NULL);
    return;
}



 
int Optimack::send_http_range_request(struct range_conn* cur_range_conn){
    char ranges_str[1000] = {0};
    int offset = 0;
    const int max_len = static_cast<int>(sizeof(ranges_str));
    uint* ranges_tmp = cur_range_conn->ranges;
    for(int i = 0; ranges_tmp[i] && i < 10; i += 2){
        if (offset >= max_len - 1) {
            break;
        }
        if(i > 1) {
            offset += snprintf(ranges_str + offset, max_len - offset, ", ");
        }
        offset += snprintf(ranges_str + offset, max_len - offset, "%u-%u", ranges_tmp[i], ranges_tmp[i+1]);
        if (offset < 0 || offset >= max_len) {
            ranges_str[max_len - 1] = '\0';
            break;
        }
    }
    print_func("[Range]R%d-%d: multi-range %s", cur_range_conn->id, cur_range_conn->port, ranges_str);

    return send_http_range_request(cur_range_conn, ranges_str);
}


int Optimack::send_http_range_request(struct range_conn* cur_range_conn, Interval* range){
    uint start = get_byte_seq(range->start), end = get_byte_seq(range->end);
    if (start == end || (start == 0 || end == 0 || request == NULL || request_len == 0))
        return -1;
    
    char ranges_str[100] = {0};
    snprintf(ranges_str, 100, "%u-%u", start, end);
    return send_http_range_request(cur_range_conn, ranges_str);
}


int find_least_range_conn(struct range_conn* range_conns, int range_conn_num){
    int min_i = 0;
    for(int i = 0; i < range_conn_num; i++){
        if(range_conns[i].requested_bytes < range_conns[min_i].requested_bytes){
            min_i = i;
        }
    }
    return min_i;
}



int Optimack::range_worker(int& sockfd, Interval* it){
    while(true){
        if(it->end <= cur_ack_rel)
            break;

        int rv = send_http_range_request(static_cast<intptr_t>(sockfd), it);

        if (rv < 0){
            print_func("[Range]: R%d bytes [%u, %u] failed\n", sockfd, it->start, it->end);
            log_debug("[R%d] bytes %d - %d failed", sockfd, it->start, it->end);
            // it->sent_epoch_time = 0;
        } 
        else{
            if(debug_range) print_func("[Range]: R%d bytes %d[%u, %u] requested", sockfd, rv, it->start, it->end);
            int ret = range_recv_block(sockfd, it);
            if(ret >= 0)
                break;
        }

        sockfd = establish_tcp_connection(sockfd, g_remote_ip, g_remote_port);
    }
    it->last_recved--;
    if(it->last_recved == 0)
        delete it;
    return 0;
}


int Optimack::range_recv_block(int sockfd, Interval* it){
    char response[MAX_RANGE_SIZE+1];
    int rv = 0, sockfd_old = 0;
    http_header header;
    header.start = (it->start);
    header.end = (it->end);
    header.parsed = 0;
    header.remain = it->end - it->start + 1;
    header.recved = 0;
    subconn_info* subconn = (subconn_infos.begin()->second);

    int consumed=0, unread=0, parsed=0, recv_offset=0, unsent=0;
    while (header.remain != 0){
        if(recv_offset == 0)
            memset(response+recv_offset, 0, MAX_RANGE_SIZE-recv_offset+1);
        if(is_ssl){
    #ifdef USE_OPENSSL
            // rv = SSL_read(range_conn_this->ssl, response+recv_offset, MAX_RANGE_SIZE-recv_offset);
    #endif
        }
        else{
            // print_func("[Range]: R%d, before recv", sockfd);
            rv = recv(sockfd, response+recv_offset, MAX_RANGE_SIZE-recv_offset, MSG_DONTWAIT);
        }

        if (rv > 0) {
            if(debug_range){
                log_error("[Range] recved %d bytes, hand over to process_range_rv", rv);
                print_func("[Range]: R%d recved %d bytes, hand over to process_range_rv", sockfd, rv);
            }
            process_range_rv_old(response, rv, this, subconn, &header, consumed, unread, parsed, recv_offset, unsent);
        }
        else if(rv <= 0){
            if(rv == 0){
                if(debug_range){
                    log_debug("[Range] recv ret %d, sockfd %d closed ", rv, sockfd);
                    print_func("[Range] recv ret %d, sockfd %d closed\n", rv, sockfd);
                }
            }
            else{
                // log_debug("[Range] R%d ret %d errno %d", rv, errno);
                // print_func("[Range] R%d ret %d errno %d\n", sockfd, rv, errno);
                if(!is_ssl){
                    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK){
                        continue;
                    }
                }
            }
            cleanup_range(sockfd, sockfd_old, &header, consumed, unread, parsed, recv_offset, unsent);
            if(debug_range) print_func("[Range]: closed range_sockfd %d\n", sockfd);
    #ifdef USE_OPENSSL
            // if(is_ssl)
                // range_conn_this->ssl_old = range_conn_this->ssl;
    #endif
            return -1;
        }
        usleep(100);
    }
    return 0;
}




int Optimack::insert_lost_range(uint start, uint end)
{
    if(start == UINT_MAX || end == UINT_MAX || start == 0 || end == 0 || end < start)
        return -1;
    return 0;
}
/***
   *tcp_seq: 1 <-tlshdr5-> 6 <-iv8-> 14 <-plaintext512-> 526 <-tag16-> 542 <-tlshdr5-> 547 <-iv8-> 555 <-plaintext512-> 1067 <-tag16-> 1083
   *byte seq(w_response_header):      1 <-plaintext512->                                           513 <-plaintext512->
   *tcp_seq,     byte_seq
   *1(start),    1         1 = 1 - 1/541*(5+8+16)
   *541(end),    512       512 = 541 - 541/541*29
   *542(start),  513       513 = 542 - 542/541*29
   *1082(end),   1024      1024 = 1082 - 1082/541*29
***/
uint Optimack::get_byte_seq(uint tcp_seq){

    if(!response_header_len)
        return UINT_MAX;

    long tcp_seq_sign = tcp_seq;

#ifdef USE_OPENSSL
    // uint record_num = get_record_num(tcp_seq);
    if(is_ssl)
        tcp_seq_sign -= tcp_seq_sign / MAX_FULL_GCM_RECORD_LEN * (TLSHDR_SIZE + 8 + 16);
#endif

    tcp_seq_sign -= response_header_len + 1; // range starts from zero!

    if(tcp_seq_sign < 0)
        return UINT_MAX;
    return tcp_seq_sign;
}


uint Optimack::get_tcp_seq(uint byte_seq){

    byte_seq += response_header_len + 1;

#ifdef USE_OPENSSL
    if(is_ssl){
        if((byte_seq)%MAX_FRAG_LEN != 0){
            log_info("get_tcp_seq: Not full divide: seq(%u %x) mod record_full_size(%d)\n", byte_seq, byte_seq, MAX_FRAG_LEN);
        }
        byte_seq += (byte_seq) / MAX_FRAG_LEN * (TLSHDR_SIZE + 8 + 16);
    }
#endif

    return byte_seq;
}




int Optimack::send_http_range_request(intptr_t sockfd_handle, Interval* range){
    uint start = get_byte_seq(range->start), end = get_byte_seq(range->end);
    if (start == end || (start == 0 || end == 0 || request == NULL || request_len == 0))
        return -1;
    
    const size_t request_buf_len = static_cast<size_t>(request_len) + 100;
    char* range_request = (char *)malloc(request_buf_len);
    if (!range_request) {
        return -1;
    }
    memset(range_request, 0 , request_buf_len);
    memcpy(range_request, request, request_len);
    if (request_len < 2) {
        free(range_request);
        return -1;
    }
    int printed = snprintf(
        range_request + request_len - 2,
        request_buf_len - static_cast<size_t>(request_len - 2),
        "Keep-Alive: timeout=150, max=300\r\nRange: bytes=%u-%u\r\n\r\n",
        start,
        end
    );
    if (printed <= 0) {
        free(range_request);
        return -1;
    }

    int rv = -1;
    if(is_ssl){
#ifdef USE_OPENSSL
        SSL *ssl = reinterpret_cast<SSL*>(sockfd_handle);
        if(ssl)
            rv = SSL_write(ssl, range_request, strlen(range_request));
#endif
    }
    else{
        int sockfd_ = static_cast<int>(sockfd_handle);
        rv = send(sockfd_, range_request, strlen(range_request), MSG_NOSIGNAL);
    }
    free(range_request);
    return rv;
}


void cleanup_range(int& range_sockfd, int& range_sockfd_old, http_header* header, int& consumed, int& unread, int& parsed, int& recv_offset, int& unsent){
    close(range_sockfd);
    range_sockfd_old = range_sockfd;
    range_sockfd = -1;
    memset(header, 0, sizeof(http_header));
    consumed = unread = parsed = recv_offset = unsent = 0;
}

int Optimack::get_http_response_header_len(subconn_info* subconn, unsigned char* payload, int payload_len){
#ifndef GPROF_CHECK
    Http1::ResponseParser rp;
    SBuf headerBuf;
    pthread_mutex_lock(&mutex_range);
    headerBuf.assign((char*)payload, payload_len);
    rp.parse(headerBuf);
    response_header_len = rp.messageHeaderSize();
    pthread_mutex_unlock(&mutex_range);
#else
    response_header_len = 398;
#endif

    response = (char*)malloc(response_header_len+1);
    memcpy(response, payload, response_header_len);
    response[response_header_len] = 0;

    
    file_size = get_content_length((char*)payload, payload_len);
    if(file_size){
        if(is_ssl){
#ifdef USE_OPENSSL
            ack_end = ((file_size + response_header_len - 1)/MAX_FRAG_LEN + 1) * MAX_FULL_GCM_RECORD_LEN + 1;
#endif
        }
        else
            ack_end += file_size + response_header_len;
    }
    return 0;
}

int get_content_length(const char* payload, int payload_len){
    const char* contentlen_field = "Content-Length: ";
    const char* payload_end = payload + payload_len;
    int contentlen_field_len = strlen(contentlen_field);
    const char* p_contentlen = std::search(payload, payload+payload_len, contentlen_field, contentlen_field+contentlen_field_len);
    if(p_contentlen < payload_end){
        p_contentlen += contentlen_field_len;
        int file_size = (u_int)std::stol(p_contentlen);
        return file_size;
    }
    return -1;
}




bool Optimack::check_packet_lost_on_all_conns(uint last_recv_inorder){
    
    if (recved_seq.size() < 1 || recved_seq.getFirstStart() == 1)
        return false;

    if(is_ssl){
#ifdef USE_OPENSSL
        if(!this->tls_record_seq_map)
            return false;
        TLS_Record_Seq_Info* seq_info = this->tls_record_seq_map->get_record_seq_info(last_recv_inorder+1);
        if(seq_info){
            last_recv_inorder = seq_info->upper_seq - 1;
        }
#endif
    }

    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        uint next_seq_rem = it->second->next_seq_rem;
// #ifdef USE_OPENSSL                
//         if(is_ssl)
//             next_seq_rem = it->second->next_seq_rem_tls;
// #endif        
        if(!it->second->is_backup && !it->second->fin_or_rst_recved && it->second->restart_counter < 3 && next_seq_rem <= last_recv_inorder){
            return false;
        }
    }
    usleep(1000);
    char tmp[1000] = {0};
    for (auto it = subconn_infos.begin(); it != subconn_infos.end(); it++){
        uint next_seq_rem = it->second->next_seq_rem;
// #ifdef USE_OPENSSL                
//         if(is_ssl)
//             next_seq_rem = it->second->next_seq_rem_tls;
// #endif
        if(!it->second->is_backup && !it->second->fin_or_rst_recved && it->second->restart_counter < 3 && next_seq_rem <= last_recv_inorder){
            log_info("second: %s, <=, return false", tmp);
            return false;
        }
    }
    return true;
}
