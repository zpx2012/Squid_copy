/**
 * http_oack_client.cpp
 *
 * A C++ program that connects to an HTTP server and accurately measures packet
 * loss. It waits for the first data packet before sending optimistic ACKs.
 * It uses libnetfilter_queue to intercept all incoming packets and logs their
 * byte ranges in a Boost.Icl interval_set to correctly handle retransmissions
 * and overlapping segments.
 *
 * This version automatically configures and cleans up the required iptables rules.
 *
 * HOW TO COMPILE:
 * g++ -std=c++17 -o http_oack_client http_oack_client.cpp -lnetfilter_queue -lmnl -lpthread -lboost_system
 *
 * PREREQUISITES:
 * You must have the Boost C++ libraries installed. On Debian/Ubuntu:
 * sudo apt-get install libboost-dev
 * You also need hping3 for the dummy packet:
 * sudo apt-get install hping3
 *
 * HOW TO RUN:
 * 1. You MUST run this program as root.
 * 2. Provide server IP, port, URI, and duration as arguments.
 * Example: sudo ./http_oack_client 93.184.216.34 80 / 10
 */

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <cstdarg>
#include <cmath>
#include <csignal>
#include <mutex>
#include <iomanip> // For std::setprecision

// C headers
#include <unistd.h>
#include <fcntl.h> // For fcntl
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

// Boost headers for the interval set
#include <boost/icl/interval_set.hpp>

#define MSS 1460 // Standard Maximum Segment Size for Ethernet to estimate packet count

// --- Global Variables ---
volatile uint32_t g_server_initial_seq = 0;
volatile uint32_t g_client_initial_seq = 0;
volatile bool g_handshake_complete = false;
volatile bool g_data_flow_started = false; // Flag to signal start of data transfer
volatile bool g_program_running = true;
boost::icl::interval_set<uint32_t> g_received_byte_intervals;
std::mutex g_interval_mutex; // Mutex to protect access to the interval set

// Struct for NFQ thread arguments
struct ClientArgs {
    std::string server_ip;
    uint32_t my_port;
};

// --- C-style helper functions ---

// A utility function to run a system command
void run_command(const char *format, ...) {
    char command[256];
    va_list args;
    va_start(args, format);
    vsnprintf(command, sizeof(command), format, args);
    va_end(args);
    // std::cout << "[CMD] Executing: " << command << std::endl;
    if (system(command) != 0) {
        std::cerr << "[CMD] Warning: Command failed - " << command << std::endl;
    }
}

// Pseudo-header for TCP checksum calculation
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

// Checksum calculation function
unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        unsigned short oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)~sum;
}

// The callback function needs C linkage to be callable from the C library libnetfilter_queue
extern "C" int packet_handler(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                              struct nfq_data *nfa, void *data) {
    unsigned char *packet_data;
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) id = ntohl(ph->packet_id);

    auto *args = static_cast<ClientArgs*>(data);
    struct in_addr server_addr;
    inet_pton(AF_INET, args->server_ip.c_str(), &server_addr);
    unsigned short my_port = args->my_port;

    int len = nfq_get_payload(nfa, &packet_data);
    if (len >= 0) {
        struct iphdr *iph = (struct iphdr *)packet_data;
        if (iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr *)(packet_data + iph->ihl * 4);
            unsigned short sport = ntohs(tcph->th_sport);
            unsigned short dport = ntohs(tcph->th_dport);
            uint16_t tcp_payload_len = ntohs(iph->tot_len) - (iph->ihl * 4) - (tcph->doff * 4);
            
            if (tcp_payload_len > 0) {
                if (!g_handshake_complete) {
                    if (iph->daddr == server_addr.s_addr && tcph->ack && g_client_initial_seq == 0) { //&& sport == my_port
                        g_client_initial_seq = ntohl(tcph->seq) - 1;
                        g_server_initial_seq = ntohl(tcph->ack_seq) - 1;
                        g_handshake_complete = true;
                        // printf("ini_seq: %x, ini_ack: %x\n", g_client_initial_seq, g_server_initial_seq);
                    }
                } else if (iph->saddr == server_addr.s_addr ) { //&& dport == my_port

                    // This is the first data packet, signal the main thread to start ACKing
                    if (!g_data_flow_started) {
                        g_data_flow_started = true;
                    }
                    uint32_t seq = ntohl(tcph->seq);
                    boost::icl::discrete_interval<uint32_t> received_interval = 
                    boost::icl::discrete_interval<uint32_t>::right_open(seq, seq + tcp_payload_len);
                    
                    std::lock_guard<std::mutex> lock(g_interval_mutex);
                    g_received_byte_intervals += received_interval;
                }
            }
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

// The thread function that runs the netfilter_queue loop.
void nfq_thread_func(ClientArgs* args) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    char buf[4096] __attribute__((aligned));

    h = nfq_open();
    if (!h) { std::cerr << "Error during nfq_open()\n"; exit(1); }
    if (nfq_unbind_pf(h, AF_INET) < 0) { std::cerr << "Error during nfq_unbind_pf()\n"; exit(1); }
    if (nfq_bind_pf(h, AF_INET) < 0) { std::cerr << "Error during nfq_bind_pf()\n"; exit(1); }
    qh = nfq_create_queue(h, 0, &packet_handler, args);
    if (!qh) { std::cerr << "Error during nfq_create_queue()\n"; exit(1); }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) { std::cerr << "Error during nfq_set_mode()\n"; exit(1); }

    fd = nfq_fd(h);
    while (g_program_running) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(h, buf, rv);
        } else if (g_program_running) {
            std::cerr << "recv failed on nfq_fd\n";
        }
    }
    
    // std::cout << "[NFQUEUE] Terminating packet capture." << std::endl;
    nfq_destroy_queue(qh);
    nfq_close(h);
}

// Creates and sends a raw TCP ACK packet.
void send_optimistic_ack(int sock, const std::string& source_ip, const std::string& dest_ip, int source_port, int dest_port, uint32_t seq, uint32_t ack_seq) {

    char datagram[4096] = {0};
    struct iphdr *iph = (struct iphdr *)datagram;
    iph->ihl = 5; iph->version = 4; iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
    iph->id = htonl(rand() % 65535); iph->ttl = 64; iph->protocol = IPPROTO_TCP;
    iph->saddr = inet_addr(source_ip.c_str()); iph->daddr = inet_addr(dest_ip.c_str());

    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));
    tcph->source = htons(source_port); tcph->dest = htons(dest_port);
    tcph->seq = htonl(seq); tcph->ack_seq = htonl(ack_seq);
    tcph->doff = 5; tcph->ack = 1; tcph->window = htons(5840);

    struct pseudo_header psh;
    psh.source_address = iph->saddr; psh.dest_address = iph->daddr;
    psh.placeholder = 0; psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));
    
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char* pseudogram = new char[psize];
    memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
    tcph->check = csum((unsigned short*)pseudogram, psize);
    delete[] pseudogram;

    iph->check = csum((unsigned short*)datagram, iph->tot_len);

    struct sockaddr_in sin;
    sin.sin_family = AF_INET; sin.sin_port = tcph->dest; sin.sin_addr.s_addr = iph->daddr;

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    sendto(sock, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
}

int main(int argc, char **argv) {
    if (argc != 5) {
        std::cerr << "Usage: " << argv[0] << " <server_ip> <server_port> <uri> <duration_sec>\n";
        return 1;
    }

    std::string server_ip = argv[1];
    int server_port = std::stoi(argv[2]);
    std::string uri = argv[3];
    int duration = std::stoi(argv[4]);
    int sock = -1; // Initialize socket descriptor
    const int MARK = 666;
    unsigned int my_port;

    int sockraw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (setsockopt(sockraw, SOL_SOCKET, SO_MARK, &MARK, sizeof(MARK)) < 0)
    {
        return -1;
    }

    run_command("sudo iptables -I OUTPUT 1 -p tcp -m mark --mark 666 -j ACCEPT");    

    // Main logic block using do-while(0) to replace goto
    do{
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { 
            std::cerr << "Socket creation error\n"; 
            break; 
        }

        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(server_port);
        inet_pton(AF_INET, server_ip.c_str(), &serv_addr.sin_addr);

        if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            perror("Connection Failed");
            break;
        }
        
        struct sockaddr_in my_addr;
        socklen_t len = sizeof(my_addr);
        getsockname(sock, (struct sockaddr *)&my_addr, &len);
        char my_ip_cstr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &my_addr.sin_addr, my_ip_cstr, sizeof(my_ip_cstr));
        std::string my_ip = my_ip_cstr;
        my_port = ntohs(my_addr.sin_port);

        ClientArgs c_args{server_ip, my_port};
        std::thread nfq_worker(nfq_thread_func, &c_args);
        run_command("sudo iptables -I OUTPUT 2 -p tcp -d %s --dport %d --sport %d -j NFQUEUE --queue-num 0", server_ip.c_str(), server_port, my_port);
        run_command("sudo iptables -I INPUT 1 -p tcp -s %s --sport %d --dport %d -j NFQUEUE --queue-num 0", server_ip.c_str(), server_port, my_port);

        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        std::string request = "GET " + uri + " HTTP/1.1\r\nHost: " + server_ip + "\r\nConnection: keep-alive\r\n\r\n";
        send(sock, request.c_str(), request.length(), 0);

        // Set socket to non-blocking to drain it without hanging
        fcntl(sock, F_SETFL, fcntl(sock, F_GETFL, 0) | O_NONBLOCK);
        char drain_buffer[4096];

        // std::cout << "[MAIN] Waiting for first data packet from server..." << std::endl;
        auto wait_start_time = std::chrono::steady_clock::now();
        bool timed_out = false;
        while (!g_data_flow_started) {
            recv(sock, drain_buffer, sizeof(drain_buffer), 0); // Keep draining buffer
            if (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - wait_start_time).count() > 30) {
                std::cerr << "[MAIN] Timeout: Server did not send any data." << std::endl;
                timed_out = true;
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        if (timed_out) break;

        // std::cout << "[MAIN] First data packet detected. Starting optimistic ACKs for " << duration << " seconds..." << std::endl;
        run_command("sudo iptables -R OUTPUT 2 -p tcp -d %s --dport %d --sport %d -j DROP", server_ip.c_str(), server_port, my_port);

        if(!g_handshake_complete)
            break;
        uint32_t client_seq_for_acks = g_client_initial_seq + 1 + request.length();
        uint32_t optimistic_ack_value = g_server_initial_seq + 1;

        auto oack_start_time = std::chrono::steady_clock::now();
        while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - oack_start_time).count() < duration) {
            optimistic_ack_value += MSS;
            send_optimistic_ack(sockraw, my_ip, server_ip, my_port, server_port, client_seq_for_acks, optimistic_ack_value);
            // recv(sock, drain_buffer, sizeof(drain_buffer), 0); // Continue draining
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        // std::cout << "[MAIN] Duration elapsed. Waiting 5s for grace period..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));

        g_program_running = false;
        // Send dummy packet to unblock recv() in nfq_thread
        //run_command("sudo hping3 127.0.0.1 -c 1 -p 12345 > /dev/null 2>&1");
        if(nfq_worker.joinable()) nfq_worker.join(); 

    }while(false);

    // --- Cleanup ---


    // std::cout << "\n--- Packet Loss Calculation ---\n";
    std::lock_guard<std::mutex> lock(g_interval_mutex);
    if (g_received_byte_intervals.empty()) {
        std::cout << "No data packets were received from the server.\n";
    } else {
        uint32_t start_seq = g_server_initial_seq + 1;
        uint32_t end_seq = boost::icl::last(g_received_byte_intervals);        
        unsigned long total_bytes_expected = (unsigned long)((uint32_t)end_seq - (uint32_t)start_seq) + 1;
        unsigned long total_bytes_received = boost::icl::size(g_received_byte_intervals);
        unsigned long lost_bytes = total_bytes_expected > total_bytes_received ? total_bytes_expected - total_bytes_received : 0;
        
        double inferred_total_packets = ceil(static_cast<double>(total_bytes_expected) / MSS);
        double captured_packets = g_received_byte_intervals.iterative_size();
        double lost_packets = ceil(static_cast<double>(lost_bytes) / MSS);
        double loss_rate = (inferred_total_packets > 0) ? (lost_packets / inferred_total_packets) * 100.0 : 0.0;

        // std::cout << "Server Initial Sequence: " << g_server_initial_seq + 1 << std::endl;
        // std::cout << "Highest Bytes Received: " << end_seq << std::endl;
        // std::cout << "Total Bytes Received: " << total_bytes_received << std::endl;
        // std::cout << "Total Bytes Expected: " << total_bytes_expected << std::endl;
        // std::cout << "Total Bytes Lost: " << lost_bytes << std::endl;
        // std::cout << "Number of Segments Received: " << captured_packets << std::endl;
        // std::cout << "Estimated Lost Packets: " << lost_packets << std::endl;
        // std::cout << "Packet Loss Rate: " << std::fixed << std::setprecision(2) << loss_rate << "%" << std::endl;
        std::cout << std::fixed << std::setprecision(6) << std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch()).count()/1000000000.0 << "," 
                  << std::fixed << std::setprecision(2) << loss_rate << "," 
                  << (loss_rate > 5 ? "True" : "False") << std::endl;
    }
    
    if (sock >= 0) close(sock);
    if (sockraw >= 0) close(sockraw);
    run_command("sudo iptables -D OUTPUT -p tcp -m mark --mark 666 -j ACCEPT");    
    run_command("sudo iptables -D OUTPUT -p tcp -d %s --dport %d --sport %d -j DROP", server_ip.c_str(), server_port, my_port);
    run_command("sudo iptables -D INPUT -p tcp -s %s --sport %d --dport %d -j NFQUEUE --queue-num 0", server_ip.c_str(), server_port, my_port);

    return 0;
}
