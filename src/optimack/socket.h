
#ifndef __SOCKET_H__
#define __SOCKET_H__

void send_ACK_payload(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port, unsigned char* payload, int payload_len, unsigned int ack, unsigned int seq = 1, unsigned int win_size = 29200, unsigned char ttl = 128);
void send_SYN(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port, char* payload, unsigned int ack, unsigned int seq = 1, unsigned char ttl = 128);
void send_ACK(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port, char* payload, unsigned int ack, unsigned int seq = 1, unsigned int win_size = 29200, unsigned char ttl = 128);
void send_request(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port, char* payload, unsigned int ack, unsigned int seq = 1, unsigned char ttl = 128);
void send_FIN_ACK(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port, char *payload, unsigned int ack, unsigned int seq = 1, unsigned char ttl = 128);
void send_RST(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port, char* payload, unsigned int seq = 1, unsigned char ttl = 128);
void send_ACK_with_SACK(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port, unsigned char* sack_str, int sack_len, char* payload, unsigned int ack, unsigned int seq = 1, unsigned int win_size = 29200, unsigned char ttl = 128);

unsigned int wait_SYN_ACK(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port, unsigned int ack = 0, int timeout = 1, char* pkt_data = NULL);
unsigned int wait_data(char* remote_ip, char* local_ip, unsigned short remote_port, unsigned short local_port, unsigned int ack = 0, unsigned int seq = 1, char* pkt_data = NULL);

#endif
