
#ifndef __GLOBALS_H__
#define __GLOBALS_H__

#define NF_QUEUE_NUM 1

extern char pkt_data[10000];
extern size_t pkt_len;

extern char payload_sk[1000];
extern char payload_nosk[1000];
extern char payload_sk_split21[1000];
extern char payload_sk_split22[1000];
extern char payload_sk_split31[1000];
extern char payload_sk_split32[1000];
extern char payload_sk_split33[1000];

extern unsigned char legal_ttl;
extern unsigned char last_ttl;

extern char type1gfw[30], type2gfw[30];

extern int type1rst, type2rst, succrst, succsynack;

extern timespec start, end;

extern pid_t tcpdump_pid;

extern int nfq_stop;
extern void nfq_process(int timeout = 1);
extern void* nfq_loop(void *arg);

extern int opt_measure;

#endif
