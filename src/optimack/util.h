
#ifndef __UTIL_H__
#define __UTIL_H__

int startswith(const char *a, const char *b);

void get_local_ip(char *ip);

void traceroute(char *remote_ip, char *output_file);
void get_legal_ttl(char *remote_ip);
void locate_gfw(char *remote_ip);

char* ip2str(u_int32_t ip, char *str);
u_int32_t str2ip(const char *str);
int cmp_ip(char* ip_str, u_int32_t ip_inaddr);

char* tcp_flags_str(u_int8_t flags);

char* hex_dump_str(const unsigned char *packet, size_t size);
void hex_dump(const unsigned char *packet, size_t size);
void human_dump(const unsigned char *packet, size_t size);
timespec diff(timespec end, timespec start);

#endif
