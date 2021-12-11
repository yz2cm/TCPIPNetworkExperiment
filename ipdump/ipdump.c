#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#ifndef __linux
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/if.h>
#include <fcntl.h>
#endif
#include <netinet/if_ether.h>

#define MAXSIZE	8192
#define CMAX	256
#define OPTNUM	9
#define ON	1
#define OFF	0
#define DEF_IF	"en0"	/* Mac OS Xのデフォルトインタフェース名 */

enum {ETHER, ARP, IP, TCP, UDP, ICMP, DUMP, ALL, TIME};
enum {IP_ADDR, PORT};

/* パケットフィルタ用マクロ */
#define FILTER_ARP(_p) (filter.flg[IP_ADDR] ?\
			((*(int *)(_p)->arp_spa == filter.ip.s_addr\
			  || *(int *) (_p)->arp_tpa == filter.ip.s_addr) ?\
			  1 : 0)\
			  : 1)
#define FILTER_IP(_p) (filter.flg[IP_ADDR] ?\
			(((_p)->ip_src.s_addr == filter.ip.s_addr\
			  || (_p)->ip_dst.s_addr == filter.ip.s_addr) ?\
			  1 : 0)\
			  : 1)

#define FILTER_TCP(_p) (filter.flg[PORT] ?\
			(((_p)->th_port == filter.port\
			  || (_p)->th_dport == filter.port) ?\
			  1 : 0)\
			  : 1)

#define FILTER_UDP(_p) (filter.flg[PORT] ?\
			(((_p)->uh_sport == filter.port\
			  || (_p)->uh_dport == filter.port) ?\
			  1 : 0)\
			  : 1)

struct filter {
	struct in_addr ip;	/* IPアドレス */
	u_int16_t port;		/* ポート番号 */
	int flg[2];		/* フィルタフラグ */
};

#ifndef __linux
int open_bpf(char *ifname, int *bufsize);
#endif

void print_ethernet(struct ether_header *eth);
void print_arg(struct ether_arp *arp);
void print_ip(struct ip *ip);
void print_icmp(struct icmp *icmp);
void print_tcp(struct tcphdr *tcp);
void print_tcp_mini(struct tcphdr *tcp);
void print_udp(struct udphdr *udp);
void dump_packet(unsigned char *buff, int len);
char *mac_ntoa(u_char *d);
char *tcp_ftoa(int flag);
char *ip_ttoa(int flag);
char *ip_ftoa(int flag);
void help(char *cmd);
int main(int argc, char **argv)
{
	return 0;
}

