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
			(((_p)->th_sport == filter.port\
			  || (_p)->th_dport == filter.port) ?\
			  1 : 0)\
			  : 1)

#define FILTER_UDP(_p) (filter.flg[PORT] ?\
			(((_p)->uh_sport == filter.port\
			  || (_p)->uh_dport == filter.port) ?\
			  1 : 0)\
			  : 1)

typedef struct {
	struct in_addr ip;	/* IPアドレス */
	u_int16_t port;		/* ポート番号 */
	int flg[2];		/* フィルタフラグ */
} filter_t;

#ifndef __linux
int open_bpf(char *ifname, int *bufsize);
#endif

void print_ethernet(struct ether_header *eth);
void print_arp(struct ether_arp *arp);
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
	int s;			/* ソケットディスクリプタ */
	int c;			/* getopt()で取得した文字 */
	char ifname[CMAX] = "";	/* インタフェース名 */
	int opt[OPTNUM];	/* 表示オプションのフラグ */
	extern int optind;	/* getopt()のグローバル変数 */
#ifndef __linux
	struct bpf_hdr *bp;	/* BPFヘッ構造体 */
	int bpf_len;		/* BPFでの受信データの長さ */
	int bufsize;		/* BPF内部のバッファサイズ */
#endif
	filter_t filter;	/* フィルタする情報 */

	/* 表示するパケット（オプション）の初期値 */
	opt[ETHER] = OFF;
	opt[ARP] = ON;
	opt[IP] = ON;
	opt[TCP] = ON;
	opt[UDP] = ON;
	opt[ICMP] = ON;
	opt[DUMP] = OFF;
	opt[ALL] = OFF;
	opt[TIME] = OFF;
	/* フィルタの初期値 */
	filter.flg[IP_ADDR] = OFF;
	filter.flg[PORT] = OFF;

	/* コマンドラインオプションの検査 */
	while((c = getopt(argc, argv, "aei:p:f:dhft")) != EOF){
		switch(c) {
			case 'a':	/* all */
				opt[ALL] = ON;
				break;
			case 'e':	/* ethernet */
				opt[ETHER] = ON;
				break;
			case 'd':	/* dump */
				opt[DUMP] = ON;
				break;
			case 't':	/* time */
				opt[TIME] = ON;
				break;
			case 'i':	/* if name */
				snprintf(ifname, sizeof(ifname), "%.255s", optarg);
				break;
			case 'p':	/* protocol */
				opt[ARP] = OFF;
				opt[IP] = OFF;
				opt[TCP] = OFF;
				opt[UDP] = OFF;
				opt[ICMP] = OFF;
				optind--;
				while (argv[optind] != NULL && argv[optind][0] != '-') {
					if (strcmp(argv[optind], "arp") == 0)
						opt[ARP] = ON;
					else if (strcmp(argv[optind], "ip") == 0)
						opt[IP] = ON;
					else if (strcmp(argv[optind], "tcp") == 0)
						opt[TCP] = ON;
					else if (strcmp(argv[optind], "udp") == 0)
						opt[UDP] = ON;
					else if (strcmp(argv[optind], "icmp") == 0)
						opt[ICMP] = ON;
					else if (strcmp(argv[optind], "other") == 0)
						;
					else {
						help(argv[0]);
						exit(EXIT_FAILURE);
					}
					optind++;
				}
				break;
			case 'f':	/* filter */
				optind--;
				while(argv[optind] != NULL && argv[optind][0] != '-') {
					if (strcmp(argv[optind], "ip") == 0 && argv[optind+1] != NULL) {
						filter.flg[IP_ADDR] = ON;
						filter.ip.s_addr = inet_addr(argv[++optind]);
					}
					else if (strcmp(argv[optind], "port") == 0 && argv[optind+1] != NULL) {
						filter.flg[PORT] = ON;
						filter.port = htons(atoi(argv[++optind]));
					} else {
						help(argv[0]);
						exit(EXIT_FAILURE);
					}
					optind++;
				}
				break;
			case 'h':	/* help */
			case '?':
			default:
				help(argv[0]);
				exit(EXIT_FAILURE);
				break;
		} /* switch */
	} /* while */

	if (optind < argc) {
		while (optind < argc) 
			printf("%s ", argv[optind++]);

		printf("\n");
		help(argv[0]);
		exit(EXIT_FAILURE);
	}

	if(filter.flg[IP_ADDR])
		printf("filter ip   = %s\n", inet_ntoa(filter.ip));
	if(filter.flg[PORT])
		printf("filter port = %d\n", htons(filter.port));
#ifdef __linux
	if((s == socket(AF_INET, SOCK_PACKET, htons(ETH_P_ALL))) < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	if(strcmp(ifname, "") != 0) {
		struct sockaddr sa;

		memset(&sa, 0, sizeof sa);
		sa.sa_family = AF_INET;
		snprintf(sa.sa_data, sizeof(sa.sa_data), "%.13s", ifname);
		if(bind(s, &sa, sizeof(sa)) < 0) {
			perror("bind");
			exit(EXIT_FAILURE);
		}
	}
#else
	if(strcmp(ifname, "") == 0)
		strcpy(ifname, DEF_IF);
	
	if((s == open_bpf(ifname, &bufsize)) < 0)
		exit(EXIT_FAILURE);

	bpf_len = 0;
#endif

	while(1) {
		struct ether_header *eth;	/* Ethernetヘッダ構造体 */
		struct ether_arp *arp;		/* ARPパケット構造体 */
		struct ip *ip;			/* IPヘッダ構造体 */
		struct icmp *icmp;		/* ICMPパケット構造体 */
		struct tcphdr *tcp;		/* TCPヘッダ構造体 */
		struct udphdr *udp;		/* UDPヘッダ構造体 */
		char buff[MAXSIZE];		/* データ受信バッファ */
		void *p;			/* ヘッダの先頭を指す作業用ポインタ */
		void *p0;			/* パケットの先頭を指すポインタ */
		int len;			/* 受信したデータの長さ */
		int disp;			/* 画面に出力したかどうかのフラグ */
		struct timeval tv;		/* パケットをダンプした時刻 */
		struct tm tm;			/* localtimeでの時刻表示 */

#ifndef __linux
		/* BPFからの入力 */
		if(bpf_len <= 0) {
			if((bpf_len = read(s, buff, bufsize)) < 0) {
				perror("read");
				exit(EXIT_FAILURE);
			}
			bp = (struct bpf_hdr *)buff;
		} else {
			bp = (struct bpf_hdr *)((char *)bp + bp->bh_hdrlen + bp->bh_caplen);
			bp = (struct bpf_hdr *)BPF_WORDALIGN((int)bp);
		}

		/* バケットダンプの時刻をセット */
		memcpy(&tv, &(bp->bh_tstamp), sizeof(tv));
		localtime_r((time_t *)&tv.tv_sec, &tm);
		/* Ethernetヘッダの先頭にポインタをセット */
		p = o0 = (char *)bp + bp->bh_hdrlen;
		len = bp->bh_caplen;
#ifdef DEBUG
		/* BPFヘッダ構造の値を表示 */
		printf("bpf_len = %d,", bpf_len);
		printf("hdrlen=%d,", bp->bh_hdrlen);
		printf("caplen=%d,", bp->bh_caplen);
		printf("datalen=%d\n", bp->bh_datalen);
#endif
		/* 次のwhileループのための処理 */
		bpf_len -= BPF_WORDALIGN(bp->bh_hdrlen + bp->bh_caplen);
#else
		/* Linux SOCK_PACKETからの入力 */
		if((len = read(s, buff, MAXSIZE)) < 0) {
			perror("read");
			exit(EXIT_FAILURE);
		}
		/* パケットダンプの時刻をセット */
		gettimeofday(&tv, (struct timezone *) 0);
		localtime_r((time_t *)&tv.tv_sec, &tm);
		/* Ethernetヘッダの先頭にポインタをセット */
		p = p0 = buff;
#endif
		/*
		 * パケット解析ルーチン
		 */
		disp = OFF;	/* 画面に出力するかどうかのフラグ */

		/* Ethernetヘッダ構造体の設定 */
		eth = (struct ether_header *)p;
		p += sizeof(struct ether_header);

		if(ntohs(eth->ether_type) == ETHERTYPE_ARP) {
			arp = (struct ether_arp *)p;
			if(opt[ARP] == ON && FILTER_ARP(arp))
				disp = ON;
		} else if(ntohs(eth->ether_type) == ETHERTYPE_IP) {
			ip = (struct ip *)p;
			p += ((int)(ip->ip_hl) << 2);

			if(!FILTER_IP(ip))
				continue;

			if(opt[IP] == ON && opt[TCP] != ON && opt[UDP] != ON && opt[ICMP] != ON)
				disp = ON;

			switch(ip->ip_p) {
				case IPPROTO_TCP:
					tcp = (struct tcphdr *)p;
					p += ((int)(tcp->th_off) << 2);
					if(!FILTER_TCP(tcp))
						continue;

					if(opt[TCP] == ON)
						disp = ON;

					break;
				case IPPROTO_UDP:
					udp = (struct udphdr *)p;
					p += sizeof(struct udphdr);
					if(!FILTER_UDP(udp))
						continue;

					if(opt[UDP] == ON)
						disp = ON;

					break;
				case IPPROTO_ICMP:
					icmp = (struct icmp *)p;
					p = icmp->icmp_data;
					if(opt[ICMP] == ON)
						disp = ON;
					
					break;
				default:
					if(opt[ALL] == ON)
						disp = ON;

					break;
			} /* switch(ip->ip_p) */
		} else if(opt[ETHER] == ON && opt[ALL] == ON)
			disp = ON;

		/*
		 * パケット表示ルーチン
		 */
		if(disp == ON || opt[ALL] == ON) {
			if(opt[TIME] == ON)
				printf("Time: %02d:%02d:%02d.%06d\n", tm.tm_hour, tm.tm_min, tm.tm_sec, (int)tv.tv_usec);

			if(opt[ETHER] == ON)
				print_ethernet(eth);

			if(ntohs(eth->ether_type) == ETHERTYPE_ARP) {
				if(opt[ARP] == ON)
					print_arp(arp);
			} else if(ntohs(eth->ether_type) == ETHERTYPE_IP){
				if(opt[IP] == ON)
					print_ip(ip);

				if(ip->ip_p == IPPROTO_TCP && opt[TCP] == ON)
					print_tcp(tcp);
				else if(ip->ip_p == IPPROTO_UDP && opt[UDP] == ON)
					print_udp(udp);
				else if(ip->ip_p == IPPROTO_ICMP && opt[ICMP] == ON)
					print_icmp(icmp);
				else if(opt[ALL] == ON)
					printf("Protocol: unlnown\n");
			} else if(opt[ALL] == ON) {
				printf("Protocol: unlnown\n");
			}

			if(opt[DUMP] == ON) {
				dump_packet(p0, len);
			}
			printf("\n");
		} /* if(disp == ON || opt[ALL] == ON) */
	} /* while(1) */

	return 0;
}

/*
 * char *mac_ntoa(u_char *d)
 * 機能
 *   配列に格納されているMACアドレスを文字列に変換
 *   static変数を利用するため、非リエントラント関数
 * 引数
 *   u_char *d;		MACアドレスが格納されている領域の先頭アドレス
 * 戻り値
 *   文字列表現のMACアドレス
 */
char *mac_ntoa(u_char *d)
{
#define MAX_MACSTR 50
	static char str[MAX_MACSTR];

	snprintf(str, MAX_MACSTR, "%02x:%02x:%02x:%02x:%02x:%02x",
			d[0], d[1], d[2], d[3], d[4], d[5]);

	return str;
}

/*
 * void print_ethernet(struct ether_header *eth);
 * 機能
 *   Ethernetヘッダの表示
 * 表示
 *   struct ether_header *rth; Ethernetヘッダ構造体へのポインタ
 * 戻り値
 *   なし
 */
void print_ethernet(struct ether_header *eth)
{
	int type = ntohs(eth->ether_type); /* Ethernetタイプ */

	if(type <= 1500)
		printf("IEEE 802.3 Ethernet Frame:\n");
	else
		printf("Ethernet Frame:\n");

	printf("+-------------------------+-------------------------+-------------------------+\n");
	printf("| Destination MAC Address: %17s|\n", mac_ntoa(eth->ether_dhost));
	printf("+-------------------------+-------------------------+-------------------------+\n");
	printf("| Source MAC Address:      %17s|\n", mac_ntoa(eth->ether_shost));
	printf("+-------------------------+-------------------------+-------------------------+\n");

	if(type < 1500)
		printf("| Length:        %5u|\n", type);
	else
		printf("| Ethernet Type: 0x%04x|\n", type);

	printf("+--------------------+\n");
}

void print_arp(struct ether_arp *arp)
{
}

void print_ip(struct ip *ip)
{
}

char *ip_ftoa(int flag)
{
	return NULL;
}

char *ip_ttoa(int flag)
{
	return NULL;
}

void print_icmp(struct icmp *icmp)
{
}

void printf_tcp_mini(struct tcphdr *tcp)
{
}

void print_tcp(struct tcphdr *tcp)
{
}

char *tcp_ftoa(int flag)
{
}

void print_udp(struct udphdr *udp)
{
}

void dump_packet(unsigned char *buff, int len)
{
}

#ifndef __linux
int open_bpf(char *ifname, int *bufsize)
{
	return 0;
}
#endif

void help(char *cmd)
{
}

