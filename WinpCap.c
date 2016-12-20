 
#include "stdafx.h"
#include<stdio.h>
#include<stdlib.h>
#define HAVE_REMOTE 
#include<pcap.h>
#include<errno.h>


#include <WINSOCK2.h>
#pragma comment(lib,"WS2_32.LIB")

 



//截取的长度
#define SNAP_LEN 1518

/* 以太网头长度:14字节 */
#define SIZE_ETHERNET 14

/* 以太网地址长度:6字节 */
#define ETHER_ADDR_LEN	6



/* 以太网头 */
struct sniff_ethernet {
	u_char  ether_dhost[ETHER_ADDR_LEN];    /* 目的MAC地址(以字符形式存储,8位存于一个char中) */
	u_char  ether_shost[ETHER_ADDR_LEN];    /* 源MAC地址(以字符形式存储,8位存于一个char中) */
	u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP头 */
struct sniff_ip {
	u_char  ip_vhl;                 //首部长度＋版本
	u_char  ip_tos;                 //服务
	u_short ip_len;                 //总长度
	u_short ip_id;                  // 标示
	u_short ip_off;                 // 偏移量
	u_char  ip_ttl;                 // 生存时间
	u_char  ip_p;                   // 协议
	u_short ip_sum;                 // 首部校验和
	struct  in_addr ip_src, ip_dst;  // 源ip，目的ip
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)    //获得首部长度,通过把版本号比特清零
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP头 */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;               // 源端口
	u_short th_dport;               // 目的端口
	tcp_seq th_seq;                 // 序列号
	tcp_seq th_ack;                 // 确认号
	u_char  th_offx2;               //首部长度和保留未用
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)    //找到首部长度,把保留未用比特清零,再右移4位
	u_char  th_flags;
	u_short th_win;                 // 接收窗口
	u_short th_sum;                 // 互联网检验和
	u_short th_urp;                 // 紧急数据指针
};

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
print_payload(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);


/*
* print data in rows of 16 bytes: offset   hex   ascii
*
* 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
*/
void
print_hex_ascii_line(const u_char *payload, int len, int offset)     //按16进制打印一个字节
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for (i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for (i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

//打印有效数据部分
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for (;;) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

/*
* 获取数据包后的回调函数,打印相关信息
*/
void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)   
{            //第2个参数:数据包头部  第3个参数:数据包

	static int count = 1;                   // 包计数器

	//包头部指针
	const struct sniff_ethernet *ethernet;  //以太网头
	const struct sniff_ip *ip;              //IP头
	const struct sniff_tcp *tcp;            //TCP头
	u_char *payload;                    //有效数据

	int size_ip;              //IP首部长度
	int size_tcp;             //TCP首部长度
	int size_payload;         //有效数据长度

//	printf("\nPacket number %d:\n", count);
	count++;

	//定义以太网头
	ethernet = (struct sniff_ethernet*)(packet);
	//MAC地址
	printf("源MAC地址:");
	for (int j = 0; j < 6; j++){
		char buffer[3];
		int num = ethernet->ether_shost[j];
		_itoa_s(num, buffer, 16);
		if (strlen(buffer) < 2){ printf("0"); }
		if (j < 5){ printf("%s-", buffer); }
		else{ printf("%s", buffer); }
	}
	printf("\n");
	printf("目的MAC地址:");
	for (int j = 0; j < 6; j++){
		char buffer[3];
		int num = ethernet->ether_dhost[j];
		_itoa_s(num, buffer, 16);
		if (strlen(buffer) < 2){ printf("0"); }
		if (j < 5){ printf("%s-", buffer); }
		else{ printf("%s", buffer); }
	}
	printf("\n");
	//找到IP头(以太网头的首地址加偏移量)
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;   //获取ip首部长度
	if (size_ip < 20) {   //要求首部长度>=20字节
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	//打印源和目的IP地址
	printf("源IP地址: %s\n", inet_ntoa(ip->ip_src));
	printf("目的IP地址: %s\n", inet_ntoa(ip->ip_dst));

	//决定协议
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		printf("   Protocol: TCP\n");
		break;
	case IPPROTO_UDP:
		printf("   Protocol: UDP\n");
		return;
	case IPPROTO_ICMP:
		printf("   Protocol: ICMP\n");
		return;
	case IPPROTO_IP:
		printf("   Protocol: IP\n");
		return;
	default:
		printf("   Protocol: unknown\n");
		return;
	}  

	//TCP

	//找到TCP头(初始地址+以太网首部长度+ip首部长度)
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;   //获取TCP首部长度
	if (size_tcp < 20) {      //要求首部长度>=20字节
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	//打印源和目的TCP端口号
	printf("源端口号: %d\n", ntohs(tcp->th_sport));
	printf("目的端口号: %d\n", ntohs(tcp->th_dport));

	//指向有效数据部分(初始地址+以太网头部+IP头部+TCP头部)
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	//计算TCP有效数据部分的长度(IP数据报总长度-IP头部-TCP头部)
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	//打印有效数据部分(可能是字节流)
	if (size_payload > 0) {
		printf("数据(%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}
	else{
		printf("没有携带数据\n", size_payload);
	}

	return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			//设备名
	char errbuf[PCAP_ERRBUF_SIZE];		//错误缓存
	pcap_t *handle;				//数据包捕获描述字

	char filter_exp[] = "dst port 80";		// 过滤表达式(目的端口80)
	struct bpf_program fp;			        //过滤程序
	bpf_u_int32 mask;			            // 子网掩码
	bpf_u_int32 net;			            // 网络号
	struct in_addr addr;                           //描述ip地址
	char* snet=(char *) malloc(sizeof(char)* 16);;                             //点十表示的网络号
	char* smask = (char *)malloc(sizeof(char)* 16);;                            //点十表示的子网掩码
	int num_packets = 4;			        // 准备捕获的包的数量
	pcap_if_t  * alldevs;                   //所有设备
	unsigned char *a_mac=(unsigned char *) malloc(sizeof(unsigned char)* 6);;                  //源MAC地址

	// 在命令行上检查设备名 
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "不能识别的网卡名称\n");
		exit(EXIT_FAILURE);
	}
	else {
		//找到设备名
		
		pcap_if_t  *d;
		int i = 0;
		if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1){
			fprintf(stderr, "Error in pcap_findalldevs_ex:\n", errbuf);
			exit(1);
		}
		for (d = alldevs; d != NULL; d = d->next){
			if (i == 1){
				dev = d->name;
				//获得指定网络设备的网络号和掩码
				if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
					printf("Couldn't get netmask for device\n");
					net = 0;
					mask = 0;
				}
				//打印设备名,网络号,子网掩码
				printf("网卡: %s\n", dev);
				addr.s_addr = net;
				snet = inet_ntoa(addr);
				printf("网络号: %s\n", snet);
				addr.s_addr = mask;
				smask = inet_ntoa(addr);
				printf("子网掩码: %s\n", smask);
			}
			i++;
		}
	}

	
	

	//打开捕获设备
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);    //获得用于捕获网络数据包的数据包捕获描述字
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	//确认是在以太网设备上捕获
	if (pcap_datalink(handle) != DLT_EN10MB) {                   //返回数据链路层类型，例如DLT_EN10MB
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	//编译过滤程序
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {       //将第3个参数指定的字符串编译到过滤程序中
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	//应用前一步获得的过滤程序
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n",
			filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	// 捕获并处理数据包,设置回调函数 
	pcap_loop(handle, num_packets, got_packet, NULL);

	// 清扫 
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\n捕获完成.\n");
	pcap_freealldevs(alldevs);
	getchar();

	return 0;
}    


