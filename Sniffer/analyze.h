#pragma once
#include "Protocol.h"
#include "afxcmn.h"
#include "afxwin.h"
#include <malloc.h> 

//Á´Â·²ã
int analyze_frame(const u_char * pkt, struct pktdata * data);

//ÍøÂç²ã
int analyze_ip(const u_char* pkt, struct pktdata *data);
int analyze_ip6(const u_char* pkt, struct pktdata *data);
int analyze_arp(const u_char* pkt, struct pktdata *data);

//´«Êä²ã
int analyze_icmp(const u_char* pkt, struct pktdata *data);
int analyze_icmp6(const u_char* pkt, struct pktdata *data);
int analyze_tcp(const u_char* pkt, struct pktdata *data);
int analyze_udp(const u_char* pkt, struct pktdata *dtat);

//Ó¦ÓÃ²ã
int analyze_http(const u_char* pkt, struct pktdata *data);

void print_packet_hex(const u_char* pkt, int size_pkt, CString *buf);