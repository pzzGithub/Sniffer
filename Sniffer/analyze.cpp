#include"stdafx.h"
#include "analyze.h"

int analyze_frame(const u_char * pkt, pktdata * data)
{
	int i;
	struct ethhdr *ethh = (struct ethhdr*)pkt;
	data->ethh = (struct ethhdr*)malloc(sizeof(struct ethhdr));
	if (NULL == data->ethh)
		return -1;

	for (i = 0; i < 6; i++)
	{
		data->ethh->dest[i] = ethh->dest[i];
		data->ethh->src[i] = ethh->src[i];
	}

	data->ethh->type = ntohs(ethh->type);

	if(data->ethh->type== 0x0806)
		return analyze_arp((u_char*)pkt + 14, data);
	else if(data->ethh->type == 0x0800)
		return analyze_ip((u_char*)pkt + 14, data);
	return 1;
}

int analyze_ip(const u_char * pkt, pktdata * data)
{
	int i;
	struct iphdr *iph = (struct iphdr*)pkt;
	data->iph = (struct iphdr*)malloc(sizeof(struct iphdr));

	if (data->iph==NULL)
		return -1;
	data->iph->check = iph->check;

	data->iph->saddr = iph->saddr;
	data->iph->daddr = iph->daddr;

	data->iph->frag_off = iph->frag_off;
	data->iph->id = iph->id;
	data->iph->proto = iph->proto;
	data->iph->tlen = ntohs(iph->tlen);
	data->iph->tos = iph->tos;
	data->iph->ttl = iph->ttl;
	data->iph->ihl = iph->ihl;
	data->iph->version = iph->version;
	//data->iph->ver_ihl= iph->ver_ihl;
	data->iph->op_pad = iph->op_pad;

	int iplen = iph->ihl * 4;//ipͷ����
	if (iph->proto == PROTO_ICMP)
		return analyze_icmp((u_char*)iph + iplen, data);
	else if (iph->proto == PROTO_TCP)
		return analyze_tcp((u_char*)iph + iplen, data);
	else if (iph->proto == PROTO_UDP)
		return analyze_udp((u_char*)iph + iplen, data);
	else
		return -1;
	return 1;
}

int analyze_arp(const u_char * pkt, pktdata * data)
{
	int i;
	struct arphdr *arph = (struct arphdr*)pkt;
	data->arph = (struct arphdr*)malloc(sizeof(struct arphdr));

	if (data->arph == NULL)
		return -1;

	//����IP��MAC
	for (i = 0; i < 6; i++)
	{
		if (i < 4)
		{
			data->arph->ar_destip[i] = arph->ar_destip[i];
			data->arph->ar_srcip[i] = arph->ar_srcip[i];
		}
		data->arph->ar_destmac[i] = arph->ar_destmac[i];
		data->arph->ar_srcmac[i] = arph->ar_srcmac[i];
	}

	data->arph->ar_hln = arph->ar_hln;
	data->arph->ar_hrd = ntohs(arph->ar_hrd);
	data->arph->ar_op = ntohs(arph->ar_op);
	data->arph->ar_pln = arph->ar_pln;
	data->arph->ar_pro = ntohs(arph->ar_pro);

	strcpy(data->pktType, "ARP");

	return 1;
}

int analyze_icmp(const u_char * pkt, pktdata * data)
{
	struct icmphdr* icmph = (struct icmphdr*)pkt;
	data->icmph = (struct icmphdr*)malloc(sizeof(struct icmphdr));

	if (NULL == data->icmph)
		return -1;

	data->icmph->chksum = icmph->chksum;
	data->icmph->code = icmph->code;
	data->icmph->seq = icmph->seq;
	data->icmph->type = icmph->type;
	strcpy(data->pktType, "ICMP");
	return 1;
}

int analyze_tcp(const u_char * pkt, pktdata * data)
{
	struct tcphdr *tcph = (struct tcphdr*)pkt;
	data->tcph = (struct tcphdr*)malloc(sizeof(struct tcphdr));
	if (NULL == data->tcph)
		return -1;

	data->tcph->ack_seq = tcph->ack_seq;
	data->tcph->check = tcph->check;

	data->tcph->doff = tcph->doff;
	data->tcph->res1 = tcph->res1;
	data->tcph->cwr = tcph->cwr;
	data->tcph->ece = tcph->ece;
	data->tcph->urg = tcph->urg;
	data->tcph->ack = tcph->ack;
	data->tcph->psh = tcph->psh;
	data->tcph->rst = tcph->rst;
	data->tcph->syn = tcph->syn;
	data->tcph->fin = tcph->fin;
	//data->tcph->doff_flag = tcph->doff_flag;

	data->tcph->dport = ntohs(tcph->dport);
	data->tcph->seq = tcph->seq;
	data->tcph->sport = ntohs(tcph->sport);
	data->tcph->urg_ptr = tcph->urg_ptr;
	data->tcph->window = tcph->window;
	data->tcph->opt = tcph->opt;

	if (ntohs(tcph->dport) == 80 || ntohs(tcph->sport) == 80)
		strcpy(data->pktType, "HTTP");
	else 
		strcpy(data->pktType, "TCP");
	return 1;
}

int analyze_udp(const u_char * pkt, pktdata * data)
{
	struct udphdr* udph = (struct udphdr*)pkt;
	data->udph = (struct udphdr*)malloc(sizeof(struct udphdr));
	if (NULL == data->udph)
		return -1;

	data->udph->check = udph->check;
	data->udph->dport = ntohs(udph->dport);
	data->udph->len = ntohs(udph->len);
	data->udph->sport = ntohs(udph->sport);

	strcpy(data->pktType, "UDP");
	return 1;
}

int analyze_http(const u_char * pkt, pktdata * data)
{
	return 0;
}

void print_packet_hex(const u_char * pkt, int size_pkt, CString * buf)
{
	int i = 0, j = 0, rowcount;
	u_char ch;

	char tempbuf[256];
	memset(tempbuf, 0, 256);

	for (i = 0; i < size_pkt; i += 16)
	{
		buf->AppendFormat(_T("%04x:  "), (u_int)i);
		rowcount = (size_pkt - i) > 16 ? 16 : (size_pkt - i);

		for (j = 0; j < rowcount; j++)
			buf->AppendFormat(_T("%02x  "), (u_int)pkt[i + j]);

		//����16���ÿո���
		if (rowcount < 16)
			for (j = rowcount; j < 16; j++)
				buf->AppendFormat(_T("    "));


		for (j = 0; j < rowcount; j++)
		{
			ch = pkt[i + j];
			ch = isprint(ch) ? ch : '.';
			buf->AppendFormat(_T("%c"), ch);
		}

		buf->Append(_T("\r\n"));

		if (rowcount < 16)
			return;
	}
}