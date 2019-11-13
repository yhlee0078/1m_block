#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>            /* for NF_ACCEPT */

#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <iostream>
#include <unordered_set>

using namespace std;
unordered_set<string> block_list;

struct ip_hdr
{
		u_char hlv;
		u_char tos;
		u_short pkt_len;
		u_short frag_id;
		u_short flags;
		u_char ttl;
		u_char protocol;
		u_short checksum;
		struct in_addr ip_src,ip_dst;
};

struct tcp_hdr 
{
		u_short src_port;
		u_short dst_port;
		u_int seq_num;
		u_int ack_num;
		u_char off_len;
		u_char flags;
		u_short win_size;
		u_short checksum;
		u_short urp;
};

//const char* methods[]{ "GET", "POST", "DELETE" };


char * target_host = NULL;
int target_host_len = 0;
int block_ed = 0;

/*
void dump(unsigned char* buf, int size) {
int i;
for (i = 0; i < size; i++) {
if (i % 16 == 0)
printf("\n");
printf("%02x ", buf[i]);
}
}


static u_int32_t print_pkt(struct nfq_data *tb) {
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark, ifi;
	int ret;
	unsigned char *data;

	block_ed = 0;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) id = ntohl(ph->packet_id);

	ret = nfq_get_payload(tb, &data);

	ipv4_hdr* ipv4_ptr = (ipv4_hdr*)data;
	int ipv4_len = ipv4_ptr->header_len * 4;
	tcp_hdr* tcp_ptr = (tcp_hdr*)((char*)ipv4_ptr + ipv4_len);
	int tcp_len = (tcp_ptr->flags) * 4;

	// printf("length : %d\n", tcp_len);

	int header_len = ((*((char*)tcp_ptr + 12) & 0xff) >> 4) * 4;
	char* data_ptr = ((char*)tcp_ptr + header_len);

	for (int i = 0; i < 3; ++i)
	{
		int method_len = strlen(methods[i]);

		if (strncmp(data_ptr, methods[i], method_len) == 0)
		{
			int url_len = strlen(target_host);

			char* p = strstr(data_ptr, "Host");
			if (p == NULL) continue;

			if (strncmp(p + 6, target_host, target_host_len) == 0)
			{
				printf("BLOCKED!\n");
				block_ed = 1;
				return id;
			}
		}
	}

	return id;
}
*/

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{

	uint32_t id, pay_len, pkt_len, tcp_len;
	uint16_t port;

	unsigned char * pkt, *http;
	struct ip_hdr *ip_ptr;
	struct tcp_hdr *tcp_ptr;
	char victim[100];
	char * token = "Host:";

	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph)
	{
		id = ntohl(ph->packet_id);
	}
	pay_len = nfq_get_payload(nfa, &pkt);
	ip_ptr = (struct ip_hdr *)pkt;

	pkt_len = ((ip_ptr->hlv) & 0x0f)*4;
	
	tcp_ptr = (struct tcp_hdr *)(pkt + pkt_len);
	tcp_len = (((tcp_ptr)->off_len & 0xf0) >> 4)*4;
	port = ntohs(tcp_ptr->dst_port);

	int ress = 0;
	if(port == 80 || port == 443)
	{
		http = (pkt+pkt_len+tcp_len);

		if( !memcmp(http, "GET", 3) || !memcmp(http, "POST", 4) || !memcmp(http, "HEAD", 4) || !memcmp(http, "PUT", 3) || !memcmp(http, "DELETE", 6) || !memcmp(http, "OPTIONS", 7))
		{
			char * start, *end;
			start = strstr((char*)http, (char*)token)+6;
			end = strstr(start, "\r\n");
			snprintf(victim, end-start+1, "%s", start);
			string tmp_host = victim;
			size_t www;
			if((www=tmp_host.find("www.")) != string::npos)
			{
					tmp_host = tmp_host.substr(www+1, string::npos);
			}	
			printf("Host is : %s\n", tmp_host);
			//cout<<"Host"<<tmp_host<<endl;
			if(block_list.find(tmp_host) != block_list.end())
			{
				printf("Block success : %s\n", http);
			 	int ret = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
				if (ret<0)
				{
					fprintf(stderr, "failed Block\n");
					exit(-1);
				}
				return ret;
			}
		}
	}
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	if (argc < 2)
	{
		fprintf(stderr, "1m_block <file>\n");
		exit(-1);
	}

	ifstream in(argv[1]);
	if(in.is_open())
	{
		string line;
		while(in)
		{
			getline(in, line);
			block_list.insert(line.substr(line.find(",")+1, string::npos));
		}
	}
	else
	{
		fprintf(stderr, "file open error");
		exit(-1);
	}
	system("iptables -F");
	system("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
	system("iptables -A INPUT -j NFQUEUE --queue-num 0");
	
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}