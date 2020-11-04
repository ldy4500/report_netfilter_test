#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>

int allow = 0;
char host[40];

typedef struct libnet_ip_hdr{
	u_int8_t length:4, version:4;
	u_int8_t typeOfSource;
	u_int16_t totalLength;
	u_int16_t indentification;
	u_int16_t flagAndFragmentOffset;
	u_int8_t TTL;
	u_int8_t protocol;
	u_int16_t headerChecksum;
	u_int8_t srcAddr[4];
	u_int8_t dstArrd[4];
}IP_Header;

typedef struct libnet_tcp_hdr{
	u_int16_t srcPort;
	u_int16_t dstPort;
	u_int32_t seqNumber;
	u_int32_t ackNumber;
	u_int8_t off:4, length:4;
	u_int8_t tcpFlags;
	u_int16_t window;
	u_int16_t checksum;
	u_int16_t urgentPointer;
}TCP_Header;

typedef struct http_request{
	u_int8_t commonHeader[16];
	char Host[6];
	char host[40];
}HTTP_Header;

int chk_IP_version(const u_char* packet){
	IP_Header *Header;
	Header = (IP_Header*)packet;
	if(Header->version == 4){
		printf("iplength : %d\n",Header->length);
		return Header->length;
	}
	else
		return -1;
}

int ret_TCP_length(const u_char* packet){
	TCP_Header *Header;
	Header = (TCP_Header*)packet;
	printf("tcplength: %d\n", Header->length);
	return Header->length;
}

void chk_Host(const u_char* packet){
	HTTP_Header *Header;
	Header = (HTTP_Header*)packet;
	if(strncmp(Header->host,host,(int)strlen(host))==0){
		allow = 1;
	}
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		allow = 0;
		printf("payload_len=%d ", ret);
		int ip_length = chk_IP_version(data);
		if(ip_length != -1){
			ip_length = ip_length*4;
			data+=ip_length;
			int tcp_length = ret_TCP_length(data);
			tcp_length = tcp_length*4;
			data += tcp_length;
			chk_Host(data);
		}

	fputc('\n', stdout);

	return id;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if(allow == 1){
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	}
	else return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	if(argc != 2){
		printf("incorrect input\n");
		exit(1);
	}
	strcpy(host,argv[1]);
	printf("%s\n",host);
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
			printf("pkt received\n");
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

