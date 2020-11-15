#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <bcc/helpers.h>


struct Packet {
	u64 timestamp;
	u32 src_ip;               // source ip
	u32 dst_ip;               // destination ip
	unsigned short src_port;  // source port
	unsigned short dst_port;  // destination port
	unsigned int ethertype;   // EtherType
	unsigned char protocol;  // destination port
	unsigned char tcp_Flags; // TCP Flags
	unsigned short len;
	unsigned short tcp_payload_len;
	unsigned short udp_len;
	unsigned char ttl;
};

//BPF_TABLE(map_type, key_type, leaf_type, table_name, num_entry)
//map <Key, Leaf>
//tracing sessions having same Key(dst_ip, src_ip, dst_port,src_port)
BPF_QUEUE(local_ip, u32, 1);
BPF_QUEUE(queue, struct Packet, 1024);
BPF_HASH(sospicious_IPs, u32, char);

/*eBPF program.
  Filter IP and TCP packets, having payload not empty
  and containing "HTTP", "GET", "POST"  as first bytes of payload.
  AND ALL the other packets having same (src_ip,dst_ip,src_port,dst_port)
  this means belonging to the same "session"
  this additional check avoids url truncation, if url is too long
  userspace script, if necessary, reassembles urls split in 2 or more packets.
  if the program is loaded as PROG_TYPE_SOCKET_FILTER
  and attached to a socket
  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/
int ebpf_program(struct __sk_buff *skb) {
	struct Packet packet;
	struct ethernet_t *ethernet = NULL;
	struct ip_t *ip = NULL;
	struct tcp_t *tcp = NULL;
	struct udp_t *udp = NULL;

	u8 *cursor = 0;
	u32 localIP;
	local_ip.pop(&localIP);

	ethernet = cursor_advance(cursor, sizeof(*ethernet));
	
	__builtin_memset(&packet, 0, sizeof(packet));

	packet.ethertype = ethernet->type;

	if (packet.ethertype == 2048){
		ip = cursor_advance(cursor, sizeof(*ip));
		packet.timestamp = bpf_ktime_get_ns();
		packet.dst_ip = ip->dst;
		packet.src_ip = ip->src;
		packet.protocol = ip->nextp;
		packet.len = ip->tlen+sizeof(*ethernet);
		packet.ttl = ip->ttl;
	}
	else
		return 0;

	if (packet.protocol == 6){
		tcp = cursor_advance(cursor, sizeof(*tcp));
		packet.src_port = tcp->src_port;
		packet.dst_port = tcp->dst_port;
		packet.tcp_Flags = 128*tcp->flag_cwr+64*tcp->flag_ece+32*tcp->flag_urg+16*tcp->flag_ack+8*tcp->flag_psh+4*tcp->flag_rst+2*tcp->flag_syn+1*tcp->flag_fin;
		packet.tcp_payload_len = ip->tlen-(ip->hlen+tcp->offset*4);
		packet.udp_len = 0;
		queue.push(&packet, BPF_EXIST);
	}
	else if (packet.protocol == 17){
		udp = cursor_advance(cursor, sizeof(*udp));
		packet.src_port = udp->sport;
		packet.dst_port = udp->dport;
		packet.tcp_Flags = 0;
		packet.tcp_payload_len = 0;
		packet.udp_len = udp->length;
		queue.push(&packet, BPF_EXIST);
	} 
	else
		return -1;

	if (packet.dst_ip != localIP && sospicious_IPs.lookup(&packet.dst_ip) != NULL)
		return -1;
	else if (packet.src_ip != localIP && sospicious_IPs.lookup(&packet.src_ip) != NULL)
		return -1;
	
	return 0;
}