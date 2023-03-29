#include <linux/if_ether.h>
#include <linux/in.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#define IP_TCP 	6
#define ETH_HLEN 14

struct data_key {
     u32 src_ip;
     u32 dst_ip;
     unsigned short src_port;
     unsigned short dst_port;
 };

struct data_value {
     u32 pid;
     u32 uid;
     u32 gid;
     char comm[64];
 };

struct Leaf {
	int timestamp;            //timestamp in ns
};


BPF_TABLE("extern", struct data_key, struct data_value, proc_http_datas, 20480);
// Table for transferring data to the user space:

BPF_HASH(sessions, struct data_key, struct Leaf, 1024);

BPF_PERF_OUTPUT(events_http);

int http_matching(struct __sk_buff *skb){
    u8 *cursor = 0;
    u32 tcp_header_length = 0;
    u32 ip_header_length = 0;
    u32 payload_offset = 0;
    u32 payload_length = 0;


    struct ethernet_t *ethernet = cursor_advance(cursor,sizeof(*ethernet));

    if (!(ethernet->type == 0x0800)) {
		return 0;
	}
    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

    if (ip->nextp != IP_TCP) {
		return 0;
	}

    if (!tcp->flag_psh) {
        return 0;
    }

    struct data_key key = {};
    struct data_key session_key = {};
    struct Leaf zero = {0};

 	ip_header_length = ip->hlen << 2;
	tcp_header_length = tcp->offset << 2; //SHL 2 -> *4 multiply

	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
	payload_length = ip->tlen - ip_header_length - tcp_header_length;

    key.src_ip = ip->src;
    key.dst_ip = ip->dst;
    key.src_port = tcp->src_port;
    key.dst_port = tcp->dst_port;


    session_key.src_ip = ip->src;
    session_key.dst_ip = ip->dst;
    session_key.src_port = tcp->src_port;
    session_key.dst_port = tcp->dst_port;


    struct data_value *value;
    value = proc_http_datas.lookup(&key);

    if (!value){
        return 0;
    }

	unsigned long payload[7];
	int i = 0;
	for (i = 0; i < 7; i++) {
		payload[i] = load_byte(skb, payload_offset + i);
	}

    if((payload[0]=='H') && (payload[1]=='T') && (payload[2]=='T') && (payload[3]=='P')){
        goto SESSION_MATCH;
    }

    if((payload[0]=='G') && (payload[1]=='E') && (payload[2]=='T')){
        goto SESSION_MATCH;
    }

    if((payload[0]=='P') && (payload[1]=='O') && (payload[2]=='S') && (payload[3]=='T')){
        goto SESSION_MATCH;
    }

    if((payload[0]=='P') && (payload[1]=='U') && (payload[2]=='T')){
        goto SESSION_MATCH;
    }

    if((payload[0]=='H') && (payload[1]=='E') && (payload[2]=='A') && (payload[3]=='D')){
        goto SESSION_MATCH;
    }

    if((payload[0]=='D') && (payload[1]=='E') && (payload[2]=='L') && (payload[3]=='E') && (payload[4]=='T') && (payload[5]=='E')){
         goto SESSION_MATCH;
    }

	struct Leaf * lookup_leaf = sessions.lookup(&session_key);
	if(lookup_leaf) {
		//send packet to userspace
		goto KEEP;
	}
	goto DROP;

	SESSION_MATCH:
	sessions.lookup_or_try_init(&session_key,&zero);

	//send packet to userspace returning -1
	KEEP:
    events_http.perf_submit_skb(skb,skb->len,value,sizeof(struct data_value));
    proc_http_datas.delete(&key);
    return 0;

	//drop the packet returning 0
	DROP:
	return 0;

}
