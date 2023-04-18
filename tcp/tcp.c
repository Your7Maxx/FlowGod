#include <linux/if_ether.h>
#include <linux/in.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>
#include <net/sock.h>

#define IP_TCP 	6
#define ETH_HLEN 14

struct data_key {
     u8 proto;
     u32 saddr;
     u32 daddr;
     u16 sport;
     u16 dport;
 };

struct data_value {
     u32 nic;
     u32 pid;
     u32 uid;
     u32 gid;
     char comm[64];
 };

BPF_TABLE("extern", struct data_key, struct data_value, proc_datas, 20480);

BPF_PERF_OUTPUT(events_tcp);

 int tcp_matching(struct __sk_buff *skb){
    u8 *cursor = 0;
    struct ethernet_t *ethernet = cursor_advance(cursor,sizeof(*ethernet));
    if(ethernet->type == 0x0800){   //type保存了二层协议类型，ETH_P_IP、ETH_P_ARP，ETH_P_ALL
        struct ip_t *ip = cursor_advance(cursor,sizeof(*ip));
        if(ip->nextp == IP_TCP){ //IP_TCP(0x06)、IPPROTO_UDP
            struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

            if (!tcp->flag_psh) { //过滤掉不携带数据的包
                return 0;
            }
            struct data_key key = {};

            key.proto = 6;
            key.saddr = ip->src;
            key.daddr = ip->dst;
            key.sport = tcp->src_port;
            key.dport = tcp->dst_port;

            struct data_value *value;
            value = proc_datas.lookup(&key);

            if (!value){
                return 0;
            }

            value->nic = skb->ifindex;
            events_tcp.perf_submit_skb(skb,skb->len,value,sizeof(struct data_value));
            return 0;
        }
    }
    return 0;
}



