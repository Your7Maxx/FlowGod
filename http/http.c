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



BPF_TABLE("extern", struct data_key, struct data_value, proc_http_datas, 20480);
// Table for transferring data to the user space:
BPF_PERF_OUTPUT(events_http);

int http_matching(struct __sk_buff *skb){
    u8 *cursor = 0;
    u32 tcp_header_length = 0;
    u32 ip_header_length = 0;
    u32 payload_offset = 0;
    u32 payload_length = 0;

    struct ethernet_t *ethernet = cursor_advance(cursor,sizeof(*ethernet));
    if(ethernet->type == 0x0800){   //type保存了二层协议类型，ETH_P_IP、ETH_P_ARP，ETH_P_ALL
        struct ip_t *ip = cursor_advance(cursor,sizeof(*ip));
        if(ip->nextp == IP_TCP){

            struct tcp_t *tcp = cursor_advance(cursor,sizeof(*tcp));

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
            value = proc_http_datas.lookup(&key);

            if (!value){
                return 0;
            }


            ip_header_length = ip->hlen << 2;
            tcp_header_length = tcp->offset << 2;
            payload_offset = ETH_HLEN + ip_header_length + tcp_header_length;
            payload_length = ip->tlen - ip_header_length - tcp_header_length;

            if(payload_length < 7){
                return 0;
            }

            unsigned long payload[7];
            int i = 0;
            for(i = 0; i<7; i++){
                payload[i] = load_byte(skb, payload_offset + i);
            }
            if((payload[0]=='H') && (payload[1]=='T') && (payload[2]=='T') && (payload[3]=='P')){
                value->nic = skb->ifindex;
                events_http.perf_submit_skb(skb,skb->len,value,sizeof(struct data_value));
                return 0;  // -1 ：复制数据报 0：不复制
            }
            if((payload[0]=='G') && (payload[1]=='E') && (payload[2]=='T')){
                value->nic = skb->ifindex;
                events_http.perf_submit_skb(skb,skb->len,value,sizeof(struct data_value));
                return 0;
            }
            if((payload[0]=='P') && (payload[1]=='O') && (payload[2]=='S') && (payload[3]=='T')){
                value->nic = skb->ifindex;
                events_http.perf_submit_skb(skb,skb->len,value,sizeof(struct data_value));
                return 0;
            }
            if((payload[0]=='P') && (payload[1]=='U') && (payload[2]=='T')){
                value->nic = skb->ifindex;
                events_http.perf_submit_skb(skb,skb->len,value,sizeof(struct data_value));
                return 0;
            }
            if((payload[0]=='H') && (payload[1]=='E') && (payload[2]=='A') && (payload[3]=='D')){
                value->nic = skb->ifindex;
                events_http.perf_submit_skb(skb,skb->len,value,sizeof(struct data_value));
                return 0;
            }
            if((payload[0]=='D') && (payload[1]=='E') && (payload[2]=='L') && (payload[3]=='E') && (payload[4]=='T') && (payload[5]=='E')){
                value->nic = skb->ifindex;
                events_http.perf_submit_skb(skb,skb->len,value,sizeof(struct data_value));
                return 0;
            }
        }

   return 0;
}
    return 0;
}
