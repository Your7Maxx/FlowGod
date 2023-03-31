#include <net/inet_sock.h>

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
     u32 pid;
     u32 uid;
     u32 gid;
     char comm[64];
 };

BPF_TABLE_PUBLIC("hash", struct data_key, struct data_value, proc_udp_datas, 20480);

int trace_udp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    u16 sport = sk->sk_num;
    u16 dport = sk->sk_dport;

    u32 saddr = sk->sk_rcv_saddr;
    u32 daddr = sk->sk_daddr;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 uid_gid = bpf_get_current_uid_gid();
        // Forming the key structure.
        // These strange transformations will be explained below.
    struct data_key key = {.proto = 17};
    key.saddr = htonl(saddr);
    key.daddr = htonl(daddr);
    key.sport = sport;
    key.dport = htons(dport);
        // Forming a structure with the process properties:
    struct data_value value = {};
    value.pid = pid_tgid >> 32;
    value.uid = (u32)uid_gid;
    value.gid = uid_gid >> 32;
    bpf_get_current_comm(value.comm, 64);
        //Writing the value into the eBPF table:
    proc_udp_datas.update(&key, &value);

    return 0;
}
