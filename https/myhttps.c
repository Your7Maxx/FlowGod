#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <linux/string.h>
#define MAX_BUF_SIZE 415

struct probe_SSL_data_t {
        u64 timestamp_ns;
        u64 delta_ns;
        u32 pid;
        u32 tid;
        u32 uid;
        u32 len;
        int buf_filled;
        int rw;
        char comm[TASK_COMM_LEN];
        u8 buf[MAX_BUF_SIZE];
};

struct data_key {
        u32 pid;
        u32 tid;
        u32 uid;
        char comm[TASK_COMM_LEN];
};

struct data_value {
        u32 len;
        int buf_filled;
        u8 buf[MAX_BUF_SIZE];
};

struct https_data {
    u32 pid;
    //u32 tid;
    u32 uid;
    //char comm[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u32 len;
    int buf_filled;
    u8 buf[MAX_BUF_SIZE];
};


BPF_TABLE_PUBLIC("extern", struct data_key, struct data_value, https_data, 4096);

BPF_PERF_OUTPUT(events_https);


int trace_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk)
{

    u16 sport = sk->sk_num;
    u16 dport = sk->sk_dport;
    u32 saddr = sk->sk_rcv_saddr;
    u32 daddr = sk->sk_daddr;
    int ret;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u32 uid = bpf_get_current_uid_gid();

    struct https_data data = {};
    data.saddr = htonl(saddr);
    data.daddr = htonl(daddr);
    data.sport = sport;
    data.dport = htons(dport);
    data.pid = pid;
   // data.tid = tid;
    data.uid = uid;
   // bpf_get_current_comm(&data.comm, sizeof(data.comm));

    struct data_key key = {};
    key.pid = pid;
    key.tid = tid;
    key.uid = uid;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    struct data_value *value;
    value = https_data.lookup(&key);

    if (!value){
        return 0;
    }

    int len = PT_REGS_RC(ctx);
    data.len = value->len;
    data.buf_filled = value->buf_filled;
    u32 buf_copy_size = min((size_t)MAX_BUF_SIZE, (size_t)len);
    ret = bpf_probe_read(&(data.buf), buf_copy_size, (char *)(value->buf));

    events_https.perf_submit(ctx, &data, sizeof(struct https_data));

    https_data.delete(&key);

    return 0;

}


