#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <linux/string.h>
#define MAX_HEADER_SIZE 200
#define MAX_BODY_SIZE 200


struct data_key {
        u32 pid;
        u32 tid;
        u32 uid;
        char comm[TASK_COMM_LEN];
};

struct data_value {
    char req_header[MAX_HEADER_SIZE];
    char req_body[MAX_BODY_SIZE];
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
    char req_header[MAX_HEADER_SIZE];
    char req_body[MAX_BODY_SIZE];
};

BPF_TABLE_PUBLIC("extern", struct data_key, struct data_value, https_data, 4096);
BPF_PERF_OUTPUT(events_py_https);

int trace_py_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk)
{

    //bpf_trace_printk("3");
    u16 sport = sk->sk_num;
    u16 dport = sk->sk_dport;
    u32 saddr = sk->sk_rcv_saddr;
    u32 daddr = sk->sk_daddr;

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
   // bpf_trace_printk("3");
    bpf_probe_read(&(data.req_header), MAX_HEADER_SIZE, (char *)(value->req_header));
    bpf_probe_read(&(data.req_body), MAX_BODY_SIZE, (char *)(value->req_body));

    //bpf_trace_printk("%s",data.req_body);

    events_py_https.perf_submit(ctx, &data, sizeof(struct https_data));

    https_data.delete(&key);

    return 0;

}


