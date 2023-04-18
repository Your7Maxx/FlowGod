#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <linux/string.h>

#define MAX_BUFFER_SIZE 400

struct data_key {
    u32 pid;
    u32 tid;
    u32 uid;
    char comm[TASK_COMM_LEN];
};

struct data_value {
    s32 len;
    char buf[MAX_BUFFER_SIZE];
};

struct https_data {
    u32 pid;
    u32 uid;
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    s32 len;
    char buf[MAX_BUFFER_SIZE];
};

struct session_key {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
 };


struct Leaf {
	int timestamp;            //timestamp in ns
};



BPF_TABLE_PUBLIC("extern", struct data_key, struct data_value, https_data, 4096);
BPF_HASH(sessions, struct session_key, struct Leaf, 1024);

BPF_PERF_OUTPUT(events_go_https);


int trace_go_tcp_sendmsg(struct pt_regs *ctx, struct sock *sk)
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

    struct session_key session_key = {};
    session_key.saddr = htonl(saddr);
    session_key.daddr = htonl(daddr);
    session_key.sport = sport;
    session_key.dport = htons(dport);


    struct https_data data = {};
    data.saddr = htonl(saddr);
    data.daddr = htonl(daddr);
    data.sport = sport;
    data.dport = htons(dport);
    data.pid = pid;
    data.uid = uid;

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

    data.len = value->len;
    bpf_probe_read(&(data.buf), MAX_BUFFER_SIZE, (char *)(value->buf));

    struct Leaf zero = {0};

    sessions.lookup_or_try_init(&session_key,&zero);
    struct Leaf * lookup_leaf = sessions.lookup(&session_key);
	if(lookup_leaf) {

	    events_go_https.perf_submit(ctx, &data, sizeof(struct https_data));
	    https_data.delete(&key);
        return 0;
    }


    https_data.delete(&key);
    return 0;

}


