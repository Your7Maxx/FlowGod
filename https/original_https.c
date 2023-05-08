#include <linux/sched.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <linux/string.h>

#define MAX_BUF_SIZE 4000


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

struct session_key {
     u32 src_ip;
     u32 dst_ip;
     unsigned short src_port;
     unsigned short dst_port;
 };

struct Leaf {
	int timestamp;            //timestamp in ns
};


BPF_TABLE_PUBLIC("extern", struct data_key, struct data_value, https_data, 4096);
BPF_HASH(sessions, struct session_key, struct Leaf, 1024);

/*bypass 512 limit*/
BPF_HASH(bpf_context_1, u64, struct data_value, 2048);
BPF_ARRAY(bpf_context_gen_1, struct data_value, 1);

BPF_HASH(bpf_context_2, u64, struct https_data, 2048);
BPF_ARRAY(bpf_context_gen_2, struct https_data, 1);

static struct data_value *make_event_1(){
        int zero = 0;
        struct data_value *bpf_ctx = bpf_context_gen_1.lookup(&zero);
        if (!bpf_ctx) return 0;
        u64 id = bpf_get_current_pid_tgid();
        bpf_context_1.update(&id, bpf_ctx);
        return bpf_context_1.lookup(&id);
}

static struct https_data *make_event_2(){
        int zero = 0;
        struct https_data *bpf_ctx = bpf_context_gen_2.lookup(&zero);
        if (!bpf_ctx) return 0;
        u64 id = bpf_get_current_pid_tgid();
        bpf_context_2.update(&id, bpf_ctx);
        return bpf_context_2.lookup(&id);
}

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

    struct https_data *data = make_event_2();
    if(!data) return 0;

    data->saddr = htonl(saddr);
    data->daddr = htonl(daddr);
    data->sport = sport;
    data->dport = htons(dport);
    data->pid = pid;
   // data.tid = tid;
    data->uid = uid;
   // bpf_get_current_comm(&data.comm, sizeof(data.comm));

    struct data_key key = {};
    key.pid = pid;
    key.tid = tid;
    key.uid = uid;
    bpf_get_current_comm(&key.comm, sizeof(key.comm));

    struct session_key session_key = {};
    session_key.src_ip = htonl(saddr);
    session_key.dst_ip = htonl(daddr);
    session_key.src_port = sport;
    session_key.dst_port = htons(dport);



    struct data_value *value =  make_event_1();
    if(!value) return 0;

    value = https_data.lookup(&key);
    if(!value) return 0;

    int len = PT_REGS_RC(ctx);
    data->len = value->len;
    data->buf_filled = value->buf_filled;
    u32 buf_copy_size = min((size_t)MAX_BUF_SIZE, (size_t)len);
    ret = bpf_probe_read(&(data->buf), buf_copy_size, (char *)(value->buf));


    struct Leaf zero = {0};
    sessions.lookup_or_try_init(&session_key,&zero);
    struct Leaf * lookup_leaf = sessions.lookup(&session_key);
	if(lookup_leaf) {
		//send packet to userspace
	    events_https.perf_submit(ctx, data, sizeof(struct https_data));
	    https_data.delete(&key);
        return 0;
    }

    https_data.delete(&key);
    return 0;
}



