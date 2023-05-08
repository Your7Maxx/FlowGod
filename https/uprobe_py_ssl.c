#include <linux/ptrace.h>
#include <linux/sched.h>

#define MAX_BUFFER_SIZE 4000

struct data_key {
        u32 pid;
        u32 tid;
        u32 uid;
        char comm[TASK_COMM_LEN];
};

struct data_value {
    char buf[MAX_BUFFER_SIZE];
};

BPF_HASH(bpf_context_1, u64, struct data_value, 2048);
BPF_ARRAY(bpf_context_gen_1, struct data_value, 1);


BPF_TABLE_PUBLIC("hash", struct data_key, struct data_value, https_data, 4096);

static struct data_value *make_event_1(){
        int zero = 0;
        struct data_value *bpf_ctx = bpf_context_gen_1.lookup(&zero);
        if (!bpf_ctx) return 0;
        u64 id = bpf_get_current_pid_tgid();
        bpf_context_1.update(&id, bpf_ctx);
        return bpf_context_1.lookup(&id);
}


int probe_SSL_rw_ex_enter(struct pt_regs *ctx,int *s, const void *buf) {

        struct data_key data_k = {};
        struct data_value *data_v = make_event_1();
        if(!data_v) return 0;

        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        data_k.pid = pid;
        data_k.tid = tid;
        data_k.uid = bpf_get_current_uid_gid();
        bpf_get_current_comm(&data_k.comm, sizeof(data_k.comm));

        bpf_probe_read_user(&data_v->buf, sizeof(data_v->buf), buf);

        https_data.update(&data_k, data_v);

        return 0;

}
