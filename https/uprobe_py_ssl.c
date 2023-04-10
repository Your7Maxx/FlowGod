#include <linux/ptrace.h>
#include <linux/sched.h>
#define MAX_BUFFER_SIZE 400

struct data_key {
        u32 pid;
        u32 tid;
        u32 uid;
        char comm[TASK_COMM_LEN];
};

struct data_value {
    char buf[MAX_BUFFER_SIZE];
};


BPF_TABLE_PUBLIC("hash", struct data_key, struct data_value, https_data, 4096);


int probe_SSL_rw_ex_enter(struct pt_regs *ctx,int *s, const void *buf) {

        struct data_key data_k = {};
        struct data_value data_v = {};

        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        data_k.pid = pid;
        data_k.tid = tid;
        data_k.uid = bpf_get_current_uid_gid();
        bpf_get_current_comm(&data_k.comm, sizeof(data_k.comm));

        bpf_probe_read_user(&data_v.buf, sizeof(data_v.buf), buf);

        https_data.update(&data_k, &data_v);

        return 0;

}