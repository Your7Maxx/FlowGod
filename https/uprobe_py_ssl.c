#include <linux/ptrace.h>
#include <linux/sched.h>
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


BPF_TABLE_PUBLIC("hash", struct data_key, struct data_value, https_data, 4096);
BPF_HASH(ssl_data_key, int, struct data_key);
BPF_HASH(ssl_data_value, int, struct data_value);
BPF_HASH(flag_map, int, int);

//BPF_PERF_OUTPUT(events);

int probe_SSL_rw_ex_enter(struct pt_regs *ctx,int *s, const void *buf) {

    int ssl_addr = (int)s;
    int * flag;
    flag = flag_map.lookup(&ssl_addr);

    if(!flag){
       // bpf_trace_printk("1");
        int f = 1; //第一次读SSL ----> header部分
        struct data_key data_k = {};
        struct data_value data_v = {};

        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        u32 tid = (u32)pid_tgid;

        data_k.pid = pid;
        data_k.tid = tid;
        data_k.uid = bpf_get_current_uid_gid();
        bpf_get_current_comm(&data_k.comm, sizeof(data_k.comm));


        bpf_probe_read_user(&data_v.req_header, sizeof(data_v.req_header), buf);

        ssl_data_key.update(&ssl_addr, &data_k);
        ssl_data_value.update(&ssl_addr, &data_v);
        flag_map.update(&ssl_addr,&f);
        return 0;
    }

    if(*flag == 1){ //第二次读SSL ----> body部分
      //  bpf_trace_printk("2");
        struct data_value *data_v_final = ssl_data_value.lookup(&ssl_addr);

        if(!data_v_final){
            return 0;
        }

        struct data_key *data_k_final = ssl_data_key.lookup(&ssl_addr);
        if(!data_k_final){
            return 0;
        }

        bpf_probe_read_user(&data_v_final->req_body, sizeof(data_v_final->req_body), buf);

        https_data.update(data_k_final, data_v_final);

       // events.perf_submit(ctx,data_final, sizeof(struct data_t));
        ssl_data_key.delete(&ssl_addr);
        ssl_data_value.delete(&ssl_addr);
        flag_map.delete(&ssl_addr);

        return 0;
    }
    else{
       // bpf_trace_printk("6");
        return 0;
    }
 //   bpf_probe_read_user(&data.buf, sizeof(data.buf), (void *)ssl);
  //  bpf_probe_read_user(&data.buf, sizeof(data.buf), s);
   // bpf_trace_printk("%s", data.buf);
  //  data.num = PT_REGS_RC(ctx)->session_cache_mode;
    return 0;

}