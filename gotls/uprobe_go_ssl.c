#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#define MAX_BUFFER_SIZE 400
#define recordTypeApplicationData  23

#define GO_PARAM1(x) ((x)->ax)
#define GO_PARAM2(x) ((x)->bx)
#define GO_PARAM3(x) ((x)->cx)
#define GO_PARAM4(x) ((x)->di)
#define GO_PARAM5(x) ((x)->si)
#define GO_PARAM6(x) ((x)->r8)
#define GO_PARAM7(x) ((x)->r9)
#define GO_PARAM8(x) ((x)->r10)
#define GO_PARAM9(x) ((x)->r11)
#define GOROUTINE(x) ((x)->r14)

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

/*
struct data_t{
    u32 pid;
    u32 uid;
    s32 len;
    u8 buf[400];
};
*/

BPF_TABLE_PUBLIC("hash", struct data_key, struct data_value, https_data, 4096);

//BPF_PERF_OUTPUT(events);


static void* go_get_argument_by_stack(struct pt_regs *ctx, int index) {
	    void* ptr = 0;
	    bpf_probe_read(&ptr, sizeof(ptr), (void *)(PT_REGS_SP(ctx)+(index*8)));
	    return ptr;
	}


int go_https_register(struct pt_regs *ctx){

   // bpf_trace_printk("1\n");

    struct data_key data_k = {};
    struct data_value data_v = {};

    //u8 buf[256] = {0};
    s32 len, record_type;
    const char *str;
    void *len_ptr;


    void *record_type_ptr;
    record_type_ptr = (void *)GO_PARAM2(ctx);

    bpf_probe_read_kernel(&record_type, sizeof(record_type), (void*)&record_type_ptr);

    if (record_type != recordTypeApplicationData){
        return 0;
    }

//    bpf_trace_printk("2\n");

   // struct data_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u32 uid = bpf_get_current_uid_gid();

    data_k.pid = pid;
    data_k.tid = tid;
    data_k.uid = uid;
    bpf_get_current_comm(&data_k.comm, sizeof(data_k.comm));

    str = (void*)GO_PARAM3(ctx);
    len_ptr = (void*)GO_PARAM4(ctx);
    bpf_probe_read_kernel(&len, sizeof(len), (void*)&len_ptr);

    data_v.len = len;

    bpf_probe_read_user(&data_v.buf,sizeof(data_v.buf),(void *)str);

  //  bpf_trace_printk("3\n");
    https_data.update(&data_k, &data_v);
   // events.perf_submit(ctx, &data, sizeof(data));

   // bpf_trace_printk("4\n");

    return 0;

}


int go_https_stack(struct pt_regs *ctx){

    struct data_key data_k = {};
    struct data_value data_v = {};

    s32 len, record_type;
    const char *str;
    void *len_ptr;

    void *record_type_ptr;
    record_type_ptr = (void *)go_get_argument_by_stack(ctx,2);

    bpf_probe_read_kernel(&record_type, sizeof(record_type), (void*)&record_type_ptr);

    if (record_type != recordTypeApplicationData){
        return 0;
    }

   // struct data_t data = {};
    data_k.pid = bpf_get_current_pid_tgid();
    data_k.tid = (u32)bpf_get_current_pid_tgid();
    data_k.uid = bpf_get_current_uid_gid();

    str = (void *)go_get_argument_by_stack(ctx,3);
    len_ptr = (void *)go_get_argument_by_stack(ctx,4);
    bpf_probe_read_kernel(&len, sizeof(len), (void*)&len_ptr);

    data_v.len = len;

    bpf_probe_read_user(&data_v.buf,sizeof(data_v.buf),(void *)str);

    https_data.update(&data_k, &data_v);
  //  events.perf_submit(ctx, &data, sizeof(data));
    return 0;

}
