#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

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


struct data_t{
    u32 pid;
    u32 uid;
    s32 len;
    u8 buf[400];
};

static void* go_get_argument_by_stack(struct pt_regs *ctx, int index) {
	    void* ptr = 0;
	    bpf_probe_read(&ptr, sizeof(ptr), (void *)(PT_REGS_SP(ctx)+(index*8)));
	    return ptr;
	}


BPF_PERF_OUTPUT(events);

int go_https_register(struct pt_regs *ctx){

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

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.uid = bpf_get_current_uid_gid();

    str = (void*)GO_PARAM3(ctx);
    len_ptr = (void*)GO_PARAM4(ctx);
    bpf_probe_read_kernel(&len, sizeof(len), (void*)&len_ptr);

    data.len = len;

    bpf_probe_read_user(&data.buf,sizeof(data.buf),(void *)str);

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;

}


int go_https_stack(struct pt_regs *ctx){

    s32 len, record_type;
    const char *str;
    void *len_ptr;

    void *record_type_ptr;
    record_type_ptr = (void *)go_get_argument_by_stack(ctx,2);

    bpf_probe_read_kernel(&record_type, sizeof(record_type), (void*)&record_type_ptr);

    if (record_type != recordTypeApplicationData){
        return 0;
    }

    struct data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    data.uid = bpf_get_current_uid_gid();

    str = (void *)go_get_argument_by_stack(ctx,3);
    len_ptr = (void *)go_get_argument_by_stack(ctx,4);
    bpf_probe_read_kernel(&len, sizeof(len), (void*)&len_ptr);

    data.len = len;

    bpf_probe_read_user(&data.buf,sizeof(data.buf),(void *)str);

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;

}
