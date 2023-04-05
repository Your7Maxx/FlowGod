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
#define GO_SP(x) ((x)->sp)

struct data_t{
    u32 pid;
    u32 uid;
    s32 len;
    u8 buf[400];
};

BPF_PERF_OUTPUT(events);

inline int crack_https(struct pt_regs *ctx){

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

   // u64* addr = (u64*)ctx->sp;
    //u64 val = 0;

   // bpf_probe_read(&val, sizeof(val), addr + 3);
   // addr = (u64*)val;

   // bpf_probe_read(&(data.buf), sizeof(data.buf), addr);

    events.perf_submit(ctx, &data, sizeof(data));

    return 0;

}


