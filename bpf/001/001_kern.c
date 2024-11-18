#include <uapi/linux/bpf.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"
#include <linux/ptrace.h>
#include <linux/version.h>
#include <linux/types.h>

typedef unsigned int u32;
typedef int pid_t;
const pid_t pid_filter = 0;
struct trace_entry {
	short unsigned int type;
	unsigned char flags;
	unsigned char preempt_count;
	int pid;
};
struct trace_event_raw_sys_enter {
	struct trace_entry ent;
	long int id;
	long unsigned int args[6];
	char __data[0];
};
struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 4096,
};
#define bpf_printk(fmt, ...)                       \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

SEC("tracepoint/syscalls/sys_enter_write")
int handle_tp(struct trace_event_raw_sys_enter* ctx)
{
    int fd = ctx->args[0];
    int err;
    // char *buf = (char *)ctx->args[1];
    // int pid=ctx->ent.pid;
    int *value;
    size_t count = ctx->args[2];
    if (fd<3){
        value = bpf_map_lookup_elem(&my_map, &fd);
        if (value){
            *value += count;
            bpf_printk("Write called: fd=%d,len(msg)=%d\n", fd,*value);
                    err =  bpf_map_update_elem(&my_map, &fd, value, BPF_ANY);
            if (err < 0) {
                return -1;
            }
        }else{
            err =  bpf_map_update_elem(&my_map, &fd, &count, BPF_ANY);
            if (err < 0) {
                return -1;
            }
        }

    }
    // bpf_printk("bpf triggered write syscall");
    return 0;
}
char _license[] SEC("license") = "GPL";
