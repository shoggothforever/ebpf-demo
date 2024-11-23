//go:build ignore


#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 定义事件结构
struct event {
    u32 pid;
    char comm[16];
    char filename[256];
};
struct event *unused __attribute__((unused));

// 定义一个映射用于存储事件
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter* ctx) {
    struct event evt = {};
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // 获取进程 PID 和命令名
    evt.pid = pid;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));

    // 从参数中读取文件名
    const char *filename = (const char *)ctx->args[1];
    bpf_core_read_user_str(&evt.filename, sizeof(evt.filename), filename);

    // 将事件发送到用户空间
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}
