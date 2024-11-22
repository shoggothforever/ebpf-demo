//go:build ignore

#include "../headers/common.h"
#include "../headers/bpf_endian.h"
#include "../headers/bpf_tracing.h"
#include "../vmlinux.h"
#include <memory.h>

struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,2048);
    __type(key,int);
    __type(value,u64);
} accept_count SEC(".maps");


SEC("kprobe/sys_accept")
int handle_sys_accept(struct pt_regs *ctx, struct task_struct *prev) {
    int sockfd = ctx->di;
    u64 *count = bpf_map_lookup_elem(&accept_count, &sockfd);
    if (count) {
        *count += 1;
        bpf_map_update_elem(&accept_count, &sockfd, count, BPF_ANY);
    } else {
        u64 new_count=1;
        bpf_map_update_elem(&accept_count, &sockfd, &new_count, BPF_ANY);
    }
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));
    bpf_printk("Accepting connection on socket: %d, pid: %d, comm=%s\n", sockfd, bpf_get_current_pid_tgid(), comm);

    return 0;
}

char _license[] SEC("license") = "GPL";
