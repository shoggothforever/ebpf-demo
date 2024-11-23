//go:build ignore

#include "../vmlinux.h"
#include "../headers/common.h"
#include "../headers/bpf_endian.h"
#include "../headers/bpf_tracing.h"
#include <stdbool.h>
#include <memory.h>
#define TASK_COMM_LEN	 16
#define MAX_FILENAME_LEN 127
const volatile unsigned long long min_duration_ns = 0;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct exec_key{
    int pid;
    char comm[TASK_COMM_LEN];

};

struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries,2048);
    __type(key,struct exec_key);
    __type(value,u64);
} exec_start SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct event {
	int pid;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	bool exit_event;
};
SEC("tracepoint/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	unsigned fname_off;
	struct event *e;
	int pid;
	u64 ts;

	/* remember time exec() was executed for this PID */
	pid = bpf_get_current_pid_tgid() >> 32;
    /* don't emit exec events when minimum duration is specified */
	if (min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	e->exit_event = false;
	e->pid = pid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);

	ts = bpf_ktime_get_ns();
    struct exec_key key={};
    __builtin_memset(&key, 0, sizeof(key));
    key.pid = pid;
    bpf_probe_read_kernel(&key.comm, sizeof(key.comm), e->comm);
	bpf_map_update_elem(&exec_start, &key, &ts, BPF_ANY);


	/* successfully submit it to user-space for post-processing */

	return 0;
}


SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct event *e;
	int pid, tid;
	u64 id, ts, *start_ts, duration_ns = 0;

	/* get PID and TID of exiting thread/process */
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

	/* ignore thread exits */
	if (pid != tid)
		return 0;
    /* if process didn't live long enough, return early */
	if (min_duration_ns && duration_ns < min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(struct event), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	// task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = true;
	e->duration_ns = duration_ns;
	e->pid = pid;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	/* if we recorded start of the process, calculate lifetime duration */
    struct exec_key key={};
    key.pid = pid;
    bpf_probe_read_kernel(&key.comm, sizeof(key.comm), e->comm);
	start_ts = bpf_map_lookup_elem(&exec_start, &key);
	if (start_ts)
		duration_ns = bpf_ktime_get_ns() - *start_ts;
	else if (min_duration_ns)
		return 0;
	bpf_map_delete_elem(&exec_start, &key);


	return 0;
}
