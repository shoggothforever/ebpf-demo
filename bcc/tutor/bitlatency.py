from __future__ import print_function
from bcc import BPF
from time import sleep

# BPF 程序
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HASH(start, struct request *);   // 存储请求开始时间
BPF_HISTOGRAM(dist);                 // 定义延迟直方图

// 记录 I/O 请求的开始时间
int trace_start(struct pt_regs *ctx, struct request *req) {
    u64 ts = bpf_ktime_get_ns();
    start.update(&req, &ts);
    return 0;
}

// 记录 I/O 请求的结束时间，并计算延迟
int trace_completion(struct pt_regs *ctx, struct request *req) {
    u64 *tsp = start.lookup(&req);
    if (tsp != 0) {
        u64 delta = bpf_ktime_get_ns() - *tsp;
        dist.increment(bpf_log2l(delta / 1000));  // 将延迟转换为微秒并记录
        start.delete(&req);  // 删除记录，避免内存泄漏
    }
    return 0;
}
"""

# 加载 BPF 程序
b = BPF(text=bpf_text)
if BPF.get_kprobe_functions(b'blk_start_request'):
        b.attach_kprobe(event="blk_start_request", fn_name="trace_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_start")
if BPF.get_kprobe_functions(b'__blk_account_io_done'):
    b.attach_kprobe(event="__blk_account_io_done", fn_name="trace_completion")
else:
    b.attach_kprobe(event="blk_account_io_done", fn_name="trace_completion")
# 输出提示信息
print("Tracing disk I/O... Hit Ctrl-C to end.")

# 持续监控磁盘 I/O 直到用户按下 Ctrl-C
try:
    sleep(99999999)
except KeyboardInterrupt:
    print("\n")

# 打印延迟直方图
b["dist"].print_log2_hist("us")
