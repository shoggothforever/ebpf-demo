from bcc import BPF
from time import sleep


if len(argc)>1:
    time=argv[0]


b = BPF(src_file="task_switch.c")
# b.attach_kprobe(event="finish_task_switch.isra.0", fn_name="count_sched")

b.attach_kprobe(event_re="^finish_task_switch$|^finish_task_switch\.isra\.\d$", fn_name="count_sched")
# generate many schedule events
for i in range(0, 100): sleep(0.01)

for k, v in b["stats"].items():
    print("task_switch[%5d->%5d]=%u" % (k.prev_pid, k.curr_pid, v.value))
b.trace_print()
