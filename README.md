# ebpf-demo
此仓库存放一些ebpf的demo代码，希望做到每个demo都有实际用途
起步的代码参考了libbpf的example，并且编译的流程也是基于libbpf的
后续会考虑使用golang来编写ebpf程序，并且使用cilium/ebpf库，实现更偏向应用层的开发

## 环境
linux 4.15.0
clang 16
libbpf 1.1.0
llvm 16

## TODO
- [ ]添加makefile
- [ ]添加dockerfile
- [ ]添加gitaction 实现将代码编译为ebpf程序到bin目录
- [ ]补充网络xdp的demo
- [ ]补充操作系统调度的demo
- [ ]补充tracepoint的demo
- [ ]补充kprobe的demo
- [ ]补充uprobe的demo
- [ ]补充cgroup的demo
- [ ]补充sk_skb的demo
- [ ]补充lwt_xmit的demo
- [ ]补充flow_dissector的demo
- [ ]使用cilium/ebpf库编写ebpf程序
- [ ]能够自动定位到docker的容器并且attach
