package open_at

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"fmt"
	"encoding/binary"
	"bytes"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/perf"
)
// remove -type event if you won't use diy struct in kernel
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type event -target bpfel  bpf open_at.c -- -I../headers

func Start() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()




	go Action1(objs)

	<-stopper
}

func Action1(objs bpfObjects){
	tp,err:=link.Tracepoint("syscalls","sys_enter_openat",objs.TraceOpenat,nil)
	if err!=nil{
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer tp.Close()
	// 读取从内核发送到用户空间的事件
	fmt.Println("Waiting for events...")
	rd, err := perf.NewReader(objs.Events, 4096)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create perf event reader: %v\n", err)
		os.Exit(1)
	}
	defer rd.Close()
	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			fmt.Fprintf(os.Stderr, "reading perf event: %v\n", err)
			return
		}

		// 将字节数据转换为事件结构
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			fmt.Fprintf(os.Stderr, "parsing perf event: %v\n", err)
			continue
		}

		fmt.Printf("PID: %d | Command: %s | File: %s\n", event.Pid, int8ArrayToString(event.Comm[:]), int8ArrayToString(event.Filename[:]))
		time.Sleep(1 * time.Second)
	}
}

// add more action function here
func int8ArrayToString(arr []int8) string {
	// 创建一个字节切片，将 [16]int8 转换为 []byte
	bytes := make([]byte, len(arr))
	for i, v := range arr {
		// 忽略空值 (值为 0)
		if v == 0 {
			break
		}
		bytes[i] = byte(v)
	}

	// 将字节切片转换为字符串
	return string(bytes)
}
