package sys_accept

import (
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"
    "time"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/rlimit"
)

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
    go func (){
        tp, err := link.Kprobe("sys_accept", objs.HandleSysAccept, nil)
        if err != nil {
            log.Fatalf("Failed to attach eBPF program to tracepoint: %v", err)
        }
        defer tp.Close()
        for{
            iterator:=objs.AcceptCount.Iterate()
            var key int
            var value uint64
            for iterator.Next(&key,&value){
                log.Printf("Socket: %d, count: %d\n", key, value)
            }

            time.Sleep(time.Second)
        }
    }()
    // Attach the eBPF program to the sched_switch tracepoint


    fmt.Println("eBPF program attached. Press Ctrl+C to exit.")

    // Wait for a signal to exit
    <-stopper

    fmt.Println("eBPF program detached.")
}
