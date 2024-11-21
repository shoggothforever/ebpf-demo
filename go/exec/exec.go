package exec
import(
	"log"
	"os"
	"os/signal"
	"syscall"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/ringbuf"
	"unsafe"
	"sync"
	"time"
	"fmt"
	"github.com/cilium/ebpf/link"
	"bytes"
	"encoding/binary"

)
type ExecKey struct {
	PID   uint32 // Matches `u32 pid` in C
	Padding [16]byte // 显式添加 padding，确保对齐
}

func Start(){
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	fmt.Println("size of ExecKey:",unsafe.Sizeof(ExecKey{}))
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
	rd,err:=ringbuf.NewReader(objs.bpfMaps.Rb)
	if err!=nil{
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	m:=sync.Mutex{}

	cnt:=0
	mp:=make(map[ExecKey]struct{})
	go func(){
		exec_start,err:=link.Tracepoint("sched","sched_process_exec",objs.HandleExec,nil)
		if err!=nil{
			log.Fatalf("opening tracepoint: %s", err)
		}
		defer exec_start.Close()
		for{
			m.Lock()
			fmt.Println(cnt,": exec_start turns ")
			cnt++
			iterator := objs.ExecStart.Iterate()
			var key ExecKey
			var value uint64
			iter:=0
			for iterator.Next(&key, &value)&&iter<10 {
				// log.Printf("Pid: %d, visit time: %d\n", key, value)
				if _,ok:=mp[key];!ok{
					mp[key]=struct{}{}
					// log.Printf("Pid: %d, visit time: %d\n", key, value)
					iter++
				}
			}
			// Check for errors during iteration
			if err := iterator.Err(); err != nil {
				log.Fatalf("map iteration failed: %v", err)
			}
			m.Unlock()
			time.Sleep(1 * time.Second)

		}
	}()
	go func(){
		sched_process_exit,err:=link.Tracepoint("sched","sched_process_exit",objs.HandleExit,nil)
		if err!=nil{
			log.Fatalf("opening tracepoint: %s", err)
		}
		defer sched_process_exit.Close()
		for{
			m.Lock()
			fmt.Println(cnt,": sched_process_exit turns ")
			iterator := objs.ExecStart.Iterate()
			var key ExecKey
			var value uint64
			iter:=0
			for iterator.Next(&key, &value)&&iter<10 {
				// log.Printf("Pid: %d, visit time: %d\n", key, value)
				if _,ok:=mp[key];ok{
					delete(mp,key)
					// log.Printf("Pid: %d, exit time: %d\n", key, value)
					iter++
				}
			}
			// Check for errors during iteration
			if err := iterator.Err(); err != nil {
				log.Fatalf("map iteration failed: %v", err)
			}
			m.Unlock()
			time.Sleep(1 * time.Second)

		}
	}()
	go func(){
		type event struct {
			PID        int32    // int corresponds to int32 in Go
			DurationNS uint64   // unsigned long long corresponds to uint64 in Go
			Comm       [16]byte // char[16] is a fixed-size array of 16 bytes
			ExitEvent  bool     // bool corresponds to bool in Go
		}
		var e event
		for{
			m.Lock()
			record,err:=rd.Read()
			if err!=nil{
				log.Fatalf("reading ringbuf: %s", err)
			}
			// log.Printf("record: %v", record)
			if err=binary.Read(bytes.NewReader(record.RawSample),binary.LittleEndian,&e);err!=nil{
				log.Fatalf("reading record: %s", err)
			}
			if e.ExitEvent{
				log.Printf("exit ts: %d, pid: %d, comm: %s\n", e.DurationNS, e.PID, e.Comm)
			}else{
				log.Printf("exec ts: %d, pid: %d, comm: %s\n", e.DurationNS, e.PID, e.Comm)
			}

			m.Unlock()
			time.Sleep(1 * time.Second)
		}
	}()
	<-stopper
	log.Println("stopper")
	return
}
