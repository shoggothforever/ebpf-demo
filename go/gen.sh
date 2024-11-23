#!/bin/bash

# 检查是否提供了包名参数
if [ $# -lt 1 ]; then
    echo "用法: $0 <包名>"
    echo "例如: $0 mypackage"
    exit 1
fi

PACKAGE_NAME=$1
DIR_NAME=$PACKAGE_NAME
GO_FILE="$PACKAGE_NAME/$PACKAGE_NAME.go"
C_FILE="$PACKAGE_NAME/$PACKAGE_NAME.c"

# 创建包名文件夹
sudo mkdir -p "$DIR_NAME"

# 设置文件夹权限
sudo chmod 777 "$DIR_NAME"

# 生成 Go 文件模板
cat > "$GO_FILE" <<EOF
package $PACKAGE_NAME

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)
// remove -type event if you won't use diy struct in kernel
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type event bpf $PACKAGE_NAME.c -- -I../headers

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


	// write your link code here

	go Action(objs)
	<-stopper
}


func Action(objs bpfObjects){
	// add your link logic here

	for{
		// write your logical code here
		time.Sleep(1 * time.Second)
	}
}

// add more action function here

EOF
sudo chmod 777 "$GO_FILE"
# 生成 C 文件模板
cat > "$C_FILE" <<EOF
//go:build ignore

#include "../vmlinux.h"
#include "../headers/common.h"
#include "../headers/bpf_endian.h"
#include "../headers/bpf_tracing.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";
struct event {
	u8 comm[16];
	__u16 val;
};
struct event *unused __attribute__((unused));

SEC("XXX")
int handle_XXX(){
    // write your code here
	return 0;
}
EOF
sudo chmod 777 "$C_FILE"
# 输出结果
echo "Go 文件已生成: $GO_FILE"

echo "C 文件已生成: $C_FILE"

echo "文件夹 $PACKAGE_NAME 已设置权限为 777"

# sh gen.sh exec
