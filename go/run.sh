
# 检查是否提供了包名参数
if [ $# -lt 1 ]; then
    echo "用法: $0 <包名>"
    echo "例如: $0 mypackage"
    exit 1
fi

BUILD_DIR=$1


go generate ./$BUILD_DIR/ && go build . && sudo ./go-ebpf


# sh run.sh exec
