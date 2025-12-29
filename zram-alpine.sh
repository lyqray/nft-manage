#!/bin/bash
# Alpine Linux ZRAM 安装脚本

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 显示帮助
show_help() {
    echo "用法: $0 {install|remove|status|help}"
    echo ""
    echo "命令:"
    echo "  install   安装 ZRAM"
    echo "  remove    卸载 ZRAM"
    echo "  status    查看状态"
    echo "  help      显示帮助"
    echo ""
    echo "示例:"
    echo "  $0 install    # 安装 ZRAM"
    echo "  $0 remove     # 卸载 ZRAM"
    echo "  $0 status     # 查看状态"
}

# 检查 root 权限
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}错误: 需要 root 权限${NC}"
        exit 1
    fi
}

# 检测操作系统
detect_os() {
    if [ -f /etc/alpine-release ]; then
        echo "alpine"
    else
        echo "unknown"
    fi
}

# 询问 ZRAM 百分比
ask_zram_ratio() {
    local default_ratio=50
    local ratio
    
    while true; do
        read -p "请输入 ZRAM 占内存的百分比 [${default_ratio}]: " ratio
        ratio=${ratio:-$default_ratio}
        
        if [[ "$ratio" =~ ^[0-9]+$ ]] && [ "$ratio" -ge 10 ] && [ "$ratio" -le 200 ]; then
            echo "$ratio"
            break
        else
            echo -e "${RED}错误: 请输入 10-200 之间的数字${NC}"
        fi
    done
}

# 安装 Alpine ZRAM
install_alpine_zram() {
    local ratio="$1"
    
    echo -e "${GREEN}正在为 Alpine Linux 安装 ZRAM...${NC}"
    
    # 创建配置目录和文件
    mkdir -p /etc/conf.d
    cat > /etc/conf.d/zram << EOF
# ZRAM 配置
ZRAM_TOTAL_RATIO="${ratio}"      # ZRAM占内存的百分比
ZRAM_PRIORITY="100"              # swap优先级
ZRAM_ALGORITHM="lz4"             # 压缩算法
MIN_SIZE_MB="128"                # 每个设备最小128MB
EOF
    echo "✓ 创建配置文件: /etc/conf.d/zram"
    
    # 创建 init.d 脚本
    cat > /etc/init.d/zram << 'EOF'
#!/sbin/openrc-run
# ZRAM 服务脚本

name="zram"
description="ZRAM swap with adaptive size"

start() {
    ebegin "Starting ZRAM swap"
    
    # 加载配置
    [ -f /etc/conf.d/zram ] && . /etc/conf.d/zram
    ZRAM_TOTAL_RATIO=${ZRAM_TOTAL_RATIO:-50}
    ZRAM_PRIORITY=${ZRAM_PRIORITY:-100}
    ZRAM_ALGORITHM=${ZRAM_ALGORITHM:-lz4}
    MIN_SIZE_MB=${MIN_SIZE_MB:-128}
    
    # 获取CPU核心数
    cpu_cores=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null || echo 1)
    
    # 获取总内存
    total_mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    total_mem_mb=$((total_mem_kb / 1024))
    
    # 计算ZRAM总量
    zram_total_mb=$((total_mem_mb * ZRAM_TOTAL_RATIO / 100))
    [ $zram_total_mb -lt 256 ] && zram_total_mb=256
    
    # 计算每个设备大小
    per_device_mb=$((zram_total_mb / cpu_cores))
    if [ $per_device_mb -lt $MIN_SIZE_MB ]; then
        per_device_mb=$MIN_SIZE_MB
        cpu_cores=$((zram_total_mb / per_device_mb))
        [ $cpu_cores -lt 1 ] && cpu_cores=1
    fi
    
    per_device_bytes=$((per_device_mb * 1024 * 1024))
    
    echo "系统信息:"
    echo "  CPU核心数: $cpu_cores"
    echo "  物理内存: ${total_mem_mb}MB"
    echo "  ZRAM总量: ${zram_total_mb}MB (${ZRAM_TOTAL_RATIO}%内存)"
    echo "  每个设备: ${per_device_mb}MB"
    echo "  总设备数: $cpu_cores"
    
    # 清理旧设备
    for i in {0..31}; do
        swapoff /dev/zram$i 2>/dev/null || true
        if [ -d /sys/class/zram-control ] && [ -e /sys/block/zram$i ]; then
            echo $i > /sys/class/zram-control/hot_remove 2>/dev/null || true
        fi
        rm -f /dev/zram$i 2>/dev/null || true
    done
    rmmod zram 2>/dev/null || true
    
    # 创建新设备
    echo "创建 $cpu_cores 个ZRAM设备..."
    modprobe zram num_devices=$cpu_cores
    sleep 0.5
    
    # 配置每个设备
    success_count=0
    for i in $(seq 0 $(($cpu_cores - 1))); do
        if [ -e /dev/zram$i ]; then
            # 设置压缩算法
            if [ -f /sys/block/zram$i/comp_algorithm ]; then
                echo "$ZRAM_ALGORITHM" > /sys/block/zram$i/comp_algorithm 2>/dev/null || true
            fi
            
            # 设置大小
            echo $per_device_bytes > /sys/block/zram$i/disksize
            
            # 创建swap
            if mkswap /dev/zram$i 2>/dev/null; then
                # 启用swap
                if swapon -p "$ZRAM_PRIORITY" /dev/zram$i 2>/dev/null; then
                    echo "✓ 配置 zram$i: ${per_device_mb}MB"
                    success_count=$((success_count + 1))
                else
                    echo "✗ 启用失败 zram$i"
                fi
            else
                echo "✗ 格式化失败 zram$i"
            fi
        else
            echo "✗ 设备不存在 /dev/zram$i"
        fi
    done
    
    # 最终报告
    echo "=== 配置完成 ==="
    echo "成功配置: $success_count/$cpu_cores 个设备"
    
    if [ $success_count -gt 0 ]; then
        total_actual=$(grep "^/dev/zram" /proc/swaps 2>/dev/null | awk '{sum+=$3} END {print sum/1024/1024}')
        echo "实际ZRAM总量: ${total_actual:-0}MB"
    else
        echo "警告: 没有ZRAM设备被激活"
        return 1
    fi
    
    eend $?
}

stop() {
    ebegin "Stopping ZRAM swap"
    
    # 获取CPU核心数
    cpu_cores=$(nproc)
    echo "停止 $cpu_cores 个ZRAM设备..."
    
    # 停止每个设备
    stopped_count=0
    for i in $(seq 0 $(($cpu_cores + 3))); do
        if swapoff /dev/zram$i 2>/dev/null; then
            echo "✓ 已停止 zram$i"
            stopped_count=$((stopped_count + 1))
        fi
        
        if [ -d /sys/class/zram-control ]; then
            echo $i > /sys/class/zram-control/hot_remove 2>/dev/null || true
        fi
        
        rm -f /dev/zram$i 2>/dev/null || true
    done
    
    # 移除模块
    rmmod zram 2>/dev/null || true
    
    echo "已停止 $stopped_count 个ZRAM设备"
    eend $?
}

depend() {
    need localmount
    before swap
}
EOF
    
    chmod +x /etc/init.d/zram
    echo "✓ 创建服务脚本: /etc/init.d/zram"
    
    # 添加到启动项
    rc-update add zram boot 2>/dev/null || true
    echo "✓ 添加到开机启动"
    
    # 启动服务
    if rc-service zram start; then
        echo -e "${GREEN}✓ ZRAM 启动成功${NC}"
    else
        echo -e "${YELLOW}⚠ ZRAM 启动可能有问题，请检查${NC}"
    fi
}

# 安装 ZRAM
install_zram() {
    echo -e "${BLUE}=== ZRAM 安装程序 ===${NC}"
    
    # 检查操作系统
    local os_type=$(detect_os)
    if [ "$os_type" != "alpine" ]; then
        echo -e "${RED}错误: 此脚本仅支持 Alpine Linux${NC}"
        exit 1
    fi
    
    # 询问 ZRAM 百分比
    echo -e "${YELLOW}提示: ZRAM 大小 = 物理内存 × 百分比${NC}"
    echo -e "${YELLOW}推荐: 50-100% (内存越大可以设越高)${NC}"
    local ratio=$(ask_zram_ratio)
    
    install_alpine_zram "$ratio"
    
    echo ""
    echo -e "${GREEN}安装完成！${NC}"
    echo ""
    echo "管理命令:"
    echo "  rc-service zram start      # 启动"
    echo "  rc-service zram stop       # 停止"
    echo "  rc-service zram restart    # 重启"
    echo "  rc-service zram status     # 状态"
    echo ""
    echo "配置文件: /etc/conf.d/zram"
    echo "卸载命令: $0 remove"
}

# 卸载 ZRAM
remove_zram() {
    echo -e "${YELLOW}正在卸载 ZRAM...${NC}"
    
    # 检查是否在 Alpine 上
    local os_type=$(detect_os)
    if [ "$os_type" != "alpine" ]; then
        echo -e "${RED}错误: 此脚本仅支持 Alpine Linux${NC}"
        exit 1
    fi
    
    # 停止服务
    if [ -f /etc/init.d/zram ]; then
        rc-service zram stop 2>/dev/null || true
        echo "✓ 停止 ZRAM 服务"
    fi
    
    # 从启动项移除
    rc-update del zram 2>/dev/null || true
    echo "✓ 从启动项移除"
    
    # 删除文件
    rm -f /etc/init.d/zram
    rm -f /etc/conf.d/zram
    echo "✓ 删除配置文件"
    
    # 清理 ZRAM 设备
    echo "清理 ZRAM 设备..."
    for i in {0..7}; do
        swapoff /dev/zram$i 2>/dev/null || true
    done
    rmmod zram 2>/dev/null || true
    echo "✓ 清理 ZRAM 设备"
    
    echo ""
    echo -e "${GREEN}卸载完成！${NC}"
    echo "提示: 建议重启系统以确保完全清理"
}

# 查看状态
check_status() {
    echo "=== ZRAM 状态检查 ==="
    echo ""
    
    # 检查操作系统
    local os_type=$(detect_os)
    if [ "$os_type" != "alpine" ]; then
        echo -e "${RED}错误: 此脚本仅支持 Alpine Linux${NC}"
        exit 1
    fi
    
    echo "操作系统: Alpine Linux"
    
    # 检查服务文件
    if [ -f /etc/init.d/zram ]; then
        echo "✓ 服务文件: /etc/init.d/zram"
    else
        echo "✗ 服务文件: 不存在"
    fi
    
    if [ -f /etc/conf.d/zram ]; then
        echo "✓ 配置文件: /etc/conf.d/zram"
        echo "当前配置:"
        grep -v "^#" /etc/conf.d/zram | grep -v "^$"
    else
        echo "✗ 配置文件: 不存在"
    fi
    
    echo ""
    
    # 检查服务状态
    if rc-service zram status >/dev/null 2>&1; then
        echo "✓ 服务状态: 已安装并启用"
    else
        echo "✗ 服务状态: 未安装或未启用"
    fi
    
    echo ""
    echo "=== 系统信息 ==="
    echo "CPU核心数: $(nproc 2>/dev/null || grep -c "^processor" /proc/cpuinfo)"
    echo "总内存: $(grep MemTotal /proc/meminfo | awk '{printf "%.1f GB\n", $2/1024/1024}')"
    
    echo ""
    echo "=== 当前 ZRAM 设备 ==="
    if ls /dev/zram* >/dev/null 2>&1; then
        for dev in /dev/zram*; do
            if [ -b "$dev" ]; then
                basename=$(basename $dev)
                size=""
                [ -f "/sys/block/$basename/disksize" ] && \
                    size=" ($(($(cat /sys/block/$basename/disksize)/1024/1024))MB)"
                echo "  $dev$size"
            fi
        done
    else
        echo "  无 ZRAM 设备"
    fi
    
    echo ""
    echo "=== 当前 SWAP 状态 ==="
    if swapon --show 2>/dev/null | grep -q zram; then
        swapon --show | grep zram
    elif grep -q zram /proc/swaps 2>/dev/null; then
        grep zram /proc/swaps
    else
        echo "  无 ZRAM swap"
    fi
}

# 主程序
main() {
    case "$1" in
        install)
            check_root
            install_zram
            ;;
        remove)
            check_root
            remove_zram
            ;;
        status)
            check_status
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            if [ $# -eq 0 ]; then
                echo -e "${YELLOW}请指定命令${NC}"
                show_help
                exit 1
            else
                echo -e "${RED}错误: 未知命令 '$1'${NC}"
                show_help
                exit 1
            fi
            ;;
    esac
}

# 运行主程序
main "$@"
