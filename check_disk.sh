#!/usr/bin/env sh
set -e

# ========= 简单颜色定义 =========
# 检查终端是否支持颜色
if [ -t 1 ]; then
    # 使用 ANSI 颜色码
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    MAGENTA='\033[0;35m'
    CYAN='\033[0;36m'
    RESET='\033[0m'
else
    # 非终端环境，不使用颜色
    RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; RESET=''
fi

# ========= 测试目录：用户根目录 =========
TEST_DIR="/root"
TEST_FILE="$TEST_DIR/.fio_test.$$"

BS4K="4k"
BS64K="64k"

printf "${CYAN}=== 云服务器磁盘快速判定（/root 目录，无 /tmp 依赖） ===${RESET}\n"
printf "${BLUE}[INFO]${RESET} fio 测试目录：$TEST_DIR\n"
printf "\n"

# ---------- 0. 权限与空间检查 ----------
if [ ! -w "$TEST_DIR" ]; then
    printf "${YELLOW}[WARN]${RESET} $TEST_DIR 不可写，某些测试可能失败，请使用 root 运行\n"
fi

FREE_MB=$(df -m "$TEST_DIR" | awk 'NR==2 {print $4}')
if [ -n "$FREE_MB" ] && [ "$FREE_MB" -lt 600 ]; then
    printf "${YELLOW}[WARN]${RESET} $TEST_DIR 可用空间不足（${FREE_MB:-0}MB）\n"
fi

# ---------- 1. 系统识别 ----------
if [ -f /etc/alpine-release ]; then
    OS="alpine"
else
    OS="debian"
fi
printf "${BLUE}[INFO]${RESET} 系统类型：$OS\n"

# ---------- 2. NVMe 判断 ----------
if [ -d /sys/class/nvme ] && [ "$(ls /sys/class/nvme 2>/dev/null)" ]; then
    NVME=1
    printf "${BLUE}[INFO]${RESET} NVMe 设备：${GREEN}是${RESET}\n"
else
    NVME=0
    printf "${BLUE}[INFO]${RESET} NVMe 设备：${YELLOW}否${RESET}\n"
fi

# ---------- 3. rotational ----------
ROTA=$(cat /sys/block/*/queue/rotational 2>/dev/null | sort -u | tr '\n' ' ')
ROTA=${ROTA:-unknown}
printf "${BLUE}[INFO]${RESET} rotational 标志: $ROTA\n"

# ---------- 4. fio 安装 ----------
if ! command -v fio >/dev/null 2>&1; then
    printf "${YELLOW}[INFO]${RESET} 安装 fio...\n"
    if [ "$OS" = "alpine" ]; then
        apk add --no-cache fio 2>/dev/null || printf "${YELLOW}[WARN]${RESET} 安装 fio 失败\n"
    else
        apt update -qq && apt install -y fio 2>/dev/null || printf "${YELLOW}[WARN]${RESET} 安装 fio 失败\n"
    fi
fi

# ---------- 5. 测试 ----------
printf "\n"
printf "${CYAN}[TEST 1/3]${RESET} 4K 随机读（5 秒）\n"
OUT_RR=$(fio --name=rr \
    --filename="$TEST_FILE" \
    --size=128M \
    --bs=$BS4K \
    --rw=randread \
    --iodepth=32 \
    --direct=1 \
    --runtime=5 \
    --time_based \
    --group_reporting 2>/dev/null || echo "")

printf "\n"
printf "${CYAN}[TEST 2/3]${RESET} 64K 顺序读（3 秒）\n"
OUT_SR=$(fio --name=sr \
    --filename="$TEST_FILE" \
    --size=256M \
    --bs=$BS64K \
    --rw=read \
    --iodepth=16 \
    --direct=1 \
    --runtime=3 \
    --time_based \
    --group_reporting 2>/dev/null || echo "")

printf "\n"
printf "${CYAN}[TEST 3/3]${RESET} 4K 混合（70R / 30W，4 秒）\n"
OUT_RW=$(fio --name=rw \
    --filename="$TEST_FILE" \
    --size=128M \
    --bs=$BS4K \
    --rw=randrw \
    --rwmixread=70 \
    --iodepth=32 \
    --direct=1 \
    --runtime=4 \
    --time_based \
    --group_reporting 2>/dev/null || echo "")

# ---------- 6. 清理测试文件 ----------
rm -f "$TEST_FILE"

# ---------- 7. 主动清理缓存（需要 root） ----------
sync
echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true

# ---------- 8. 解析（busybox 兼容） ----------
RR_IOPS=$(echo "$OUT_RR" | awk -F'IOPS=' '/IOPS=/{print $2}' | awk -F',' 'NR==1{print int($1)}')
RR_IOPS=${RR_IOPS:-0}

RR_LAT_US=$(echo "$OUT_RR" | awk '
/lat \(usec\):/ && /avg=/ {
    for (i=1;i<=NF;i++) if ($i ~ /avg=/) {
        gsub("avg=","",$i); gsub(",","",$i); print $i; exit
    }
}
/clat \(usec\):/ && /avg=/ {
    for (i=1;i<=NF;i++) if ($i ~ /avg=/) {
        gsub("avg=","",$i); gsub(",","",$i); print $i; exit
    }
}
')
RR_LAT_US=${RR_LAT_US:-unknown}

SR_BW=$(echo "$OUT_SR" | awk -F'BW=' '/BW=/{print $2}' | awk -F'MiB/s' 'NR==1{print $1}')
SR_BW=${SR_BW:-unknown}

RW_IOPS=$(echo "$OUT_RW" | awk -F'IOPS=' '/IOPS=/{print $2}' | awk -F',' 'END{print int($1)}')
RW_IOPS=${RW_IOPS:-0}

# ---------- 9. 判定 ----------
printf "\n"
printf "${CYAN}=== 判定结果 ===${RESET}\n"

# 根据 IOPS 值确定结果颜色
if [ "$RR_IOPS" -lt 500 ]; then
    RESULT="机械 HDD / 极低性能盘"
    RESULT_COLOR="$RED"
elif [ "$RR_IOPS" -lt 1500 ]; then
    RESULT="严重限速云盘"
    RESULT_COLOR="$YELLOW"
elif [ "$RR_IOPS" -lt 5000 ]; then
    RESULT="普通 SSD 云盘（共享型）"
    RESULT_COLOR="$BLUE"
elif [ "$RR_IOPS" -lt 30000 ]; then
    RESULT="高性能 SSD 云盘"
    RESULT_COLOR="$GREEN"
else
    if [ "$NVME" -eq 1 ]; then
        RESULT="NVMe 云盘（可能存在 QoS）"
    else
        RESULT="NVMe 级性能云盘"
    fi
    RESULT_COLOR="$MAGENTA"
fi

if [ "$RW_IOPS" -lt $((RR_IOPS / 3)) ]; then
    RESULT="$RESULT（写性能受限）"
fi

printf "结论：${RESULT_COLOR}$RESULT${RESET}\n"
printf "\n"
printf "${CYAN}[测试指标]${RESET}\n"

# 为每个指标添加颜色
# 4K 随机读 IOPS
if [ "$RR_IOPS" -lt 500 ]; then
    IOPS_COLOR="$RED"
elif [ "$RR_IOPS" -lt 1500 ]; then
    IOPS_COLOR="$YELLOW"
elif [ "$RR_IOPS" -lt 5000 ]; then
    IOPS_COLOR="$BLUE"
elif [ "$RR_IOPS" -lt 30000 ]; then
    IOPS_COLOR="$GREEN"
else
    IOPS_COLOR="$MAGENTA"
fi
printf "  4K 随机读 IOPS : ${IOPS_COLOR}$RR_IOPS${RESET}\n"

# 4K 平均延迟 - 修复浮点数比较问题
if [ "$RR_LAT_US" != "unknown" ]; then
    # 提取整数部分进行比较（Alpine ash 兼容）
    LAT_NUM=$(echo "$RR_LAT_US" | awk 'BEGIN {FS="."} {print $1}')
    if [ -n "$LAT_NUM" ] && [ "$LAT_NUM" -gt 3000 ] 2>/dev/null; then
        LAT_COLOR="$RED"
    elif [ -n "$LAT_NUM" ] && [ "$LAT_NUM" -gt 1000 ] 2>/dev/null; then
        LAT_COLOR="$YELLOW"
    elif [ -n "$LAT_NUM" ] && [ "$LAT_NUM" -gt 500 ] 2>/dev/null; then
        LAT_COLOR="$BLUE"
    elif [ -n "$LAT_NUM" ] && [ "$LAT_NUM" -gt 100 ] 2>/dev/null; then
        LAT_COLOR="$GREEN"
    elif [ -n "$LAT_NUM" ]; then
        LAT_COLOR="$MAGENTA"
    else
        LAT_COLOR="$YELLOW"
    fi
    printf "  4K 平均延迟   : ${LAT_COLOR}${RR_LAT_US} µs${RESET}\n"
else
    printf "  4K 平均延迟   : ${YELLOW}${RR_LAT_US} µs${RESET}\n"
fi

# 64K 顺序读
if [ "$SR_BW" != "unknown" ]; then
    # 提取带宽数字部分
    BW_NUM=$(echo "$SR_BW" | awk 'BEGIN {FS="."} {print $1}')
    if [ -n "$BW_NUM" ] && [ "$BW_NUM" -lt 50 ] 2>/dev/null; then
        BW_COLOR="$RED"
    elif [ -n "$BW_NUM" ] && [ "$BW_NUM" -lt 200 ] 2>/dev/null; then
        BW_COLOR="$YELLOW"
    elif [ -n "$BW_NUM" ] && [ "$BW_NUM" -lt 500 ] 2>/dev/null; then
        BW_COLOR="$GREEN"
    elif [ -n "$BW_NUM" ]; then
        BW_COLOR="$MAGENTA"
    else
        BW_COLOR="$GREEN"
    fi
    printf "  64K 顺序读    : ${BW_COLOR}${SR_BW} MiB/s${RESET}\n"
else
    printf "  64K 顺序读    : ${YELLOW}${SR_BW} MiB/s${RESET}\n"
fi

# 4K 混合 IOPS
if [ "$RW_IOPS" -lt $((RR_IOPS / 3)) ]; then
    printf "  4K 混合 IOPS  : ${RED}$RW_IOPS${RESET}\n"
else
    printf "  4K 混合 IOPS  : ${GREEN}$RW_IOPS${RESET}\n"
fi

printf "\n"
printf "${GREEN}=== 测试完成（缓存已清理） ===${RESET}\n"

printf "${CYAN}=== 判定区间参考说明（人工校验用） ===${RESET}\n"
printf "4K 随机读 IOPS：\n"
printf "  ${RED}< 500${RESET}         → HDD / 冷数据盘\n"
printf "  ${YELLOW}500–1500${RESET}      → 严重限速云盘\n"
printf "  ${BLUE}1500–5000${RESET}     → 普通 SSD 云盘（共享）\n"
printf "  ${GREEN}5000–30000${RESET}    → 高性能 SSD 云盘\n"
printf "  ${MAGENTA}> 30000${RESET}       → NVMe 云盘 / 本地 NVMe\n"
printf "\n"
printf "4K 平均延迟 clat（µs）：\n"
printf "  ${RED}> 3000 µs${RESET}     → HDD / 严重拥塞\n"
printf "  ${YELLOW}1000–3000 µs${RESET}  → 限速 / 队列阻塞\n"
printf "  ${BLUE}500–1000 µs${RESET}   → 普通 SSD\n"
printf "  ${GREEN}100–500 µs${RESET}    → 高性能 SSD\n"
printf "  ${MAGENTA}< 100 µs${RESET}      → NVMe 级别\n"
