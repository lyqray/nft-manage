#!/bin/bash

# nftables 管理脚本
CONFIG_DIR="/etc/nftables"  # 规则文件目录
MAIN_CONFIG="/etc/nftables.conf"  # 主配置文件
SCRIPT_RULES_FILE="$CONFIG_DIR/script-rules.nft"  # 脚本生成的规则文件

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 检查root权限
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}请使用sudo运行此脚本${NC}"
        exit 1
    fi
}

# 检测Linux发行版
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif [ -f /etc/alpine-release ]; then
        echo "alpine"
    else
        # 回退到包管理器检测
        if command -v apt &> /dev/null; then
            echo "debian"
        elif command -v yum &> /dev/null; then
            echo "centos"
        elif command -v dnf &> /dev/null; then
            echo "fedora"
        elif command -v zypper &> /dev/null; then
            echo "opensuse"
        elif command -v pacman &> /dev/null; then
            echo "arch"
        elif command -v apk &> /dev/null; then
            echo "alpine"
        else
            echo "unknown"
        fi
    fi
}

# 检测nftables是否安装
check_nft_installed() {
    if ! command -v nft &> /dev/null; then
        echo -e "${RED}nftables 未安装${NC}"
        local distro=$(detect_distro)
        echo -e "${YELLOW}检测到系统: $distro${NC}"
        
        read -p "是否安装 nftables？(y/N): " install_choice
        
        if [[ "$install_choice" == "y" || "$install_choice" == "Y" ]]; then
            install_nftables "$distro"
        else
            echo -e "${RED}脚本需要 nftables 才能运行，退出${NC}"
            exit 1
        fi
    else
        echo -e "${GREEN}nftables 已安装${NC}"
    fi
}

# 安装nftables
install_nftables() {
    local distro="$1"
    echo -e "${YELLOW}正在安装 nftables...${NC}"
    
    case "$distro" in
        debian|ubuntu)
            apt-get update
            apt-get install -y nftables
            ;;
        centos|rhel|rocky|almalinux)
            if command -v dnf &> /dev/null; then
                dnf install -y nftables
            else
                yum install -y nftables
            fi
            ;;
        fedora)
            dnf install -y nftables
            ;;
        opensuse*|suse)
            zypper install -y nftables
            ;;
        arch|manjaro)
            pacman -S --noconfirm nftables
            ;;
        alpine)
            apk update
            apk add nftables
            ;;
        *)
            echo -e "${RED}无法自动识别系统类型${NC}"
            echo -e "${YELLOW}请尝试手动安装 nftables：${NC}"
            echo "Debian/Ubuntu: apt install nftables"
            echo "CentOS/RHEL: yum install nftables"
            echo "Fedora: dnf install nftables"
            echo "openSUSE: zypper install nftables"
            echo "Arch Linux: pacman -S nftables"
            echo "Alpine Linux: apk add nftables"
            exit 1
            ;;
    esac
    
    # 检查安装是否成功
    if command -v nft &> /dev/null; then
        echo -e "${GREEN}nftables 安装成功${NC}"
        
        # 智能服务管理
        if command -v systemctl &> /dev/null; then
            systemctl enable nftables --now 2>/dev/null && \
            echo -e "${GREEN}nftables 服务已启用并启动 (systemd)${NC}"
        elif command -v rc-update &> /dev/null; then
            rc-update add nftables default 2>/dev/null
            rc-service nftables start 2>/dev/null && \
            echo -e "${GREEN}nftables 服务已启用并启动 (OpenRC)${NC}"
        elif [ -f /etc/init.d/nftables ]; then
            /etc/init.d/nftables start && \
            echo -e "${GREEN}nftables 服务已启动 (init.d)${NC}"
        else
            echo -e "${YELLOW}无法自动启动服务，请手动启动 nftables${NC}"
        fi
    else
        echo -e "${RED}nftables 安装失败${NC}"
        exit 1
    fi
}

# Alpine Linux 特定的配置检查
check_alpine_config() {
    if [ -f /etc/alpine-release ] && command -v rc-update &> /dev/null; then
        echo -e "${BLUE}检测到 Alpine Linux${NC}"
        
        if ! rc-update show | grep -q nftables; then
            echo -e "${YELLOW}nftables 未添加到默认运行级别${NC}"
            read -p "是否要添加 nftables 到默认运行级别？(y/N): " alpine_choice
            if [[ "$alpine_choice" == "y" || "$alpine_choice" == "Y" ]]; then
                rc-update add nftables default
                echo -e "${GREEN}nftables 已添加到默认运行级别${NC}"
            fi
        fi
    fi
}

# 自动检测默认路由接口
detect_wan_interface() {
    # 尝试多种方法检测外网接口
    local iface
    
    # 方法1: 通过默认路由检测
    iface=$(ip route show default 2>/dev/null | awk '/default/ {print $5}')
    
    # 方法2: 通过非lo接口检测
    if [ -z "$iface" ]; then
        iface=$(ip link show | grep -E "^[0-9]+:" | grep -v "lo:" | awk -F: '{print $2}' | tr -d ' ' | head -1)
    fi
    
    # 方法3: 通过网络配置文件检测
    if [ -z "$iface" ]; then
        if [ -f /etc/netplan/*.yaml ]; then
            iface=$(grep -r "eth\|ens\|enp" /etc/netplan/ | head -1 | awk '{print $2}' | tr -d ':')
        fi
    fi
    
    # 默认回退到eth0
    echo "${iface:-eth0}"
}

# 网络接口配置
WAN_IFACE=$(detect_wan_interface)

# 验证端口格式（支持单个端口和端口范围）
validate_port() {
    local port="$1"
    # 支持单个端口：123 或 端口范围：100-200
    if [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" =~ ^[0-9]+-[0-9]+$ ]]; then
        return 0
    else
        return 1
    fi
}

# 创建配置目录和文件
create_config_structure() {
    if [ ! -d "$CONFIG_DIR" ]; then
        mkdir -p "$CONFIG_DIR"
        echo -e "${GREEN}创建配置目录: $CONFIG_DIR${NC}"
    fi
    
    # 创建规则文件（如果不存在）
    if [ ! -f "$SCRIPT_RULES_FILE" ]; then
        cat > "$SCRIPT_RULES_FILE" << 'EOF'
#!/usr/sbin/nft -f

# 脚本管理的表 - 不影响其他服务
table inet script_filter {
    chain input {
        type filter hook input priority 10; policy accept;
    }
}

table inet script_nat {
    chain prerouting {
        type nat hook prerouting priority 10;
    }
    
    chain postrouting {
        type nat hook postrouting priority 100;
    }
}
EOF
        echo -e "${GREEN}创建规则文件: $SCRIPT_RULES_FILE${NC}"
    fi
    
    # 确保主配置文件包含我们的规则文件
    if [ ! -f "$MAIN_CONFIG" ]; then
        cat > "$MAIN_CONFIG" << EOF
#!/usr/sbin/nft -f

# 包含系统规则文件
include "/etc/nftables.conf.d/*.nft"

# 脚本自定义规则文件
include "$SCRIPT_RULES_FILE"
EOF
        echo -e "${GREEN}创建主配置文件: $MAIN_CONFIG${NC}"
    elif ! grep -q "include \"$SCRIPT_RULES_FILE\"" "$MAIN_CONFIG" 2>/dev/null; then
        # 在主配置文件末尾添加包含规则和注释
        echo -e "\n# 脚本自定义规则文件\ninclude \"$SCRIPT_RULES_FILE\"" >> "$MAIN_CONFIG"
        echo -e "${GREEN}在主配置文件末尾添加包含规则${NC}"
    fi
}

# 查看当前所有nft规则
show_rules() {
    echo -e "${YELLOW}=== 当前nftables规则 ===${NC}"
    nft list ruleset
    echo -e "${YELLOW}=======================${NC}"
}

# 应用规则文件
apply_rules_file() {
    if [ -f "$SCRIPT_RULES_FILE" ]; then
        # 只刷新脚本管理的表，不影响其他服务
        nft flush table inet script_filter 2>/dev/null
        nft flush table inet script_nat 2>/dev/null
        nft delete table inet script_filter 2>/dev/null
        nft delete table inet script_nat 2>/dev/null
        
        nft -f "$SCRIPT_RULES_FILE"
        echo -e "${GREEN}已应用规则文件: $SCRIPT_RULES_FILE${NC}"
    else
        echo -e "${RED}规则文件不存在: $SCRIPT_RULES_FILE${NC}"
    fi
}

# 在规则文件中添加规则
add_rule_to_file() {
    local table="$1"
    local chain="$2"
    local rule="$3"
    
    # 使用awk来安全地添加规则
    local temp_file=$(mktemp)
    
    awk -v table="$table" -v chain="$chain" -v rule="$rule" '
    BEGIN { in_target_table = 0; in_target_chain = 0; inserted = 0 }
    
    # 匹配目标表
    $0 ~ "^table " table " {$" {
        in_target_table = 1
        print $0
        next
    }
    
    # 在目标表中匹配目标链
    in_target_table && $0 ~ "chain " chain " {$" {
        in_target_chain = 1
        print $0
        next
    }
    
    # 在目标链中插入规则（在右花括号前）
    in_target_table && in_target_chain && /^    }$/ {
        print "        " rule
        print $0
        inserted = 1
        in_target_chain = 0
        next
    }
    
    # 表结束
    in_target_table && /^}$/ {
        in_target_table = 0
    }
    
    { print $0 }
    
    END {
        if (!inserted) {
            print "// 规则插入失败: " rule > "/dev/stderr"
        }
    }
    ' "$SCRIPT_RULES_FILE" > "$temp_file"
    
    if [ $? -eq 0 ] && grep -q "$rule" "$temp_file"; then
        mv "$temp_file" "$SCRIPT_RULES_FILE"
        return 0
    else
        rm -f "$temp_file"
        return 1
    fi
}

# 从文件中删除规则
delete_rule_from_file() {
    local pattern="$1"
    if [ -f "$SCRIPT_RULES_FILE" ]; then
        sed -i "/$pattern/d" "$SCRIPT_RULES_FILE"
    fi
}

# 清空所有规则（只清空脚本管理的规则）
clear_all_rules() {
    echo -e "${YELLOW}清空所有脚本管理的规则${NC}"
    echo -e "${RED}警告: 这将删除所有脚本添加的端口转发和端口访问控制规则！${NC}"
    echo -e "${BLUE}注意: 不会影响其他服务（如fail2ban、docker等）添加的规则${NC}"
    read -p "确定要清空所有脚本规则吗？(y/N): " confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${YELLOW}已取消清空操作${NC}"
        return
    fi
    
    # 创建临时文件，只保留表结构，删除所有自定义规则
    local temp_file=$(mktemp)
    
    awk '
    BEGIN { in_table = 0; in_chain = 0 }
    
    # 匹配表开始
    /^table / {
        in_table = 1
        print $0
        next
    }
    
    # 表结束
    in_table && /^}$/ {
        in_table = 0
        print $0
        next
    }
    
    # 匹配链开始
    in_table && /chain [^ ]+ {/ {
        in_chain = 1
        print $0
        next
    }
    
    # 链结束
    in_chain && /^    }$/ {
        in_chain = 0
        print $0
        next
    }
    
    # 跳过所有规则行（保留链定义和表结构）
    in_chain && /^        [^}]/ && !/type filter hook/ && !/type nat hook/ {
        # 跳过规则行，但保留hook定义
        next
    }
    
    { print $0 }
    ' "$SCRIPT_RULES_FILE" > "$temp_file"
    
    if [ $? -eq 0 ]; then
        mv "$temp_file" "$SCRIPT_RULES_FILE"
        # 重新应用规则
        apply_rules_file
        echo -e "${GREEN}已清空所有脚本管理的规则${NC}"
        echo -e "${YELLOW}所有脚本添加的端口转发和访问控制规则已被删除${NC}"
    else
        rm -f "$temp_file"
        echo -e "${RED}清空规则失败${NC}"
    fi
}

# 添加端口转发
add_port_forward() {
    echo -e "${YELLOW}添加端口转发${NC}"
    echo -e "${BLUE}提示: 按回车默认使用本地转发(127.0.0.1)${NC}"
    echo -e "${BLUE}支持单个端口(80)或端口范围(1000-2000)${NC}"
    read -p "请输入外部端口: " ext_port
    read -p "请输入目标IP(默认127.0.0.1): " target_ip
    target_ip=${target_ip:-127.0.0.1}
    read -p "请输入目标端口: " target_port
    read -p "请输入协议(tcp/udp, 默认tcp): " protocol
    protocol=${protocol:-tcp}
    
    # 验证端口格式
    if ! validate_port "$ext_port" || ! validate_port "$target_port"; then
        echo -e "${RED}错误: 端口格式不正确，请使用数字或范围(如100-200)${NC}"
        return 1
    fi
    
    # 添加到规则文件 - 使用正确的nftables语法
    add_rule_to_file "inet script_nat" "prerouting" "ip protocol ${protocol} ${protocol} dport ${ext_port} counter dnat to ${target_ip}:${target_port}"
    if [ $? -eq 0 ]; then
        add_rule_to_file "inet script_nat" "postrouting" "ip daddr ${target_ip} ${protocol} dport ${target_port} counter masquerade"
    fi
    
    # 应用新规则
    apply_rules_file
    
    echo -e "${GREEN}端口转发已添加: ${NC}"
    echo -e "外部端口: ${ext_port}/${protocol}"
    echo -e "目标地址: ${target_ip}:${target_port}"
    if [ "$target_ip" = "127.0.0.1" ]; then
        echo -e "类型: ${BLUE}本地端口转发${NC}"
    else
        echo -e "类型: ${GREEN}远程端口转发${NC}"
    fi
}

# 删除端口转发
delete_port_forward() {
    echo -e "${YELLOW}删除端口转发${NC}"
    echo -e "${BLUE}支持单个端口(80)或端口范围(1000-2000)${NC}"
    read -p "请输入要删除的外部端口: " ext_port
    read -p "请输入协议(tcp/udp, 默认tcp): " protocol
    protocol=${protocol:-tcp}
    
    # 验证端口格式
    if ! validate_port "$ext_port"; then
        echo -e "${RED}错误: 端口格式不正确，请使用数字或范围(如100-200)${NC}"
        return 1
    fi
    
    # 首先获取目标IP和端口信息，用于删除对应的masquerade规则
    local target_info=""
    if [ -f "$SCRIPT_RULES_FILE" ]; then
        target_info=$(awk -v port="$ext_port" -v proto="$protocol" '
        /chain prerouting {/,/^    }/ {
            if ($0 ~ "dport " port ".*dnat to") {
                # 提取目标IP和端口
                for (i=1; i<=NF; i++) {
                    if ($i == "to") {
                        target = $(i+1)
                        gsub(/;$/, "", target)
                        print target
                        break
                    }
                }
            }
        }' "$SCRIPT_RULES_FILE")
    fi
    
    echo -e "${BLUE}正在删除端口转发规则...${NC}"
    
    # 从文件中删除prerouting链的DNAT规则
    delete_rule_from_file "dport ${ext_port}.*dnat to"
    delete_rule_from_file "ip protocol ${protocol} ${protocol} dport ${ext_port}.*dnat"
    
    # 删除postrouting链的masquerade规则
    if [ -n "$target_info" ]; then
        # 如果有目标信息，删除对应的masquerade规则
        local target_ip=$(echo "$target_info" | cut -d: -f1)
        local target_port=$(echo "$target_info" | cut -d: -f2)
        
        echo -e "${BLUE}删除目标地址 ${target_ip}:${target_port} 的masquerade规则${NC}"
        delete_rule_from_file "ip daddr ${target_ip} ${protocol} dport ${target_port}.*masquerade"
        delete_rule_from_file "daddr ${target_ip}.*dport ${target_port}.*masquerade"
    else
        # 如果没有目标信息，使用更通用的模式删除
        echo -e "${YELLOW}无法获取目标信息，使用通用模式删除masquerade规则${NC}"
        delete_rule_from_file "dport ${ext_port}.*masquerade"
        delete_rule_from_file "ip daddr.*dport ${ext_port}.*masquerade"
    fi
    
    # 重新加载规则文件
    apply_rules_file
    
    echo -e "${GREEN}已删除端口 ${ext_port}/${protocol} 的转发规则${NC}"
    
    # 显示剩余的端口转发规则
    local remaining_rules=$(grep -c "dport.*dnat" "$SCRIPT_RULES_FILE" 2>/dev/null || echo "0")
    echo -e "${BLUE}剩余端口转发规则: ${remaining_rules} 条${NC}"
}

# 允许端口访问
allow_port() {
    echo -e "${YELLOW}允许端口访问${NC}"
    echo -e "${BLUE}支持单个端口(80)或端口范围(1000-2000)${NC}"
    read -p "请输入端口号: " port
    read -p "请输入协议(tcp/udp, 默认tcp): " protocol
    protocol=${protocol:-tcp}
    
    # 验证端口格式
    if ! validate_port "$port"; then
        echo -e "${RED}错误: 端口格式不正确，请使用数字或范围(如100-200)${NC}"
        return 1
    fi
    
    # 添加到规则文件
    add_rule_to_file "inet script_filter" "input" "ip protocol ${protocol} ${protocol} dport ${port} ct state new accept"
    
    # 应用新规则
    apply_rules_file
    
    echo -e "${GREEN}已允许端口: ${port}/${protocol}${NC}"
}

# 拒绝端口访问
deny_port() {
    echo -e "${YELLOW}拒绝端口访问${NC}"
    echo -e "${BLUE}支持单个端口(80)或端口范围(1000-2000)${NC}"
    read -p "请输入端口号: " port
    read -p "请输入协议(tcp/udp, 默认tcp): " protocol
    protocol=${protocol:-tcp}
    
    # 验证端口格式
    if ! validate_port "$port"; then
        echo -e "${RED}错误: 端口格式不正确，请使用数字或范围(如100-200)${NC}"
        return 1
    fi
    
    # 删除允许规则（如果存在）
    delete_rule_from_file "dport ${port}.*accept"
    
    # 添加拒绝规则
    add_rule_to_file "inet script_filter" "input" "ip protocol ${protocol} ${protocol} dport ${port} drop"
    
    # 重新加载规则文件
    apply_rules_file
    
    echo -e "${GREEN}已拒绝端口: ${port}/${protocol}${NC}"
}

# 删除访问规则
delete_access_rule() {
    echo -e "${YELLOW}删除访问规则${NC}"
    echo -e "${BLUE}支持单个端口(80)或端口范围(1000-2000)${NC}"
    read -p "请输入要删除规则的端口: " port
    read -p "请输入协议(tcp/udp, 默认tcp): " protocol
    protocol=${protocol:-tcp}
    
    # 验证端口格式
    if ! validate_port "$port"; then
        echo -e "${RED}错误: 端口格式不正确，请使用数字或范围(如100-200)${NC}"
        return 1
    fi
    
    # 从文件中删除相关规则
    delete_rule_from_file "dport ${port}.*accept"
    delete_rule_from_file "dport ${port}.*drop"
    delete_rule_from_file "dport ${port}.*reject"
    
    # 重新加载规则文件
    apply_rules_file
    
    echo -e "${GREEN}已删除端口 ${port}/${protocol} 的访问规则${NC}"
    echo -e "${BLUE}注意: 删除规则后，该端口的访问将遵循默认策略${NC}"
}

# 列出所有规则（包括端口转发和访问控制）
list_all_rules() {
    echo -e "${YELLOW}=== 当前所有脚本管理的规则 ===${NC}"
    
    if [ -f "$SCRIPT_RULES_FILE" ]; then
        # 显示端口转发规则
        echo -e "${BLUE}--- 端口转发规则 ---${NC}"
        local has_forward_rules=0
        awk '/chain prerouting {/,/^    }/ {if (/dnat to/) print}' "$SCRIPT_RULES_FILE" | while read -r line; do
            ext_port=$(echo "$line" | grep -oE "dport [0-9]+(-[0-9]+)?" | awk '{print $2}')
            protocol=$(echo "$line" | grep -oE "tcp|udp")
            target=$(echo "$line" | grep -oE "to [^;]+" | sed 's/to //')
            
            if [ -n "$ext_port" ] && [ -n "$target" ]; then
                if echo "$target" | grep -q "127.0.0.1"; then
                    type_label="${BLUE}[本地转发]${NC}"
                else
                    type_label="${GREEN}[远程转发]${NC}"
                fi
                echo -e "转发: ${ext_port}/${protocol} -> ${target} $type_label"
                has_forward_rules=1
            fi
        done
        
        if [ $has_forward_rules -eq 0 ]; then
            echo -e "${YELLOW}无端口转发规则${NC}"
        fi
        
        echo
        
        # 显示端口访问控制规则
        echo -e "${BLUE}--- 端口访问控制规则 ---${NC}"
        local has_access_rules=0
        
        # 检查input链中的accept规则
        awk '/chain input {/,/^    }/ {if (/accept/ && /dport/) print}' "$SCRIPT_RULES_FILE" | while read -r line; do
            port=$(echo "$line" | grep -oE "dport [0-9]+(-[0-9]+)?" | awk '{print $2}')
            protocol=$(echo "$line" | grep -oE "tcp|udp")
            
            if [ -n "$port" ]; then
                echo -e "允许: ${port}/${protocol} ${GREEN}[允许访问]${NC}"
                has_access_rules=1
            fi
        done
        
        # 检查拒绝规则
        awk '/chain input {/,/^    }/ {if (/drop/ && /dport/) print}' "$SCRIPT_RULES_FILE" | while read -r line; do
            port=$(echo "$line" | grep -oE "dport [0-9]+(-[0-9]+)?" | awk '{print $2}')
            protocol=$(echo "$line" | grep -oE "tcp|udp")
            
            if [ -n "$port" ] && [ -n "$protocol" ]; then
                echo -e "拒绝: ${port}/${protocol} ${RED}[拒绝访问]${NC}"
                has_access_rules=1
            fi
        done
        
        if [ $has_access_rules -eq 0 ]; then
            echo -e "${YELLOW}无端口访问控制规则${NC}"
        fi
        
    else
        echo -e "${RED}规则文件不存在${NC}"
    fi
    
    echo -e "${YELLOW}====================${NC}"
}

# 重新加载规则（只重新加载脚本规则）
reload_rules() {
    echo -e "${YELLOW}重新加载脚本规则${NC}"
    echo -e "${BLUE}注意: 只重新加载脚本管理的规则，不影响其他服务${NC}"
    
    # 只刷新脚本管理的表
    nft flush table inet script_filter 2>/dev/null
    nft flush table inet script_nat 2>/dev/null
    nft delete table inet script_filter 2>/dev/null
    nft delete table inet script_nat 2>/dev/null
    
    # 重新加载脚本规则文件
    if [ -f "$SCRIPT_RULES_FILE" ]; then
        nft -f "$SCRIPT_RULES_FILE"
        echo -e "${GREEN}脚本规则已重新加载${NC}"
    else
        echo -e "${RED}脚本规则文件不存在${NC}"
        return 1
    fi
    
    echo -e "${BLUE}当前活动的规则表:${NC}"
    nft list tables
}

# 添加nft自启（防止重启失效）
enable_autostart() {
    if command -v systemctl &> /dev/null; then
        if systemctl enable nftables 2>/dev/null; then
            echo -e "${GREEN}nftables开机自启已启用 (systemd)${NC}"
        else
            echo -e "${RED}启用开机自启失败${NC}"
        fi
    elif command -v rc-update &> /dev/null; then
        # Alpine Linux (OpenRC)
        if rc-update add nftables default 2>/dev/null; then
            echo -e "${GREEN}nftables开机自启已启用 (OpenRC)${NC}"
        else
            echo -e "${RED}启用开机自启失败${NC}"
        fi
    else
        echo -e "${YELLOW}无法确定init系统，请手动设置开机自启${NC}"
    fi
    
    echo -e "${BLUE}可以使用以下命令管理:${NC}"
    if command -v systemctl &> /dev/null; then
        echo "systemctl status nftables  # 查看状态"
        echo "systemctl disable nftables # 禁用自启"
        echo "systemctl start nftables   # 启动服务"
        echo "systemctl stop nftables    # 停止服务"
    elif command -v rc-update &> /dev/null; then
        echo "rc-service nftables status  # 查看状态"
        echo "rc-update del nftables      # 禁用自启"
        echo "rc-service nftables start   # 启动服务"
        echo "rc-service nftables stop    # 停止服务"
    fi
}

# 显示菜单
show_menu() {
    echo -e "${GREEN}=== nftables 管理脚本 ===${NC}"
    echo "1. 查看当前所有nft规则"
    echo "2. 添加端口转发"
    echo "3. 删除端口转发"
    echo "4. 允许端口访问"
    echo "5. 拒绝端口访问"
    echo "6. 删除访问规则"
    echo "7. 列出所有脚本规则"
    echo "8. 清空所有脚本规则"
    echo "9. 重新加载脚本规则"
    echo "10. 添加nft自启（防止重启失效）"
    echo "0. 退出"
    echo -e "${GREEN}=======================${NC}"
}

# 主循环
main() {
    check_root
    check_nft_installed
    check_alpine_config
    create_config_structure
    
    while true; do
        show_menu
        read -p "请选择操作 [0-10]: " choice
        
        case $choice in
            1) show_rules ;;
            2) add_port_forward ;;
            3) delete_port_forward ;;
            4) allow_port ;;
            5) deny_port ;;
            6) delete_access_rule ;;
            7) list_all_rules ;;
            8) clear_all_rules ;;
            9) reload_rules ;;
            10) enable_autostart ;;
            0) echo "再见！"; exit 0 ;;
            *) echo -e "${RED}无效选择${NC}" ;;
        esac
        
        echo
        read -p "按回车键继续..."
        clear
    done
}

# 启动脚本
clear
main
