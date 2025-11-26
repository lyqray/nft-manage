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

# 验证单个端口格式
validate_single_port() {
    local port="$1"
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        return 0
    else
        return 1
    fi
}

# 验证端口范围格式
validate_port_range() {
    local port_range="$1"
    if [[ "$port_range" =~ ^[0-9]+-[0-9]+$ ]]; then
        local start_port=$(echo "$port_range" | cut -d'-' -f1)
        local end_port=$(echo "$port_range" | cut -d'-' -f2)
        if [ "$start_port" -le "$end_port" ] && [ "$start_port" -ge 1 ] && [ "$end_port" -le 65535 ]; then
            return 0
        fi
    fi
    return 1
}

# 验证端口格式（支持单个端口、端口范围和逗号分隔）
validate_port() {
    local port_input="$1"
    
    # 如果包含逗号，分割验证每个部分
    if [[ "$port_input" == *","* ]]; then
        IFS=',' read -ra port_parts <<< "$port_input"
        for part in "${port_parts[@]}"; do
            local trimmed_part=$(echo "$part" | xargs)  # 去除空格
            if ! validate_single_port "$trimmed_part" && ! validate_port_range "$trimmed_part"; then
                return 1
            fi
        done
        return 0
    else
        # 单个端口或端口范围
        if validate_single_port "$port_input" || validate_port_range "$port_input"; then
            return 0
        else
            return 1
        fi
    fi
}

# 解析端口输入为数组
parse_port_input() {
    local port_input="$1"
    local -n port_array="$2"  # 使用nameref传递数组
    
    if [[ "$port_input" == *","* ]]; then
        IFS=',' read -ra temp_array <<< "$port_input"
        for part in "${temp_array[@]}"; do
            local trimmed_part=$(echo "$part" | xargs)  # 去除空格
            port_array+=("$trimmed_part")
        done
    else
        port_array+=("$port_input")
    fi
}

# 获取公网IPv6地址
get_public_ipv6() {
    # 尝试多种方法获取公网IPv6
    local ipv6
    
    # 方法1: 通过ip命令获取非link-local地址
    ipv6=$(ip -6 addr show scope global | grep inet6 | awk '{print $2}' | cut -d'/' -f1 | head -1)
    
    # 方法2: 通过外部服务获取（如果有网络连接）
    if [ -z "$ipv6" ]; then
        ipv6=$(curl -6 -s ifconfig.co 2>/dev/null || echo "")
    fi
    
    echo "$ipv6"
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

# 脚本管理的表（不影响其他服务）
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

# 脚本管理的表 - IPv6专用NAT表（不影响其他服务）
table ip6 script_nat {
    chain prerouting {
        type nat hook prerouting priority 0;
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
        nft flush table ip6 script_nat 2>/dev/null
        nft delete table inet script_filter 2>/dev/null
        nft delete table inet script_nat 2>/dev/null
        nft delete table ip6 script_nat 2>/dev/null
        
        nft -f "$SCRIPT_RULES_FILE"
        echo -e "${GREEN}已应用规则文件: $SCRIPT_RULES_FILE${NC}"
    else
        echo -e "${RED}规则文件不存在: $SCRIPT_RULES_FILE${NC}"
    fi
}

# 清理空的表和链
cleanup_empty_tables() {
    if [ ! -f "$SCRIPT_RULES_FILE" ]; then
        return 0
    fi
    
    local temp_file=$(mktemp)
    local in_table=0
    local current_table=""
    local table_content=""
    local has_rules=0
    
    # 读取原文件
    while IFS= read -r line; do
        # 检测表开始
        if [[ "$line" =~ ^table[[:space:]]+([^[:space:]]+)[[:space:]]+([^[:space:]]+)[[:space:]]*\{[[:space:]]*$ ]]; then
            if [ $in_table -eq 1 ]; then
                # 结束上一个表
                if [ $has_rules -eq 1 ]; then
                    echo "$table_content" >> "$temp_file"
                    echo "}" >> "$temp_file"
                fi
            fi
            
            in_table=1
            current_table="${BASH_REMATCH[1]} ${BASH_REMATCH[2]}"
            table_content="$line"
            has_rules=0
            continue
        fi
        
        # 在表中
        if [ $in_table -eq 1 ]; then
            table_content="$table_content"$'\n'"$line"
            
            # 检测表结束
            if [[ "$line" =~ ^[[:space:]]*}[[:space:]]*$ ]]; then
                if [ $has_rules -eq 1 ]; then
                    echo "$table_content" >> "$temp_file"
                fi
                in_table=0
                current_table=""
                table_content=""
                has_rules=0
            # 检测是否有实际规则（非空行、非注释、非仅包含链定义）
            elif [[ "$line" =~ ^[[:space:]]+[^[:space:]#] ]] && [[ ! "$line" =~ chain[[:space:]]+[^[:space:]]+[[:space:]]*\{[[:space:]]*$ ]] && [[ ! "$line" =~ ^[[:space:]]*$ ]]; then
                has_rules=1
            fi
        else
            # 不在表中，直接写入
            echo "$line" >> "$temp_file"
        fi
    done < "$SCRIPT_RULES_FILE"
    
    # 处理最后一个表
    if [ $in_table -eq 1 ] && [ $has_rules -eq 1 ]; then
        echo "$table_content" >> "$temp_file"
    fi
    
    # 替换原文件
    mv "$temp_file" "$SCRIPT_RULES_FILE"
}

# 在规则文件中添加规则（修复版，避免创建空表）
add_rule_to_file() {
    local table="$1"
    local chain="$2"
    local rule="$3"
    
    local temp_file=$(mktemp)
    local rule_inserted=0
    local table_found=0
    local chain_found=0
    
    # 读取文件并插入规则
    while IFS= read -r line; do
        echo "$line" >> "$temp_file"
        
        # 找到目标表
        if [[ "$line" =~ ^table[[:space:]]+$table[[:space:]]*\{[[:space:]]*$ ]]; then
            table_found=1
        fi
        
        # 在目标表中找到目标链
        if [ $table_found -eq 1 ] && [[ "$line" =~ ^[[:space:]]*chain[[:space:]]+$chain[[:space:]]*\{[[:space:]]*$ ]] && [ $rule_inserted -eq 0 ]; then
            chain_found=1
            # 读取下一行（应该是链的内容开始）
            while IFS= read -r next_line; do
                echo "$next_line" >> "$temp_file"
                
                # 如果遇到规则行（有缩进）或者链的结束，就在之前插入我们的规则
                if [[ "$next_line" =~ ^[[:space:]]+[^}] ]] || [[ "$next_line" =~ ^[[:space:]]*}[[:space:]]*$ ]]; then
                    echo "        $rule" >> "$temp_file"
                    rule_inserted=1
                    break
                fi
            done
        fi
    done < "$SCRIPT_RULES_FILE"
    
    # 如果没找到表或链，不自动创建（避免产生空表）
    if [[ $rule_inserted -eq 0 ]]; then
        rm -f "$temp_file"
        echo -e "${RED}错误: 在表 $table 中找不到链 $chain${NC}"
        echo -e "${YELLOW}请先确保表结构正确创建${NC}"
        return 1
    fi
    
    if [[ $rule_inserted -eq 1 ]]; then
        mv "$temp_file" "$SCRIPT_RULES_FILE"
        return 0
    else
        rm -f "$temp_file"
        return 1
    fi
}

# 从文件中删除规则（修复版，保留空行）
delete_rule_from_file() {
    local pattern="$1"
    if [ -f "$SCRIPT_RULES_FILE" ]; then
        # 使用更精确的匹配，避免误删，保留空行
        grep -v "$pattern" "$SCRIPT_RULES_FILE" > "${SCRIPT_RULES_FILE}.tmp" && mv "${SCRIPT_RULES_FILE}.tmp" "$SCRIPT_RULES_FILE"
        
        # 删除后清理空表
        cleanup_empty_tables
    fi
}

# 清空所有规则（只清空脚本管理的规则）
clear_all_rules() {
    echo -e "${YELLOW}清空所有脚本管理的规则${NC}"
    echo -e "${RED}警告: 这将删除所有脚本添加的端口转发和入站控制规则！${NC}"
    echo -e "${BLUE}注意: 不会影响其他服务（如fail2ban、docker等）添加的规则${NC}"
    read -p "确定要清空所有脚本规则吗？(y/N): " confirm
    
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${YELLOW}已取消清空操作${NC}"
        return
    fi
    
    # 重新创建基础表结构
    cat > "$SCRIPT_RULES_FILE" << 'EOF'
#!/usr/sbin/nft -f

# 脚本管理的表（不影响其他服务）
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

# 脚本管理的表 - IPv6专用NAT表（不影响其他服务）
table ip6 script_nat {
    chain prerouting {
        type nat hook prerouting priority 0;
    }
    
    chain postrouting {
        type nat hook postrouting priority 100;
    }
}
EOF
    
    # 重新应用规则
    apply_rules_file
    echo -e "${GREEN}已清空所有脚本管理的规则${NC}"
}

# 添加端口转发（增强版，支持批量端口和all协议）
add_port_forward() {
    echo -e "${YELLOW}添加端口转发${NC}"
    echo -e "${BLUE}提示: 按回车默认使用本地转发(127.0.0.1或::1)${NC}"
    echo -e "${BLUE}支持格式:${NC}"
    echo -e "  ${GREEN}单个端口:${NC} 80"
    echo -e "  ${GREEN}端口范围:${NC} 1000-2000"  
    echo -e "  ${GREEN}多个端口:${NC} 80,443,1000-2000,3000"
    
    read -p "请输入外部端口: " ext_port_input
    read -p "请输入目标IP(默认127.0.0.1): " target_ip
    target_ip=${target_ip:-127.0.0.1}
    read -p "请输入目标端口: " target_port_input
    
    # 协议选择（增加all选项）
    while true; do
        read -p "请输入协议(tcp/udp/all, 默认tcp): " protocol
        protocol=${protocol:-tcp}
        if [[ "$protocol" == "tcp" || "$protocol" == "udp" || "$protocol" == "all" ]]; then
            break
        else
            echo -e "${RED}错误: 协议必须是 tcp、udp 或 all${NC}"
        fi
    done
    
    # 验证外部端口格式
    if ! validate_port "$ext_port_input"; then
        echo -e "${RED}错误: 外部端口格式不正确${NC}"
        echo -e "${YELLOW}支持的格式: 单个端口(80), 端口范围(1000-2000), 多个端口(80,443,1000-2000)${NC}"
        return 1
    fi
    
    # 验证目标端口格式
    if ! validate_port "$target_port_input"; then
        echo -e "${RED}错误: 目标端口格式不正确${NC}"
        echo -e "${YELLOW}支持的格式: 单个端口(80), 端口范围(1000-2000), 多个端口(80,443,1000-2000)${NC}"
        return 1
    fi
    
    # 解析端口输入
    local ext_ports=()
    local target_ports=()
    parse_port_input "$ext_port_input" ext_ports
    parse_port_input "$target_port_input" target_ports
    
    # 检查端口数量匹配
    if [ ${#ext_ports[@]} -ne ${#target_ports[@]} ]; then
        if [ ${#target_ports[@]} -eq 1 ]; then
            # 如果目标端口只有一个，扩展到与外部端口相同数量
            local single_target_port="${target_ports[0]}"
            target_ports=()
            for ((i=0; i<${#ext_ports[@]}; i++)); do
                target_ports+=("$single_target_port")
            done
            echo -e "${BLUE}使用相同目标端口: $single_target_port 用于所有外部端口${NC}"
        else
            echo -e "${RED}错误: 外部端口数量(${#ext_ports[@]})与目标端口数量(${#target_ports[@]})不匹配${NC}"
            echo -e "${YELLOW}请确保端口数量相同，或只提供一个目标端口用于所有外部端口${NC}"
            return 1
        fi
    fi
    
    local protocols=()
    if [ "$protocol" == "all" ]; then
        protocols=("tcp" "udp")
        echo -e "${BLUE}同时添加 TCP 和 UDP 协议规则${NC}"
    else
        protocols=("$protocol")
    fi
    
    local success_count=0
    local total_count=0
    
    # 计算总规则数
    for proto in "${protocols[@]}"; do
        for ((i=0; i<${#ext_ports[@]}; i++)); do
            ((total_count++))
        done
    done
    
    echo -e "${BLUE}即将添加 $total_count 条转发规则...${NC}"
    
    # 添加规则
    for proto in "${protocols[@]}"; do
        for ((i=0; i<${#ext_ports[@]}; i++)); do
            local ext_port="${ext_ports[i]}"
            local target_port="${target_ports[i]}"
            
            # 生成唯一的注释标识（包含协议信息）
            local unique_id="${ext_port}_${proto}_${target_ip}_${target_port}"
            local delete_comment="comment \"${unique_id}\""
            
            # 判断IP类型并构建正确的nftables规则
            local dnat_rule
            local snat_rule=""
            
            if [[ "$target_ip" =~ : ]]; then
                # IPv6规则 - 获取本机公网IPv6
                local public_ipv6=$(get_public_ipv6)
                if [ -z "$public_ipv6" ]; then
                    echo -e "${RED}无法获取公网IPv6地址，请手动输入: ${NC}"
                    read -p "请输入您的公网IPv6地址: " public_ipv6
                    if [ -z "$public_ipv6" ]; then
                        echo -e "${RED}未提供公网IPv6地址，无法创建IPv6转发${NC}"
                        return 1
                    fi
                fi
                
                # IPv6规则语法
                if [ "$proto" = "tcp" ]; then
                    dnat_rule="tcp dport ${ext_port} dnat to [${target_ip}]:${target_port} ${delete_comment}"
                else
                    dnat_rule="udp dport ${ext_port} dnat to [${target_ip}]:${target_port} ${delete_comment}"
                fi
                snat_rule="oifname \"${WAN_IFACE}\" snat to ${public_ipv6} ${delete_comment}"
                
                # 添加到ip6 script_nat表
                if add_rule_to_file "ip6 script_nat" "prerouting" "$dnat_rule"; then
                    add_rule_to_file "ip6 script_nat" "postrouting" "$snat_rule"
                    ((success_count++))
                    echo -e "${GREEN}✓ 添加 IPv6 ${proto} 转发: ${ext_port} -> ${target_ip}:${target_port}${NC}"
                else
                    echo -e "${RED}✗ 添加 IPv6 ${proto} 转发失败: ${ext_port} -> ${target_ip}:${target_port}${NC}"
                fi
                
            else
                # IPv4规则 - 修复inet表DNAT语法
                # 在inet表中必须明确指定ip协议
                if [ "$proto" = "tcp" ]; then
                    dnat_rule="ip protocol tcp tcp dport ${ext_port} dnat to ${target_ip}:${target_port} ${delete_comment}"
                else
                    dnat_rule="ip protocol udp udp dport ${ext_port} dnat to ${target_ip}:${target_port} ${delete_comment}"
                fi
                snat_rule="oifname \"${WAN_IFACE}\" masquerade ${delete_comment}"
                
                # 添加到inet script_nat表
                if add_rule_to_file "inet script_nat" "prerouting" "$dnat_rule"; then
                    add_rule_to_file "inet script_nat" "postrouting" "$snat_rule"
                    ((success_count++))
                    echo -e "${GREEN}✓ 添加 IPv4 ${proto} 转发: ${ext_port} -> ${target_ip}:${target_port}${NC}"
                else
                    echo -e "${RED}✗ 添加 IPv4 ${proto} 转发失败: ${ext_port} -> ${target_ip}:${target_port}${NC}"
                fi
            fi
        done
    done
    
    # 应用新规则
    apply_rules_file
    
    echo -e "${GREEN}端口转发添加完成: ${success_count}/${total_count} 条规则成功${NC}"
    if [ "$target_ip" = "127.0.0.1" ] || [ "$target_ip" = "::1" ]; then
        echo -e "类型: ${BLUE}本地端口转发${NC}"
    else
        echo -e "类型: ${GREEN}远程端口转发${NC}"
    fi
}

# 删除端口转发（增强版，支持批量端口和all协议）
delete_port_forward() {
    echo -e "${YELLOW}删除端口转发${NC}"
    echo -e "${BLUE}支持格式:${NC}"
    echo -e "  ${GREEN}单个端口:${NC} 80"
    echo -e "  ${GREEN}端口范围:${NC} 1000-2000"  
    echo -e "  ${GREEN}多个端口:${NC} 80,443,1000-2000,3000"
    
    read -p "请输入要删除的外部端口: " ext_port_input
    
    # 协议选择（增加all选项）
    while true; do
        read -p "请输入协议(tcp/udp/all, 默认tcp): " protocol
        protocol=${protocol:-tcp}
        if [[ "$protocol" == "tcp" || "$protocol" == "udp" || "$protocol" == "all" ]]; then
            break
        else
            echo -e "${RED}错误: 协议必须是 tcp、udp 或 all${NC}"
        fi
    done
    
    # 验证端口格式
    if ! validate_port "$ext_port_input"; then
        echo -e "${RED}错误: 端口格式不正确${NC}"
        echo -e "${YELLOW}支持的格式: 单个端口(80), 端口范围(1000-2000), 多个端口(80,443,1000-2000)${NC}"
        return 1
    fi
    
    # 解析端口输入
    local ext_ports=()
    parse_port_input "$ext_port_input" ext_ports
    
    local protocols=()
    if [ "$protocol" == "all" ]; then
        protocols=("tcp" "udp")
        echo -e "${BLUE}同时删除 TCP 和 UDP 协议规则${NC}"
    else
        protocols=("$protocol")
    fi
    
    echo -e "${BLUE}正在删除端口 ${ext_port_input} 的转发规则...${NC}"
    
    local deleted_count=0
    for proto in "${protocols[@]}"; do
        for ext_port in "${ext_ports[@]}"; do
            # 构建精确的匹配模式，包含协议信息
            local pattern="${ext_port}_${proto}_"
            
            # 删除所有包含该唯一标识的规则
            if [ -f "$SCRIPT_RULES_FILE" ]; then
                # 创建临时文件
                local temp_file=$(mktemp)
                
                # 过滤掉包含目标唯一标识的行
                grep -v "$pattern" "$SCRIPT_RULES_FILE" > "$temp_file"
                
                # 替换原文件
                mv "$temp_file" "$SCRIPT_RULES_FILE"
                
                ((deleted_count++))
                echo -e "${GREEN}✓ 删除 ${proto} 端口 ${ext_port} 的转发规则${NC}"
            fi
        done
    done
    
    # 清理空表并重新应用规则
    cleanup_empty_tables
    apply_rules_file
    
    echo -e "${GREEN}已删除 ${deleted_count} 条转发规则${NC}"
    if [ "$protocol" == "all" ]; then
        echo -e "${BLUE}注意: 删除了TCP和UDP协议的规则${NC}"
    else
        echo -e "${BLUE}注意: 只删除了${protocol}协议的规则${NC}"
    fi
}

# 验证IP地址格式
validate_ip() {
    local ip="$1"
    
    # IPv4验证
    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
    fi
    
    # IPv6验证（简化版，支持压缩格式）
    if [[ "$ip" =~ ^[0-9a-fA-F:]+$ ]] && [[ "$ip" =~ : ]]; then
        return 0
    fi
    
    # CIDR格式验证
    if [[ "$ip" =~ ^[0-9a-fA-F:\.]+/[0-9]+$ ]]; then
        return 0
    fi
    
    return 1
}

# 允许入站（增强版，支持批量端口和all协议）
allow_port() {
    echo -e "${YELLOW}允许入站${NC}"
    echo -e "${BLUE}支持格式:${NC}"
    echo -e "  ${GREEN}单个端口:${NC} 80"
    echo -e "  ${GREEN}端口范围:${NC} 1000-2000"  
    echo -e "  ${GREEN}多个端口:${NC} 80,443,1000-2000,3000"
    echo -e "${BLUE}可以指定允许访问的源IP，不输入则允许所有IP${NC}"
    echo -e "${BLUE}支持IPv4(192.168.1.1)、IPv6(2001:db8::1)和CIDR(192.168.1.0/24)格式${NC}"
    
    read -p "请输入端口号: " port_input
    
    # 协议选择（增加all选项）
    while true; do
        read -p "请输入协议(tcp/udp/all, 默认tcp): " protocol
        protocol=${protocol:-tcp}
        if [[ "$protocol" == "tcp" || "$protocol" == "udp" || "$protocol" == "all" ]]; then
            break
        else
            echo -e "${RED}错误: 协议必须是 tcp、udp 或 all${NC}"
        fi
    done
    
    # 询问源IP
    while true; do
        read -p "请输入允许访问的源IP(不输入则允许所有IP): " source_ip
        
        if [ -z "$source_ip" ]; then
            # 空输入，允许所有IP
            break
        elif validate_ip "$source_ip" || [[ "$source_ip" == "any" ]]; then
            # 有效的IP地址或any
            break
        else
            echo -e "${RED}错误: IP地址格式不正确${NC}"
            echo -e "${YELLOW}支持的格式:${NC}"
            echo -e "  IPv4: 192.168.1.1"
            echo -e "  IPv6: 2001:db8::1"
            echo -e "  CIDR: 192.168.1.0/24"
            echo -e "  任意: any"
        fi
    done
    
    # 验证端口格式
    if ! validate_port "$port_input"; then
        echo -e "${RED}错误: 端口格式不正确，请使用数字或范围(如100-200)${NC}"
        echo -e "${YELLOW}支持的格式: 单个端口(80), 端口范围(1000-2000), 多个端口(80,443,1000-2000)${NC}"
        return 1
    fi
    
    # 解析端口输入
    local ports=()
    parse_port_input "$port_input" ports
    
    local protocols=()
    if [ "$protocol" == "all" ]; then
        protocols=("tcp" "udp")
        echo -e "${BLUE}同时添加 TCP 和 UDP 协议规则${NC}"
    else
        protocols=("$protocol")
    fi
    
    local success_count=0
    local total_count=$(( ${#ports[@]} * ${#protocols[@]} ))
    
    echo -e "${BLUE}即将添加 $total_count 条允许规则...${NC}"
    
    # 添加规则
    for proto in "${protocols[@]}"; do
        for port in "${ports[@]}"; do
            # 生成唯一标识（包含协议和源IP信息）
            local unique_id="ALLOW_${port}_${proto}_${source_ip:-any}"
            local rule_comment="comment \"${unique_id}\""
            
            # 构建规则
            local rule=""
            if [ -n "$source_ip" ] && [ "$source_ip" != "any" ]; then
                # 指定了源IP
                if [[ "$source_ip" =~ : ]]; then
                    # IPv6地址
                    rule="ip6 saddr ${source_ip} ${proto} dport ${port} accept ${rule_comment}"
                else
                    # IPv4地址
                    rule="ip saddr ${source_ip} ${proto} dport ${port} accept ${rule_comment}"
                fi
            else
                # 允许所有IP
                rule="${proto} dport ${port} accept ${rule_comment}"
            fi
            
            # 添加到filter表
            if add_rule_to_file "inet script_filter" "input" "$rule"; then
                ((success_count++))
                if [ -n "$source_ip" ]; then
                    echo -e "${GREEN}✓ 允许 ${proto} 端口 ${port} 来自 ${source_ip}${NC}"
                else
                    echo -e "${GREEN}✓ 允许所有IP访问 ${proto} 端口 ${port}${NC}"
                fi
            else
                echo -e "${RED}✗ 添加 ${proto} 端口 ${port} 允许规则失败${NC}"
            fi
        done
    done
    
    # 应用新规则
    apply_rules_file
    
    echo -e "${GREEN}入站规则添加完成: ${success_count}/${total_count} 条规则成功${NC}"
}

# 拒绝入站（增强版，支持批量端口和all协议）
deny_port() {
    echo -e "${YELLOW}拒绝入站${NC}"
    echo -e "${BLUE}支持格式:${NC}"
    echo -e "  ${GREEN}单个端口:${NC} 80"
    echo -e "  ${GREEN}端口范围:${NC} 1000-2000"  
    echo -e "  ${GREEN}多个端口:${NC} 80,443,1000-2000,3000"
    echo -e "${BLUE}可以指定拒绝访问的源IP，不输入则拒绝所有IP${NC}"
    echo -e "${BLUE}支持IPv4(192.168.1.1)、IPv6(2001:db8::1)和CIDR(192.168.1.0/24)格式${NC}"
    
    read -p "请输入端口号: " port_input
    
    # 协议选择（增加all选项）
    while true; do
        read -p "请输入协议(tcp/udp/all, 默认tcp): " protocol
        protocol=${protocol:-tcp}
        if [[ "$protocol" == "tcp" || "$protocol" == "udp" || "$protocol" == "all" ]]; then
            break
        else
            echo -e "${RED}错误: 协议必须是 tcp、udp 或 all${NC}"
        fi
    done
    
    # 询问源IP
    while true; do
        read -p "请输入拒绝访问的源IP(不输入则拒绝所有IP): " source_ip
        
        if [ -z "$source_ip" ]; then
            # 空输入，拒绝所有IP
            break
        elif validate_ip "$source_ip" || [[ "$source_ip" == "any" ]]; then
            # 有效的IP地址或any
            break
        else
            echo -e "${RED}错误: IP地址格式不正确${NC}"
            echo -e "${YELLOW}支持的格式:${NC}"
            echo -e "  IPv4: 192.168.1.1"
            echo -e "  IPv6: 2001:db8::1"
            echo -e "  CIDR: 192.168.1.0/24"
            echo -e "  任意: any"
        fi
    done
    
    # 验证端口格式
    if ! validate_port "$port_input"; then
        echo -e "${RED}错误: 端口格式不正确，请使用数字或范围(如100-200)${NC}"
        echo -e "${YELLOW}支持的格式: 单个端口(80), 端口范围(1000-2000), 多个端口(80,443,1000-2000)${NC}"
        return 1
    fi
    
    # 解析端口输入
    local ports=()
    parse_port_input "$port_input" ports
    
    local protocols=()
    if [ "$protocol" == "all" ]; then
        protocols=("tcp" "udp")
        echo -e "${BLUE}同时添加 TCP 和 UDP 协议规则${NC}"
    else
        protocols=("$protocol")
    fi
    
    local success_count=0
    local total_count=$(( ${#ports[@]} * ${#protocols[@]} ))
    
    echo -e "${BLUE}即将添加 $total_count 条拒绝规则...${NC}"
    
    # 添加规则
    for proto in "${protocols[@]}"; do
        for port in "${ports[@]}"; do
            # 生成唯一标识（包含协议和源IP信息）
            local unique_id="DENY_${port}_${proto}_${source_ip:-any}"
            local rule_comment="comment \"${unique_id}\""
            
            # 构建规则
            local rule=""
            if [ -n "$source_ip" ] && [ "$source_ip" != "any" ]; then
                # 指定了源IP
                if [[ "$source_ip" =~ : ]]; then
                    # IPv6地址
                    rule="ip6 saddr ${source_ip} ${proto} dport ${port} drop ${rule_comment}"
                else
                    # IPv4地址
                    rule="ip saddr ${source_ip} ${proto} dport ${port} drop ${rule_comment}"
                fi
            else
                # 拒绝所有IP
                rule="${proto} dport ${port} drop ${rule_comment}"
            fi
            
            # 添加到filter表
            if add_rule_to_file "inet script_filter" "input" "$rule"; then
                ((success_count++))
                if [ -n "$source_ip" ]; then
                    echo -e "${GREEN}✓ 拒绝 ${proto} 端口 ${port} 来自 ${source_ip}${NC}"
                else
                    echo -e "${GREEN}✓ 拒绝所有IP访问 ${proto} 端口 ${port}${NC}"
                fi
            else
                echo -e "${RED}✗ 添加 ${proto} 端口 ${port} 拒绝规则失败${NC}"
            fi
        done
    done
    
    # 应用新规则
    apply_rules_file
    
    echo -e "${GREEN}拒绝规则添加完成: ${success_count}/${total_count} 条规则成功${NC}"
}

# 删除入站规则（增强版，支持批量端口和all协议）
delete_access_rule() {
    echo -e "${YELLOW}删除入站规则${NC}"
    echo -e "${BLUE}支持格式:${NC}"
    echo -e "  ${GREEN}单个端口:${NC} 80"
    echo -e "  ${GREEN}端口范围:${NC} 1000-2000"  
    echo -e "  ${GREEN}多个端口:${NC} 80,443,1000-2000,3000"
    echo -e "${BLUE}可以指定删除特定IP的规则，不输入则删除该端口的所有规则${NC}"
    
    read -p "请输入要删除规则的端口: " port_input
    
    # 协议选择（增加all选项）
    while true; do
        read -p "请输入协议(tcp/udp/all, 默认tcp): " protocol
        protocol=${protocol:-tcp}
        if [[ "$protocol" == "tcp" || "$protocol" == "udp" || "$protocol" == "all" ]]; then
            break
        else
            echo -e "${RED}错误: 协议必须是 tcp、udp 或 all${NC}"
        fi
    done
    
    # 询问源IP
    read -p "请输入要删除规则的源IP(不输入则删除该端口的所有规则): " source_ip
    
    # 验证端口格式
    if ! validate_port "$port_input"; then
        echo -e "${RED}错误: 端口格式不正确，请使用数字或范围(如100-200)${NC}"
        echo -e "${YELLOW}支持的格式: 单个端口(80), 端口范围(1000-2000), 多个端口(80,443,1000-2000)${NC}"
        return 1
    fi
    
    # 解析端口输入
    local ports=()
    parse_port_input "$port_input" ports
    
    local protocols=()
    if [ "$protocol" == "all" ]; then
        protocols=("tcp" "udp")
        echo -e "${BLUE}同时删除 TCP 和 UDP 协议规则${NC}"
    else
        protocols=("$protocol")
    fi
    
    echo -e "${BLUE}正在删除端口 ${port_input} 的入站规则...${NC}"
    
    local deleted_count=0
    for proto in "${protocols[@]}"; do
        for port in "${ports[@]}"; do
            # 构建精确的匹配模式
            local pattern=""
            if [ -n "$source_ip" ] && [ "$source_ip" != "any" ]; then
                # 删除特定IP和特定协议的规则
                pattern="${port}_${proto}_${source_ip}"
            else
                # 删除该端口特定协议的所有规则
                pattern="${port}_${proto}_"
            fi
            
            # 删除匹配的规则（同时匹配ALLOW和DENY规则）
            if [ -f "$SCRIPT_RULES_FILE" ]; then
                # 创建临时文件
                local temp_file=$(mktemp)
                
                # 过滤掉包含目标模式的行
                grep -v "$pattern" "$SCRIPT_RULES_FILE" > "$temp_file"
                
                # 替换原文件
                mv "$temp_file" "$SCRIPT_RULES_FILE"
                
                ((deleted_count++))
                if [ -n "$source_ip" ]; then
                    echo -e "${GREEN}✓ 删除 ${proto} 端口 ${port} 来自 ${source_ip} 的规则${NC}"
                else
                    echo -e "${GREEN}✓ 删除 ${proto} 端口 ${port} 的所有规则${NC}"
                fi
            fi
        done
    done
    
    # 清理空表并重新应用规则
    cleanup_empty_tables
    apply_rules_file
    
    echo -e "${GREEN}已删除 ${deleted_count} 条入站规则${NC}"
    if [ "$protocol" == "all" ]; then
        echo -e "${BLUE}注意: 删除了TCP和UDP协议的规则${NC}"
    else
        echo -e "${BLUE}注意: 只删除了${protocol}协议的规则${NC}"
    fi
}

# 列出所有规则（修复版）
list_all_rules() {
    echo -e "${YELLOW}=== 当前所有脚本管理的规则 ===${NC}"
    
    if [ -f "$SCRIPT_RULES_FILE" ]; then
        # 显示端口转发规则
        echo -e "${BLUE}--- 端口转发规则 ---${NC}"
        local has_forward_rules=0
        
        # 检查NAT表中的规则
        if grep -q "dnat to" "$SCRIPT_RULES_FILE"; then
            while IFS= read -r line; do
                if [[ "$line" =~ dnat.*to.*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+|[0-9]+) ]] || [[ "$line" =~ dnat.*to.*\[.*\]:[0-9]+ ]]; then
                    # 提取端口和协议信息
                    local port=$(echo "$line" | grep -oE "dport [0-9]+(-[0-9]+)?" | awk '{print $2}')
                    local protocol=$(echo "$line" | grep -oE "tcp|udp" | head -1)
                    local target=$(echo "$line" | grep -oE "to [^ ]+" | awk '{print $2}')
                    
                    if [ -n "$port" ] && [ -n "$target" ]; then
                        protocol=${protocol:-tcp}
                        echo -e "转发: ${port}/${protocol} -> ${target}"
                        has_forward_rules=1
                    fi
                fi
            done < <(grep "dnat to" "$SCRIPT_RULES_FILE")
        fi
        
        if [ $has_forward_rules -eq 0 ]; then
            echo -e "${YELLOW}无端口转发规则${NC}"
        fi
        
        echo
        
        # 显示入站控制规则
        echo -e "${BLUE}--- 入站控制规则 ---${NC}"
        local has_access_rules=0
        
        # 检查accept规则
        if grep -q "dport.*accept" "$SCRIPT_RULES_FILE"; then
            while IFS= read -r line; do
                local port=$(echo "$line" | grep -oE "dport [0-9]+(-[0-9]+)?" | awk '{print $2}')
                local protocol=$(echo "$line" | grep -oE "tcp|udp" | head -1)
                local source_ip=$(echo "$line" | grep -oE "saddr [^ ]+" | awk '{print $2}' || echo "any")
                
                if [ -n "$port" ]; then
                    protocol=${protocol:-tcp}
                    echo -e "允许: ${port}/${protocol} 来自 ${source_ip}"
                    has_access_rules=1
                fi
            done < <(grep "dport.*accept" "$SCRIPT_RULES_FILE")
        fi
        
        # 检查drop规则
        if grep -q "dport.*drop" "$SCRIPT_RULES_FILE"; then
            while IFS= read -r line; do
                local port=$(echo "$line" | grep -oE "dport [0-9]+(-[0-9]+)?" | awk '{print $2}')
                local protocol=$(echo "$line" | grep -oE "tcp|udp" | head -1)
                local source_ip=$(echo "$line" | grep -oE "saddr [^ ]+" | awk '{print $2}' || echo "any")
                
                if [ -n "$port" ]; then
                    protocol=${protocol:-tcp}
                    echo -e "拒绝: ${port}/${protocol} 来自 ${source_ip}"
                    has_access_rules=1
                fi
            done < <(grep "dport.*drop" "$SCRIPT_RULES_FILE")
        fi
        
        if [ $has_access_rules -eq 0 ]; then
            echo -e "${YELLOW}无入站控制规则${NC}"
        fi
        
    else
        echo -e "${RED}规则文件不存在${NC}"
    fi
    
    echo -e "${YELLOW}====================${NC}"
}

# 重新加载规则
reload_rules() {
    echo -e "${YELLOW}重新加载脚本规则${NC}"
    echo -e "${BLUE}注意: 只重新加载脚本管理的规则，不影响其他服务${NC}"
    
    apply_rules_file
    echo -e "${GREEN}脚本规则已重新加载${NC}"
}

# 添加nft自启
enable_autostart() {
    if command -v systemctl &> /dev/null; then
        if systemctl enable nftables 2>/dev/null; then
            echo -e "${GREEN}nftables开机自启已启用 (systemd)${NC}"
        else
            echo -e "${RED}启用开机自启失败${NC}"
        fi
    elif command -v rc-update &> /dev/null; then
        if rc-update add nftables default 2>/dev/null; then
            echo -e "${GREEN}nftables开机自启已启用 (OpenRC)${NC}"
        else
            echo -e "${RED}启用开机自启失败${NC}"
        fi
    else
        echo -e "${YELLOW}无法确定init系统，请手动设置开机自启${NC}"
    fi
}

# 显示菜单
show_menu() {
    echo -e "${GREEN}=== nftables 管理脚本 ===${NC}"
    echo "1. 添加端口转发"
    echo "2. 删除端口转发"
    echo "3. 允许入站"
    echo "4. 拒绝入站"
    echo "5. 删除入站规则"
    echo "6. 列出所有脚本规则"
    echo "7. 重新加载脚本规则"
    echo "8. 清空所有脚本规则"
    echo "9. 查看当前所有nft规则"
    echo "10. 添加nft自启（防止脚本规则重启失效）"
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
            1) add_port_forward ;;
            2) delete_port_forward ;;
            3) allow_port ;;
            4) deny_port ;;
            5) delete_access_rule ;;
            6) list_all_rules ;;
            7) reload_rules ;;
            8) clear_all_rules ;;
            9) show_rules ;;
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
