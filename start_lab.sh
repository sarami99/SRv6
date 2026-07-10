#!/bin/bash
# =====================================================================
# Cherry AI - v26.4 (THE FINAL ARCHITECT EDITION - SR-IOV FABRIC BASE)
# 🎯 職責：硬體網卡映射、Containerlab 拓撲拉起、WAN 隧道打通（不越權掛載 XDP）
# =====================================================================
set -e
stty sane || reset
trap 'stty sane' EXIT

LAB_NAME="cherry-ai-lab"
PF0="enp66s0f0np0"
PF1="enp66s0f1np1" 

echo "🧹 [1/5] 執行全面環境重置..."
sudo pkill -9 cherry_pce 2>/dev/null || true
sudo pkill -9 gobgpd 2>/dev/null || true
sudo fuser -k 179/tcp 50051/tcp 20179/tcp 8082/tcp 2>/dev/null || true

sudo containerlab destroy -t cherry-ai-lab.clab.yml --cleanup 2>/dev/null || true
sudo docker rm -f $(sudo docker ps -aq) 2>/dev/null || true

echo "🧹 清除主機連線追蹤表中的舊有 GRE 殘留狀態..."
sudo conntrack -D -p 47 2>/dev/null || true

echo "🧹 清除虛擬 eBPF 檔案系統殘留雜訊..."
if mountpoint -q /sys/fs/bpf; then
    sudo umount -l /sys/fs/bpf 2>/dev/null || true
fi
sudo rm -rf /sys/fs/bpf/* || true
sudo mount -t bpf bpf /sys/fs/bpf
sudo chmod 777 /sys/fs/bpf

sudo ip netns list | awk '{print $1}' | while read -r ns; do sudo ip netns delete "$ns" 2>/dev/null || true; done
sudo umount /var/run/docker/netns/* 2>/dev/null || true
sudo rm -rf /var/run/docker/netns/* /var/lib/docker/network/* 2>/dev/null || true

echo "⚙️  [硬體解鎖] 正在擴張 Mellanox 實體 100G 網口 MTU 緩衝區..."
sudo ip link set dev "$PF0" mtu 3500 || true
sudo ip link set dev "$PF1" mtu 3500 || true

echo "🐳 [2/5] 編譯主機對齊之高效能容器鏡像..."
sudo docker build -t cherry-ai-node:latest -f Dockerfile .

echo "🚀 [3/5] 啟動容器拓撲網路環境..."
sudo containerlab deploy -t cherry-ai-lab.clab.yml --reconfigure --max-workers 1

# =================================================================
# 💉 Mellanox Legacy 硬體 L2 直通 (解鎖組播與 MAC 限制版)
# =================================================================
inject_vf() {
    local pf=$1; local vid=$2; local node=$3; local intf=$4; local vlan=$5
    local node_full="clab-$LAB_NAME-$node"
    local prefix=$(echo $pf | sed 's/np[0-1]$//')
    
    if [ "$(sudo docker inspect -f '{{.State.Status}}' $node_full 2>/dev/null)" == "running" ]; then
        local pid=$(sudo docker inspect -f '{{.State.Pid}}' "$node_full")
        
        sudo ip link set "$pf" vf "$vid" mac 00:00:00:00:00:00 2>/dev/null || true
        sudo ip link set "$pf" vf "$vid" vlan "$vlan" spoofchk off trust on
        
        sudo docker exec "$node_full" ip link delete "$intf" 2>/dev/null || true
        sudo ip link set "${prefix}v${vid}" netns "$pid"
        
        sudo docker exec "$node_full" ip link set dev "${prefix}v${vid}" name "$intf" mtu 3000 up
        sudo docker exec "$node_full" ethtool -K "$intf" lro off 2>/dev/null || true
    fi
}

echo "💉 [4/5] 執行硬體 100G 直通網卡映射對齊..."
inject_vf $PF0 0  ubuntu01 eth1 101; inject_vf $PF0 1  linux01 eth3 101
inject_vf $PF0 2  ubuntu01 eth2 102; inject_vf $PF0 3  linux02 eth3 102
inject_vf $PF0 4  linux01 eth2 103;  inject_vf $PF0 5  linux02 eth4 103
inject_vf $PF0 6  linux01 eth4 104;  inject_vf $PF0 7  linux09 eth1 104
inject_vf $PF0 8  linux02 eth2 106;  inject_vf $PF0 9  linux07 eth1 106
inject_vf $PF0 10 client-u01 eth1 201; inject_vf $PF0 11 ubuntu01 eth10 201

inject_vf $PF0 12 linux09 eth3 109;  inject_vf $PF1 0  linux10 eth4 109
inject_vf $PF0 13 linux07 eth3 113;  inject_vf $PF1 1  linux08 eth1 113

inject_vf $PF1 2  linux10 eth2 111;  inject_vf $PF1 3  linux03 eth6 111
inject_vf $PF1 4  linux08 eth3 115;  inject_vf $PF1 5  linux04 eth2 115
inject_vf $PF1 6  linux03 eth4 120;  inject_vf $PF1 7  linux05 eth1 120
inject_vf $PF1 8  linux03 eth3 121;  inject_vf $PF1 9  linux04 eth6 121
inject_vf $PF1 10 linux04 eth5 123;  inject_vf $PF1 11 linux05 eth2 123
inject_vf $PF1 12 linux04 eth4 124;  inject_vf $PF1 13 linux06 eth4 124
inject_vf $PF1 14 linux05 eth3 125;  inject_vf $PF1 15 linux06 eth3 125
inject_vf $PF1 16 linux05 eth4 126;  inject_vf $PF1 17 ubuntu02 eth1 126
inject_vf $PF1 18 ubuntu02 eth2 127; inject_vf $PF1 19 linux06 eth2 127
inject_vf $PF1 20 client-u02 eth1 202; inject_vf $PF1 21 ubuntu02 eth10 202
inject_vf $PF1 22 client-l10 eth1 203; inject_vf $PF1 23 linux10 eth10 203
inject_vf $PF1 24 client-l08 eth1 204; inject_vf $PF1 25 linux08 eth10 204
inject_vf $PF1 26 linux10 eth3 130;  inject_vf $PF1 27 linux12 eth1 130
inject_vf $PF1 28 linux03 eth5 131;  inject_vf $PF1 29 linux12 eth2 131
inject_vf $PF1 30 linux05 eth5 132;  inject_vf $PF1 31 linux12 eth3 132
inject_vf $PF1 32 linux08 eth2 133;  inject_vf $PF1 33 linux11 eth1 133
inject_vf $PF1 34 linux04 eth3 134;  inject_vf $PF1 35 linux11 eth2 134
inject_vf $PF1 36 linux06 eth1 135;  inject_vf $PF1 37 linux11 eth3 135

echo "🌐 配置 Client 直通核心 IP 網段位址..."
sudo docker exec clab-$LAB_NAME-client-u01 ip addr add 10.10.1.2/24 dev eth1 || true
sudo docker exec clab-$LAB_NAME-client-u01 ip route replace default via 10.10.1.1 || true
sudo docker exec clab-$LAB_NAME-client-u02 ip addr add 10.20.2.2/24 dev eth1 || true
sudo docker exec clab-$LAB_NAME-client-u02 ip route replace default via 10.20.2.1 || true

echo "🔗 啟動 WAN 隧道與終極貫通防禦..."
P620_WIFI_IF="wlx7419f8164815"
P620_LOCAL_IP="192.168.50.2"
REMOTE_SG_IP="63.222.115.137"
UBUNTU02_IP="172.20.50.204"

sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null
sudo sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
sudo iptables -t nat -I PREROUTING -i "$P620_WIFI_IF" -p 47 -j DNAT --to-destination "$UBUNTU02_IP" 2>/dev/null || true
sudo iptables -t nat -I POSTROUTING -s "$UBUNTU02_IP" -o "$P620_WIFI_IF" -p 47 -j SNAT --to-source "$P620_LOCAL_IP" 2>/dev/null || true
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 | sudo tee $i >/dev/null; done

sudo docker exec -u root clab-$LAB_NAME-ubuntu02 bash -c "
    for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 0 > \$i; done
    ethtool -K eth0 tx off rx off 2>/dev/null || true
    ip tunnel del gre-to-sg 2>/dev/null || true
    ip tunnel add gre-to-sg mode gre remote $REMOTE_SG_IP local $UBUNTU02_IP ttl 255
    ip link set gre-to-sg mtu 1400 multicast on up
    ip -6 addr add fc00:10d::0/127 dev gre-to-sg 2>/dev/null || true
    ip route replace $REMOTE_SG_IP via 172.20.50.1
    vtysh -c 'conf t' -c 'interface gre-to-sg' -c 'ipv6 router isis CHERRY' -c 'isis network point-to-point'
" || true

echo "📡 核心網 LSDB 就緒，正在啟動 GoBGP 拓撲接收器..."
nohup sudo gobgpd -f gobgpd_ls.toml > gobgpd_ls.toml.log 2>&1 &

echo "========================================================="
echo "🎉 [BASE LIVE] 拓撲與直通網卡就緒！請立即執行 ./super_ignite.sh 通車！"
echo "========================================================="
