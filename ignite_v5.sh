#!/bin/bash
LAB_NAME="cherry-ai-lab"
OBJ_FILE="/home/sam/labs/cherry-ai/xdp_v5.o"

# 確保最新編譯 (Keep this at the top!)
sudo rm -f "$OBJ_FILE"
sudo clang -O2 -target bpf -g -I/usr/include/x86_64-linux-gnu -c cherry_shield.c -o xdp_v5.o

nodes=("linux01" "linux02" "linux03" "linux04" "linux05" "linux06" "linux07" "linux08" "linux09" "linux10" "linux11" "linux12" "ubuntu01" "ubuntu02")

for n in "${nodes[@]}"; do
    node_full="clab-$LAB_NAME-$n"
    if [ "$(sudo docker inspect -f '{{.State.Status}}' $node_full 2>/dev/null)" == "running" ]; then
        echo "⚡ [物理清空舊世界殘留驅動] $n ..."
        
        # 🎯 核心真理：不僅扒網卡，還要強行物理爆破 BPF 虛擬檔案系統裡的歷史死鎖檔案！
        sudo docker exec -u 0 "$node_full" bash -c "
            for eth in \$(ls /sys/class/net | grep eth | grep -v eth0); do 
                bpftool net detach xdp dev \$eth 2>/dev/null || true;
                ip link set dev \$eth xdp off 2>/dev/null || true; 
                ip link set dev \$eth xdpgeneric off 2>/dev/null || true; 
            done;
            # 🛡️ 鋼鐵爆破：全盤粉碎舊世界殘留的 policy 表與 mac 表，強行解除記憶體規格死鎖！
            rm -f /sys/fs/bpf/srv6_policy_map 2>/dev/null || true
            rm -f /sys/fs/bpf/next_hop_mac_map 2>/dev/null || true
            rm -f /sys/fs/bpf/xdp_prog_${n} 2>/dev/null || true
            rm -rf /sys/fs/bpf/${n}/* 2>/dev/null || true
        "
        sleep 0.1
        # 🎯 巨頭模式：只推送二進位產物，絕對不越權在外部加載或 Pin 任何網卡！
        sudo docker cp "$OBJ_FILE" "$node_full:/root/xdp_v5.o"
        echo "  ✅ $n 內核完全體產物推送成功！"
    fi
done

# 🏁 注意：結尾絕對乾乾淨淨，沒有任何提前拉起 Agent 的指令！
echo "🎉 全網無殘留核心產物分發完畢！" 
