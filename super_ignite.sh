#!/bin/bash
# 🍒 Cherry AI - SP-Grade Orderly Redirection Alignment (Silicon Valley Mode)
set -e

echo "⚙️  Step 1: Compiling Go Controller & Agent Binaries..."
# 🧠 100% 鋼鐵對齊：大腦與哨兵同步編譯為原生二進位，拒絕臨時目錄空轉！
go build -o cherry_pce srv6_injector_v2.go
go build -o cherry_agent agent_v5.go

echo "⚙️  Step 2: Triggering Node-Isolated Driver Ignition (Only Copy, No Attach)..."
# 呼叫純淨的分發後勤腳本
sudo ./ignite_v5.sh

echo "⚙️  Step 3: Flushing stale network socket descriptors and zombie brains..."
# 🛡️ 雙重爆頭：同時清理 TCP 端口和舊的二進位進程名
sudo fuser -k 20179/tcp 8080/tcp 2>/dev/null || true
sudo pkill -9 cherry_pce 2>/dev/null || true

# 🎯 換軌核心時序：以純二進位線速點燃中央大腦！
echo "🚀 Step 4: Launching Central PCE Brain..."
./cherry_pce &
sleep 1 # ⚡ 降維打擊：二進位秒級啟動，1 秒監聽綠燈即全盤亮起！

# 🎯 大腦就緒後，最後一鼓作氣喚醒全網 14 節點哨兵
echo "⚡ Step 5: Awakening Sentry Agents over isolated private FDs..."
sudo ./kick_agents.sh

# 保持總控前景掛起，方便在大腦控制台即時觀測 14 節點接入畫面
wait
