package main

import (
        "bytes"
        "encoding/binary"
        "encoding/hex"
        "fmt"
        "log"
        "net"
        "net/http"
        "strings"
        "sync"
        "time"
)

type NodeInfo struct {
        Hostname string
        Role     string
}

var (
        peerStatus = make(map[string]NodeInfo)
        agentConns = make(map[string]net.Conn) 
        mu         sync.Mutex
)

func getRole(name string) string {
        if name == "ubuntu01" { return "Ingress (Forward)" }
        if name == "ubuntu02" { return "Ingress (Return)" }
        if name == "linux03"  { return "BSID Anchor (FWD)" }
        if name == "linux07"  { return "BSID Anchor (REV)" }
        if name == "linux10"  { return "Tenant B Ingress (FWD)" }
        if name == "linux08"  { return "Tenant B Egress (REV)" }
        return "Transit (End.uSID)"
}

func main() {
        fmt.Println("🚀 [Cherry PCE] V5.0 (純 REDIRECT 直連 MAC 投餵完全體)")

        go func() {
                http.HandleFunc("/bgp", func(w http.ResponseWriter, r *http.Request) {
                        mu.Lock()
                        defer mu.Unlock()
                        fmt.Fprintf(w, "--- [Cherry AI] BGP SAFI 73 Tele-Cloud Peer Status ---\n\n")
                        fmt.Fprintf(w, "%-25s | %-12s | %-22s | %-10s\n", "PEER ADDRESS", "HOSTNAME", "FABRIC ROLE", "STATE")
                        fmt.Fprintf(w, "--------------------------------------------------------------------------------\n")
                        for addr, info := range peerStatus {
                                fmt.Fprintf(w, "%-25s | %-12s | %-22s | %-10s\n", addr, info.Hostname, info.Role, "ESTABLISHED")
                        }
                })
                fmt.Println("📊 狀態監控組件就緒: http://localhost:8080/bgp")
                _ = http.ListenAndServe(":8080", nil)
        }()

        ln, err := net.Listen("tcp4", "172.20.50.1:20179")
        if err != nil { log.Fatal(err) }

        for {
                conn, _ := ln.Accept()
                go handleAgent(conn)
        }
}

func handleAgent(conn net.Conn) {
        remoteAddr := conn.RemoteAddr().String()

        header := make([]byte, 16)
        if _, err := conn.Read(header); err != nil { 
                conn.Close()
                return 
        }
        name := strings.TrimSpace(string(bytes.Trim(header, "\x00")))
        role := getRole(name)

        mu.Lock()
        peerStatus[remoteAddr] = NodeInfo{Hostname: name, Role: role}
        agentConns[name] = conn 
        mu.Unlock()

        fmt.Printf("✅ [%-10s] (%s) 連線成功，角色認證: %s\n", name, remoteAddr, role)

        defer func() {
                conn.Close()
                mu.Lock()
                delete(peerStatus, remoteAddr)
                delete(agentConns, name) 
                mu.Unlock()
                fmt.Printf("❌ [%s] 連線中斷\n", name)
        }()

        open, _ := hex.DecodeString("ffffffffffffffffffffffffffffffff00310104fa5600b4ac14140114020601040002004902064104fa56ea0002020200")
        keep, _ := hex.DecodeString("ffffffffffffffffffffffffffffffff001304")
        conn.Write(open); conn.Write(keep)

        // 🔒 【Cherry AI 拓撲硬核全域對齊防線】：開機即灌滿直連物理地圖
        switch name {
        case "ubuntu01":
                conn.Write(BuildMacUpdate("fc00:0:1:2:7:8:4:3", "aa:bb:cc:00:01:03", 101)) 
        case "linux01":
                conn.Write(BuildMacUpdate("fc00:0:2:7:8:4:3:0", "aa:bb:cc:00:02:03", 103)) 
        case "linux02":
                conn.Write(BuildMacUpdate("fc00:0:7:8:4:3:0:0", "aa:bb:cc:00:07:01", 106)) 
        case "linux07":
                conn.Write(BuildMacUpdate("fc00:0:8:4:3:0:0:0", "aa:bb:cc:00:08:01", 113)) 
                time.Sleep(5 * time.Millisecond)
                conn.Write(BuildMacUpdate("fc00:0:1:9001:1:0:0:0", "aa:bb:cc:00:02:06", 106)) 
        case "linux08":
                conn.Write(BuildMacUpdate("fc00:0:4:3:0:0:0:0", "aa:bb:cc:00:04:02", 115)) 
        case "linux04":
                conn.Write(BuildMacUpdate("fc00:0:3:0:0:0:0:0", "aa:bb:cc:00:03:06", 121)) 
        case "linux03":
                conn.Write(BuildMacUpdate("fc00:0:5:6:9002:1:0:0", "aa:bb:cc:00:05:01", 120)) 
        case "linux05":
                conn.Write(BuildMacUpdate("fc00:0:6:9002:1:0:0:0", "aa:bb:cc:00:06:04", 125)) 
        case "linux06":
                conn.Write(BuildMacUpdate("fc00:0:9002:1:0:0:0:0", "aa:bb:cc:00:99:02", 127)) 
        }
        time.Sleep(10 * time.Millisecond)

        if name == "ubuntu01" { conn.Write(BuildSRv6Update("::ffff:10.20.2.2", "fc00:0:1:2:7:8:4:3")) }
        if name == "linux03"  { conn.Write(BuildSRv6Update("fc00:0:3::", "fc00:0:5:6:9002:1:0:0")) }

        if name == "ubuntu02" { conn.Write(BuildSRv6Update("::ffff:10.10.1.2", "fc00:0:6:5:3:4:8:7")) }
        if name == "linux07"  { conn.Write(BuildSRv6Update("fc00:0:7::", "fc00:0:1:9001:1:0:0:0")) }

        if name == "linux10"  { conn.Write(BuildSRv6Update("::ffff:192.168.80.2", "fc00:0:f:5:4:e:8:1")) }
        if name == "linux08"  { conn.Write(BuildSRv6Update("::ffff:192.168.10.2", "fc00:0:e:4:5:f:a:1")) }

        buf := make([]byte, 1024)
        for { 
                if _, err := conn.Read(buf); err != nil { break } 
        }
}

func BuildSRv6Update(endpoint string, path string) []byte {
        epIP := net.ParseIP(endpoint).To16()
        pathIP := net.ParseIP(path).To16()
        payload := append(epIP, pathIP...)

        // 🎯 【世紀補白對齊】：強行追加 12 位元組的 0x00 補白，確保 policyMap Value 的 24 位元組物理空間 100% 對齊不發生偏移！
        paddingMetrics := make([]byte, 12)
        binary.BigEndian.PutUint32(paddingMetrics[0:4], 1) // 預設 TenantID = 1
        binary.BigEndian.PutUint32(paddingMetrics[4:8], 128) // 預設 FlexAlgo = 128

        totalPayload := append(payload, paddingMetrics...)

        header := make([]byte, 19)
        copy(header[0:16], bytes.Repeat([]byte{0xff}, 16))
        binary.BigEndian.PutUint16(header[16:18], uint16(19+len(totalPayload))) // 總長度強行鎖定為 63 位元組
        header[18] = 2 

        return append(header, totalPayload...)
}

func BuildMacUpdate(nextHopIPv6 string, macStr string, ifindex uint32) []byte {
        ip := net.ParseIP(nextHopIPv6).To16()
        hw, _ := net.ParseMAC(macStr)

        payload := make([]byte, 16+12)
        copy(payload[0:16], ip)
        copy(payload[16:22], hw)

        // 🎯 世紀修正：出口 IfIndex 必須強行寫入為 BigEndian 大端序網路序，精確咬合 XDP 內核！
        binary.BigEndian.PutUint32(payload[24:28], ifindex) 

        header := make([]byte, 19)
        copy(header[0:16], bytes.Repeat([]byte{0xff}, 16))
        binary.BigEndian.PutUint16(header[16:18], uint16(19+len(payload)))
        header[18] = 3 
        return append(header, payload...)
}
