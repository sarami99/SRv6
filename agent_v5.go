package main

import (
        "bytes"
        "encoding/binary"
        "log"
        "net"
        "os"
        "time"

        "github.com/cilium/ebpf"
        "github.com/cilium/ebpf/link"
        "github.com/vishvananda/netlink"
)

var MacHardwareRegistry = map[string]map[string]struct{
        MacAddr [6]byte
        IfIndex uint32
}{
        "linux01": {
                "eth3": {MacAddr: [6]byte{0x0a, 0x15, 0x81, 0x0c, 0xbc, 0x94}, IfIndex: 47},
                "eth2": {MacAddr: [6]byte{0xe2, 0xad, 0x9b, 0x37, 0x71, 0x70}, IfIndex: 50},
                "eth4": {MacAddr: [6]byte{0x5e, 0xa4, 0x45, 0x47, 0xa2, 0xf4}, IfIndex: 52},
        },
        "linux02": {
                "eth3": {MacAddr: [6]byte{0x4a, 0x54, 0x52, 0x61, 0x01, 0xbd}, IfIndex: 49},
                "eth4": {MacAddr: [6]byte{0x06, 0x11, 0xb6, 0xf5, 0x79, 0x54}, IfIndex: 51},
                "eth2": {MacAddr: [6]byte{0x1a, 0xc3, 0x5d, 0x80, 0xc2, 0xb8}, IfIndex: 54},
        },
        "linux03": {
                "eth6": {MacAddr: [6]byte{0x02, 0x4b, 0x97, 0xbb, 0x23, 0x61}, IfIndex: 89},
                "eth4": {MacAddr: [6]byte{0x56, 0xac, 0x57, 0xa5, 0x91, 0x92}, IfIndex: 92},
                "eth3": {MacAddr: [6]byte{0x66, 0x4d, 0x45, 0x21, 0xe1, 0x1e}, IfIndex: 94},
                "eth5": {MacAddr: [6]byte{0xa6, 0x6b, 0x04, 0x7d, 0xaf, 0x01}, IfIndex: 114},
        },
        "linux04": {
                "eth2": {MacAddr: [6]byte{0x92, 0xe0, 0xf2, 0xb6, 0xed, 0x61}, IfIndex: 91},
                "eth6": {MacAddr: [6]byte{0x96, 0x28, 0x5e, 0x28, 0x4f, 0x09}, IfIndex: 95},
                "eth5": {MacAddr: [6]byte{0x02, 0x51, 0xc5, 0xe2, 0x3b, 0x23}, IfIndex: 96},
                "eth4": {MacAddr: [6]byte{0xfe, 0x5c, 0x79, 0x23, 0x7e, 0x39}, IfIndex: 98},
                "eth3": {MacAddr: [6]byte{0x36, 0x32, 0x00, 0x34, 0x8f, 0xd9}, IfIndex: 120},
        },
        "linux05": {
                "eth1": {MacAddr: [6]byte{0x92, 0xa9, 0x15, 0xdf, 0xd9, 0xfb}, IfIndex: 93},
                "eth2": {MacAddr: [6]byte{0x4e, 0x91, 0x36, 0x3f, 0x9b, 0x8b}, IfIndex: 97},
                "eth3": {MacAddr: [6]byte{0x76, 0x73, 0xa5, 0xf9, 0x53, 0x38}, IfIndex: 100},
                "eth4": {MacAddr: [6]byte{0x9e, 0x84, 0xcb, 0xf6, 0xeb, 0x5b}, IfIndex: 102},
                "eth5": {MacAddr: [6]byte{0xe2, 0x8c, 0xee, 0x41, 0x9b, 0x20}, IfIndex: 116},
        },
        "linux06": {
                "eth4": {MacAddr: [6]byte{0x02, 0xaf, 0x7b, 0x3a, 0x22, 0xb1}, IfIndex: 99},
                "eth3": {MacAddr: [6]byte{0x62, 0x76, 0x50, 0xd4, 0x91, 0xbe}, IfIndex: 101},
                "eth2": {MacAddr: [6]byte{0x8e, 0x14, 0x65, 0x97, 0xdd, 0xfa}, IfIndex: 105},
                "eth1": {MacAddr: [6]byte{0x4a, 0x7a, 0xb5, 0xcf, 0x65, 0x9d}, IfIndex: 122},
        },
        "linux07": {
                "eth1": {MacAddr: [6]byte{0x16, 0xec, 0x39, 0xb0, 0xad, 0xd5}, IfIndex: 55},
                "eth3": {MacAddr: [6]byte{0x26, 0xf8, 0x78, 0x97, 0x23, 0x6b}, IfIndex: 59},
        },
        "linux08": {
                "eth1": {MacAddr: [6]byte{0xb2, 0xc0, 0xc2, 0x2a, 0x10, 0xea}, IfIndex: 87},
                "eth3": {MacAddr: [6]byte{0x4e, 0x12, 0xe5, 0x37, 0x83, 0xd9}, IfIndex: 90},
                "eth10": {MacAddr: [6]byte{0x4a, 0xdf, 0xc3, 0x56, 0x60, 0xb5}, IfIndex: 111},
                "eth2": {MacAddr: [6]byte{0x22, 0x9b, 0x51, 0xf3, 0xc4, 0x3d}, IfIndex: 118},
        },
        "linux09": {
                "eth1": {MacAddr: [6]byte{0x92, 0xe8, 0xc0, 0x33, 0x40, 0xcb}, IfIndex: 53},
                "eth3": {MacAddr: [6]byte{0x92, 0x98, 0x4d, 0xe5, 0x31, 0x25}, IfIndex: 58},
        },
        "linux10": {
                "eth4": {MacAddr: [6]byte{0x72, 0xeb, 0xf4, 0x2b, 0x68, 0x67}, IfIndex: 86},
                "eth2": {MacAddr: [6]byte{0x92, 0xfa, 0xf2, 0xb0, 0xda, 0xdc}, IfIndex: 88},
                "eth10": {MacAddr: [6]byte{0xa2, 0x96, 0x5d, 0x5a, 0x73, 0x92}, IfIndex: 109},
                "eth3": {MacAddr: [6]byte{0x0a, 0x09, 0x1a, 0x72, 0x3f, 0x79}, IfIndex: 112},
        },
        "linux11": {
                "eth1": {MacAddr: [6]byte{0x0e, 0x73, 0x50, 0xb1, 0xf2, 0xd6}, IfIndex: 119},
                "eth2": {MacAddr: [6]byte{0x06, 0xd1, 0x2a, 0x20, 0xd9, 0xd0}, IfIndex: 121},
                "eth3": {MacAddr: [6]byte{0xfa, 0x3b, 0xf2, 0x55, 0x35, 0x52}, IfIndex: 123},
        },
        "linux12": {
                "eth1": {MacAddr: [6]byte{0x26, 0xbc, 0x6d, 0xb6, 0x5b, 0xd8}, IfIndex: 113},
                "eth2": {MacAddr: [6]byte{0x76, 0xf3, 0x65, 0xa9, 0x14, 0x5a}, IfIndex: 115},
                "eth3": {MacAddr: [6]byte{0x46, 0xc9, 0xde, 0xec, 0x4a, 0xd5}, IfIndex: 117},
        },
        "ubuntu01": {
                "eth1": {MacAddr: [6]byte{0x1e, 0x98, 0xa6, 0x13, 0x99, 0x8a}, IfIndex: 46},
                "eth2": {MacAddr: [6]byte{0x1e, 0x6c, 0xdd, 0xb7, 0x54, 0x2c}, IfIndex: 48},
                "eth10": {MacAddr: [6]byte{0xbe, 0xc5, 0x7c, 0x0f, 0xd3, 0xc6}, IfIndex: 57},
        },
        "ubuntu02": {
                "eth1": {MacAddr: [6]byte{0xf2, 0xf3, 0x81, 0x35, 0x6c, 0x4f}, IfIndex: 103},
                "eth2": {MacAddr: [6]byte{0x1e, 0x07, 0x0c, 0x0c, 0xb2, 0xd6}, IfIndex: 104},
                "eth10": {MacAddr: [6]byte{0xae, 0x5b, 0x76, 0xe7, 0x2b, 0xba}, IfIndex: 107},
        },
}

type Srv6PolicyVal struct {
        UsidTarget [16]byte
        TenantID   uint32
        FlexAlgo   uint32
}

var TopologyRegistry = map[string]map[string]uint32{
        "ubuntu01": {"eth1": 101, "eth2": 102, "eth10": 201},
        "ubuntu02": {"eth1": 126, "eth2": 127, "eth10": 202},
        "linux01":  {"eth3": 101, "eth2": 103, "eth4": 104},
        "linux02":  {"eth3": 102, "eth4": 103, "eth2": 106},
        "linux03":  {"eth6": 111, "eth4": 120, "eth3": 121, "eth5": 131},
        "linux04":  {"eth2": 115, "eth6": 121, "eth5": 123, "eth4": 124, "eth3": 134},
        "linux05":  {"eth1": 120, "eth2": 123, "eth3": 125, "eth4": 126, "eth5": 132},
        "linux06":  {"eth4": 124, "eth3": 125, "eth2": 127, "eth1": 135},
        "linux07":  {"eth1": 106, "eth3": 113},
        "linux08":  {"eth1": 113, "eth3": 115, "eth2": 133, "eth10": 204},
        "linux09":  {"eth1": 104, "eth3": 109},
        "linux10":  {"eth4": 109, "eth2": 111, "eth3": 130, "eth10": 203},
        "linux11":  {"eth1": 133, "eth2": 134, "eth3": 135},
        "linux12":  {"eth1": 130, "eth2": 131, "eth3": 132},
}

func main() {
        if len(os.Args) < 2 { log.Fatal("Usage: ./agent [hostname]") }
        hostname := os.Args[1]

        log.Printf("🚀 [Cherry Sentry] 100%% 物理焊接對齊完全體，啟動: %s", hostname)

        _ = os.MkdirAll("/sys/fs/bpf", 0755)
        policyPin := "/sys/fs/bpf/srv6_policy_map"
        macPin := "/sys/fs/bpf/next_hop_mac_map"

        policyMap, err := ebpf.LoadPinnedMap(policyPin, nil)
        if err != nil {
                policyMap, err = ebpf.NewMap(&ebpf.MapSpec{
                        Type:       ebpf.Hash,
                        KeySize:    16,
                        ValueSize:  24,
                        MaxEntries: 1024,
                })
                if err != nil { log.Fatalf("建立 policyMap 失敗: %v", err) }
                _ = policyMap.Pin(policyPin)
        }

        macMap, err := ebpf.LoadPinnedMap(macPin, nil)
        if err != nil {
                macMap, err = ebpf.NewMap(&ebpf.MapSpec{
                        Type:       ebpf.Hash,
                        KeySize:    16,
                        ValueSize:  10,
                        MaxEntries: 256,
                })
                if err != nil { log.Fatalf("建立 macMap 失敗: %v", err) }
                _ = macMap.Pin(macPin)
        }

        spec, err := ebpf.LoadCollectionSpec("/root/xdp_v5.o")
        if err != nil { log.Fatalf("解析 ELF 失敗: %v", err) }

        // 💡 【大網焊接核心】：直接動用 MapReplacements，強行阻斷內核派生分身匿名表！
        coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
                MapReplacements: map[string]*ebpf.Map{
                        "srv6_policy_map":  policyMap, // 💥 強行將 ELF 裡的符號，重定向到 VFS 實體表！
                        "next_hop_mac_map": macMap,    // 💥 強行將 ELF 裡的符號，重定向到 VFS 實體表！
                },
        })
        if err != nil { log.Fatalf("強行對齊焊接 Collection 失敗: %v", err) }
        defer coll.Close()

        program := coll.Programs["xdp_srv6_engine"]
        if program == nil { log.Fatal("Critical: Core BPF program missing!") }

        // 綁定網卡 (Native 模式開火)
        hostLinks, ok := TopologyRegistry[hostname]
        if ok {
                for ifaceName := range hostLinks {
                        iface, err := net.InterfaceByName(ifaceName)
                        if err != nil { continue }
                        l, err := link.AttachXDP(link.XDPOptions{
                                Interface: iface.Index,
                                Program:   program,
                                Flags:     link.XDPDriverMode,
                        })
                        if err != nil {
                                l, err = link.AttachXDP(link.XDPOptions{
                                        Interface: iface.Index,
                                        Program:   program,
                                        Flags:     link.XDPGenericMode,
                                })
                                if err != nil { continue }
                        }
                        defer l.Close()
                        log.Printf("🎯 [NATIVE-Bypass] XDP 引擎成功鎖定介面: %s", ifaceName)
                }
        }

        // 📡 監聽器：NDP 雷達 (回歸最乾淨的單一表寫入)
        go func() {
                updates := make(chan netlink.NeighUpdate)
                done := make(chan struct{})
                defer close(done)

                if err := netlink.NeighSubscribe(updates, done); err != nil {
                        log.Printf("🚨 訂閱 Netlink 雷達失敗: %v", err)
                        return
                }

                log.Printf("📡 [NETLINK-RADAR] 內核 NDP 雷達上線...")
                for update := range updates {
                        if update.Neigh.State&netlink.NUD_REACHABLE != 0 || update.Neigh.State&netlink.NUD_STALE != 0 {
                                nextHopIP := update.Neigh.IP.To16()
                                if nextHopIP == nil || nextHopIP[0] != 0xfc || nextHopIP[1] != 0x00 { continue }

                                hwAddr := update.Neigh.HardwareAddr
                                if len(hwAddr) < 6 { continue }

                                valBytes := make([]byte, 12)
                                copy(valBytes[0:6], hwAddr)
                                binary.BigEndian.PutUint32(valBytes[8:12], uint32(update.Neigh.LinkIndex))

                                // 🏛️ 乾乾淨淨，只寫入全網唯一的焊接實體表
                                _ = macMap.Put(nextHopIP, valBytes)
                                log.Printf("⚡ [NETLINK-SYNC] Neighbor Facts Blasted: IP %s -> MAC %s", update.Neigh.IP.String(), hwAddr.String())
                        }
                }
        }()

        // 接入中央大腦 PCE
        var conn net.Conn
        for {
                conn, err = net.Dial("tcp4", "172.20.50.1:20179")
                if err == nil { break }
                time.Sleep(2 * time.Second)
        }
        defer conn.Close()

        headerBytes := make([]byte, 16)
        copy(headerBytes, []byte(hostname))
        conn.Write(headerBytes)

        buf := make([]byte, 4096)
        for {
                n, err := conn.Read(buf)
                if err != nil { break }

                idx := 0
                for idx+19 <= n {
                        if buf[idx] == 0xff && buf[idx+15] == 0xff {
                                msgLen := int(binary.BigEndian.Uint16(buf[idx+16 : idx+18]))
                                if idx+msgLen > n { break }

                                msgBuf := buf[idx : idx+msgLen]
                                msgType := msgBuf[18]

                                if msgType == 2 {
                                        var keyBytes [16]byte
                                        copy(keyBytes[:], msgBuf[19:35]) 

                                        var val Srv6PolicyVal
                                        copy(val.UsidTarget[:], msgBuf[35:51]) 

                                        if len(msgBuf) >= 63 {
                                                val.TenantID = binary.BigEndian.Uint32(msgBuf[51:55])
                                                val.FlexAlgo = binary.BigEndian.Uint32(msgBuf[55:59])
                                        } else {
                                                if hostname == "ubuntu01" || hostname == "ubuntu02" {
                                                        if bytes.Equal(val.UsidTarget[:], make([]byte, 16)) {
                                                                val.TenantID = 0
                                                        } else { val.TenantID = 1 }
                                                } else { val.TenantID = 1 }
                                        }

                                        valBytes := make([]byte, 24)
                                        copy(valBytes[0:16], val.UsidTarget[:])
                                        binary.NativeEndian.PutUint32(valBytes[16:20], val.TenantID)
                                        binary.NativeEndian.PutUint32(valBytes[20:24], val.FlexAlgo)

                                        // 🏛️ 乾乾淨淨，直接灌入全網唯一的 Pinned 共享表
                                        _ = policyMap.Put(keyBytes, valBytes)
                                        log.Printf("🔥 [POLICY-BURST] Injected explicit route into Pinned Policy Map. TenantID: %d", val.TenantID)
                                }

                                if msgType == 3 {
                                        var keyBytes [16]byte
                                        copy(keyBytes[:], msgBuf[19:35])
                                        valBytes := make([]byte, 12)
                                        copy(valBytes[0:12], msgBuf[35:47])

                                        // 🏛️ 乾乾淨淨，直接灌入全網唯一的 Pinned 共享表
                                        _ = macMap.Put(keyBytes, valBytes)
                                        log.Printf("⚡ [LOCAL-MAC-BURST] Injected burst into Pinned Map!")
                                }

                                idx += msgLen
                        } else {
                                idx++
                        }
                }
        }
        select {}
}
