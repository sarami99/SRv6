package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	pb "path/to/firewall/proto" // Import your generated proto
	"google.golang.org/grpc"
)

// Global map reference
var routingMap *ebpf.Map

type server struct {
	pb.UnimplementedFirewallAgentServer
}

// Implement the gRPC UpdateRule function
func (s *server) UpdateRule(ctx context.Context, req *pb.Rule) (*pb.UpdateResponse, error) {
	log.Printf("Lieutenant received order: %s -> %s", req.Cidr, req.Action)

	// 1. Convert CIDR string to IP/Prefix
	ip, ipNet, err := net.ParseCIDR(req.Cidr)
	if err != nil {
		return &pb.UpdateResponse{Success: false, Message: "Invalid CIDR"}, nil
	}
	prefixLen, _ := ipNet.Mask.Size()

    // 2. Prepare the Key for LPM Trie
    // Note: LPM keys require careful struct packing in Go to match C
	key := struct {
		PrefixLen uint32
		Data      uint32
	}{
		PrefixLen: uint32(prefixLen),
		Data:      ip2int(ip), // Helper function to convert IP to uint32
	}

    // 3. Prepare the Value
	value := struct {
		Action  uint32
		IfIndex uint32
	}{
		Action:  uint32(req.Action),
		IfIndex: req.RedirectIfindex,
	}

    // 4. Update the Kernel Map (Atomic Operation)
	if err := routingMap.Put(key, value); err != nil {
		log.Printf("Failed to update map: %v", err)
		return &pb.UpdateResponse{Success: false, Message: err.Error()}, nil
	}

	return &pb.UpdateResponse{Success: true, Message: "Rule Applied"}, nil
}

func main() {
	// Allow locking memory for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// 1. Load Pre-compiled eBPF objects
	spec, err := ebpf.LoadCollectionSpec("xdp_soldier.o")
	if err != nil {
		log.Fatalf("Failed to load objects: %v", err)
	}

    // 2. Load into Kernel
	objs := struct {
		XdpProg     *ebpf.Program `ebpf:"xdp_prog"`
		RoutingTable *ebpf.Map     `ebpf:"routing_table"`
	}{}
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("Loading objects: %v", err)
	}
	defer objs.XdpProg.Close()
	defer objs.RoutingTable.Close()
    
    // Assign global map for the gRPC handler to use
    routingMap = objs.RoutingTable

	// 3. Attach to Interface (e.g., eth0)
	iface, _ := net.InterfaceByName("eth0")
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Attach XDP: %v", err)
	}
	defer l.Close()

	log.Println("Lieutenant is on duty. XDP Attached. Listening for General...")

	// 4. Start gRPC Server
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterFirewallAgentServer(s, &server{})
	
    if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}

// Helper: ip2int converts net.IP to uint32 (Big Endian logic needed here)
func ip2int(ip net.IP) uint32 {
	if len(ip) == 16 {
		return uint32(ip[12])<<24 | uint32(ip[13])<<16 | uint32(ip[14])<<8 | uint32(ip[15])
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}
