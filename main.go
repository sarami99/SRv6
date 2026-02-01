package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	// 1. GoBGP Imports (Control Plane)
	gobgpapi "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"

	// 2. GoVPP Imports (Data Plane)
	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/api"
	
	// 3. Your Generated VPP Bindings (Make sure to generate these first!)
	// These paths depend on where you ran binapi-generator
	interfaces "my-project/binapi/interface"
	ip "my-project/binapi/ip" 
)

// Config
const (
	GoBGP_Address = "127.0.0.1:50051" // GoBGP gRPC Port
	VPP_Socket    = "/run/vpp/api.sock" // VPP Shared Memory Socket
)

func main() {
	// =================================================================
	// STEP 1: Connect to VPP (The Muscle)
	// =================================================================
	fmt.Println("[Glue] Connecting to VPP Data Plane...")
	conn, err := govpp.Connect(VPP_Socket)
	if err != nil {
		log.Fatalf("Error connecting to VPP: %v", err)
	}
	defer conn.Disconnect()

	// Create a channel to send API commands
	vppChannel, err := conn.NewAPIChannel()
	if err != nil {
		log.Fatalf("Error creating VPP API channel: %v", err)
	}
	defer vppChannel.Close()
	fmt.Println("[Glue] VPP Connected.")

	// =================================================================
	// STEP 2: Connect to GoBGP (The Brain)
	// =================================================================
	fmt.Println("[Glue] Connecting to GoBGP Control Plane...")
	bgpConn, err := grpc.Dial(GoBGP_Address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Error connecting to GoBGP: %v", err)
	}
	defer bgpConn.Close()
	bgpClient := gobgpapi.NewGobgpApiClient(bgpConn)
	fmt.Println("[Glue] GoBGP Connected.")

	// =================================================================
	// STEP 3: Monitor BGP Updates (The Loop)
	// =================================================================
	// We want to listen for IPv6 Unicast routes (SRv6 usually flows here)
	stream, err := bgpClient.MonitorTable(context.Background(), &gobgpapi.MonitorTableRequest{
		TableType: gobgpapi.TableType_GLOBAL,
		Family: &gobgpapi.Family{
			Afi:  gobgpapi.Family_AFI_IP6,
			Safi: gobgpapi.Family_SAFI_UNICAST,
		},
	})
	if err != nil {
		log.Fatalf("Error subscribing to BGP updates: %v", err)
	}

	fmt.Println("[Glue] Listening for SRv6/IPv6 Routes...")

	for {
		// Block until GoBGP sends an update
		recv, err := stream.Recv()
		if err != nil {
			log.Printf("BGP Stream Error: %v", err)
			break // In production, add reconnect logic here
		}

		// Process the Path (Route)
		if path := recv.Path; path != nil {
			// This is where you extract the specific SRv6 logic
			handleRouteUpdate(vppChannel, path)
		}
	}
}

// =================================================================
// STEP 4: The Translation Logic (GoBGP -> VPP)
// =================================================================
func handleRouteUpdate(ch api.Channel, path *gobgpapi.Path) {
	// 1. Decode Prefix (e.g., 2001:db8:A::/64)
	var prefix string
	var prefixLen uint8
	
	// (Simplification: Decoding NLRI from GoBGP Protobuf)
	// In real code, use gobgp/pkg/packet/bgp helpers to unmarshal path.Nlri
	// For this demo, let's assume we extracted:
	prefix = "2001:db8:dest::"
	prefixLen = 64
	nextHop := "2001:db8:spine::1" // Extracted from BGP Attributes

	fmt.Printf("[Glue] Received BGP Route: %s/%d via %s\n", prefix, prefixLen, nextHop)

	// 2. Determine Action (Add or Delete)
	isWithdraw := path.IsWithdraw
	
	// 3. Construct VPP API Message
	// We use the generated 'ip' package struct
	vppRoute := &ip.IPRouteAddDel{
		IsAdd:       !isWithdraw, // True = Add, False = Delete
		IsMultipath: false,
		Route: ip.IPRoute{
			TableID: 0, // Default VRF
			Prefix: ip.Prefix{
				Address: parseIP(prefix), // Helper to convert string to VPP IP type
				Len:     prefixLen,
			},
			Paths: []ip.FibPath{
				{
					SwIfIndex:  ^uint32(0), // Recursive lookup (no specific interface)
					TableID:    0,
					Nh: ip.FibPathNh{
						Address: parseIP(nextHop),
					},
					// *** SRv6 MAGIC HAPPENS HERE ***
					// If this was an SR Policy, you would attach the SID List label stack here.
					// For basic routing, we just set the Next Hop.
				},
			},
		},
	}

	// 4. Send to VPP
	req := &ip.IPRouteAddDelReply{}
	err := ch.SendRequest(vppRoute).ReceiveReply(req)
	
	if err != nil {
		log.Printf("Failed to program VPP: %v", err)
	} else if req.Retval != 0 {
		log.Printf("VPP rejected route (Retval %d)", req.Retval)
	} else {
		fmt.Printf(" -> Successfully programmed into VPP FIB.\n")
	}
}

// Helper: Parse string IP to VPP API format
func parseIP(ipStr string) ip.Address {
	parsed := net.ParseIP(ipStr)
	var addr ip.Address
	// Handle IPv6 mapping to VPP Union type...
	// (Actual implementation requires handling the VPP IPUnion struct)
	return addr
}
