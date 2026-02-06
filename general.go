package main

import (
	"context"
	"log"
	"time"

	pb "path/to/firewall/proto"
	"google.golang.org/grpc"
)

func main() {
	// 1. Connect to the Lieutenant (Market Data Plant)
	conn, err := grpc.Dial("10.20.30.40:50051", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	client := pb.NewFirewallAgentClient(conn)

	// 2. Scenario: "Scrub Centra" detects a DDoS from 185.x.x.x
	log.Println("General: Attack Detected. Deploying countermeasures...")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

    // 3. Issue Command: DROP everything from 185.100.0.0/16
	r, err := client.UpdateRule(ctx, &pb.Rule{
		Cidr:   "185.100.0.0/16",
		Action: pb.Action_DROP,
	})

	if err != nil {
		log.Fatalf("Lieutenant failed to execute: %v", err)
	}

	log.Printf("General: Orders received. Status: %s", r.Message)
    
    // 4. Issue Command: Redirect Safe Traffic to Arista (Interface Index 3)
    // "Traffic from 8.8.8.8 is safe, send to uplink"
    client.UpdateRule(ctx, &pb.Rule{
		Cidr:            "8.8.8.8/32",
		Action:          pb.Action_REDIRECT,
		RedirectIfindex: 3,
	})
}
