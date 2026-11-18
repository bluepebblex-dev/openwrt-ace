package main

import (
	"fmt"
	"os"
	"time"

	"github.com/bluepebblex-dev/openwrt-ace/engine/internal/subscription"
)

func main() {
	nodes, err := subscription.Fetch(os.Args[1])
	if err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	fmt.Printf("共 %d 个节点\n", len(nodes))
	lat := subscription.Latencies(nodes, 3*time.Second, 12)
	for i, n := range nodes {
		if i > 4 {
			break
		}
		fmt.Printf("- %s [%s] %s:%d  %dms\n", n.Name, n.Type, n.Server, n.Port, lat[n.Name])
	}
	if len(nodes) > 0 {
		fmt.Println("--- raw 样例 ---")
		fmt.Println(nodes[0].Raw)
	}
}
