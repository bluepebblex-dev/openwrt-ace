package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"
)

// runVPNRefresh force-refreshes the VPN Gate node cache. LuCI's "刷新节点"
// button shells out to this, in the same hidden-command pattern as `core`
// and `geo` (main.go dispatches it before the public command table).
//
// The pipeline is exactly the one the Windows bridge's `vpn_refresh` action
// runs: direct HTTPS fetch -> parse -> classify (home broadband vs DC) ->
// probe latency -> sort -> save. Only the cache file is written; no route,
// DNS, tunnel or core config is read or changed, so a refresh can run while
// the service is up without interrupting the connection.
//
// Stage messages go to stderr (LuCI captures them into the log panel); one
// JSON line on stdout reports the result so the CLI is scriptable:
//
//	{"ok":true,"count":380,"countries":49,"at":1763820000}
func runVPNRefresh(args []string) int {
	fs := flag.NewFlagSet("vpn-refresh", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}

	stage := func(s string) { fmt.Fprintln(os.Stderr, s) }
	finish := func(ok bool, count, countries int) {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(struct {
			OK        bool  `json:"ok"`
			Count     int   `json:"count"`
			Countries int   `json:"countries"`
			At        int64 `json:"at"`
		}{OK: ok, Count: count, Countries: countries, At: time.Now().Unix()})
	}

	stage("正在获取 VPN Gate 节点…")
	// The bridge uses 90s for the whole pipeline; give the latency phase a
	// little more room on a slow router (the fetch alone measured ~5s here).
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	raw, err := fetchVPNGateDirect(ctx)
	if err != nil {
		stage("VPN Gate 获取失败：" + err.Error())
		finish(false, 0, 0)
		return 1
	}
	nodes := parseVPNGateCSV(raw)
	if len(nodes) == 0 {
		stage("VPN Gate 返回的列表为空")
		finish(false, 0, 0)
		return 1
	}

	stage(fmt.Sprintf("已获取 %d 个节点，正在识别家宽/机房…", len(nodes)))
	enrichCtx, ecancel := context.WithTimeout(context.Background(), 30*time.Second)
	_, _ = enrichVPNGateClasses(enrichCtx, &http.Client{Timeout: 15 * time.Second}, nodes)
	ecancel()

	stage("正在测量节点延迟…")
	measureVPNGateLatency(ctx, nodes)
	sortVPNGateNodesByLatency(nodes)
	saveVPNGateCache(nodes)

	countries := vpnGateCountries(nodes)
	stage(fmt.Sprintf("完成：%d 个节点，%d 个国家", len(nodes), len(countries)))
	finish(true, len(nodes), len(countries))
	return 0
}
