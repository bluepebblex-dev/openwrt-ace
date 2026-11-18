package main

// Subscription carrier ("订阅前置"): a Clash subscription supplies the node the
// WARP tunnel is dialled from. The tunnel itself is unchanged — WARP still
// terminates at Cloudflare; only the hop that carries it is one the user owns,
// which is what turns "a WARP exit" into an exit that keeps the carrier's
// address family and reputation.
//
// The node's YAML is kept verbatim (see internal/subscription) and spliced into
// the generated config, with the outermost WARP outbound pointed at it through
// mihomo's dialer-proxy. That is the same mechanism the WARP-in-WARP chain and
// the OpenVPN exit already use, so nothing new happens at runtime.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xhwarp/warp-client/internal/filelock"
	"github.com/xhwarp/warp-client/internal/subscription"
)

const (
	subCacheName = "subscription.json"
	// subCacheTTL is how long a fetched list is reused. Connect happens often
	// (retries, repairs); re-downloading on each attempt would add a round trip
	// to every one of them and hammer the panel.
	subCacheTTL = 10 * time.Minute
)

// subCacheFile is the on-disk list with the URL it came from.
type subCacheFile struct {
	URL   string              `json:"url"`
	At    time.Time           `json:"at"`
	Nodes []subscription.Node `json:"nodes"`
}

func subCachePath() (string, error) {
	d, err := appDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, subCacheName), nil
}

func loadSubCache() (subCacheFile, bool) {
	p, err := subCachePath()
	if err != nil {
		return subCacheFile{}, false
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return subCacheFile{}, false
	}
	var f subCacheFile
	if json.Unmarshal(raw, &f) != nil {
		return subCacheFile{}, false
	}
	return f, true
}

func saveSubCache(f subCacheFile) error {
	p, err := subCachePath()
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return filelock.WithLock(p, func() error {
		return writeVPNGateFile(p, raw)
	})
}

// fetchSubscription returns the nodes for rawURL, preferring the cache when it
// is fresh for this URL. When the panel cannot be reached the last good list is
// returned instead: a session that worked five minutes ago should not break
// because the subscription host is momentarily unreachable — and a connect must
// not fail just because the account's panel is down.
func fetchSubscription(rawURL string, force bool) ([]subscription.Node, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errors.New("订阅地址为空")
	}
	cache, haveCache := loadSubCache()
	cacheUsable := haveCache && cache.URL == rawURL && len(cache.Nodes) > 0
	if cacheUsable && !force && time.Since(cache.At) < subCacheTTL {
		return cache.Nodes, nil
	}
	nodes, err := subscription.Fetch(rawURL)
	if err != nil {
		if cacheUsable {
			stageMsg(fmt.Sprintf("订阅拉取失败（%v），沿用 %s 的缓存节点", err, humanAge(time.Since(cache.At))))
			return cache.Nodes, nil
		}
		return nil, err
	}
	if err := saveSubCache(subCacheFile{URL: rawURL, At: time.Now(), Nodes: nodes}); err != nil {
		// A cache write failure is not fatal: the nodes are already in hand.
		fmt.Fprintln(os.Stderr, errPal.warn("订阅缓存未写入: "+err.Error()))
	}
	return nodes, nil
}

// resolveSubscriptionCarrier fills opts.subProxyRaw/subProxyName for rendering.
// Pinned node first; when the panel has rotated it away, the fastest reachable
// node takes over so the session still connects (and says so).
func resolveSubscriptionCarrier(opts *options) error {
	if !opts.subCarrier {
		return nil
	}
	nodes, err := fetchSubscription(opts.subURL, false)
	if err != nil {
		return fmt.Errorf("订阅前置不可用: %w", err)
	}
	lat := subscription.Latencies(nodes, 2*time.Second, 12)
	node, ok := subscription.Pick(nodes, opts.subNode, lat)
	if !ok {
		return errors.New("订阅前置：没有可用节点")
	}
	if opts.subNode != "" && node.Name != opts.subNode {
		stageMsg(fmt.Sprintf("订阅里找不到固定节点「%s」（已轮换？），改用最快的 %s", opts.subNode, node.Name))
	}
	opts.subProxyRaw = node.Raw
	opts.subProxyName = node.Name
	stageMsg(fmt.Sprintf("订阅前置已就绪：%s（%s:%d）", node.Name, node.Server, node.Port))
	return nil
}

// injectCarrierDialer points the first outbound in proxyBody at the carrier
// node. The first item is the outermost hop by construction: the single WARP
// outbound, the chain's outer half, or the base under a Psiphon/OpenVPN exit.
// Everything above it then reaches the internet through the subscription node.
func injectCarrierDialer(proxyBody, name string) string {
	if name == "" {
		return proxyBody
	}
	lines := strings.Split(proxyBody, "\n")
	for i, ln := range lines {
		if !strings.HasPrefix(ln, "  - ") {
			continue
		}
		out := make([]string, 0, len(lines)+1)
		out = append(out, lines[:i+1]...)
		out = append(out, "    dialer-proxy: "+yamlScalar(quoted(name)))
		out = append(out, lines[i+1:]...)
		return strings.Join(out, "\n")
	}
	return proxyBody
}

// humanAge renders a cache age the way the log lines read best.
func humanAge(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%d 秒前", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
	}
	return fmt.Sprintf("%d 小时前", int(d.Hours()))
}
