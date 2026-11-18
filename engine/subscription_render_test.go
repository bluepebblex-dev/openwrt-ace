package main

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xhwarp/warp-client/internal/core"
)

// The carrier has to end up as an outbound of its own, with the outermost WARP
// outbound dialling through it. Rendering order matters: mihomo resolves the
// reference by name at config load, so a wrong name or a missing proxy is a
// core that refuses to start, not a slow connect.
func TestRenderInjectSubscriptionCarrier(t *testing.T) {
	opts := defaultConnectOptions(protoWG, false, false)
	opts.proxyMode = modeCustom
	opts.subCarrier = true
	opts.subURL = "https://example.com/sub"
	opts.subProxyName = "日本 家宽 01"
	opts.subProxyRaw = "  - name: \"日本 家宽 01\"\n    type: ss\n    server: 1.2.3.4\n    port: 8443\n    cipher: aes-256-gcm\n    password: pw"

	out, err := renderClientConfig(opts, cachedEndpoint{Endpoint: "162.159.192.1:2408"}, protoRun{kind: kindWG, name: protoWG})
	if err != nil {
		t.Fatalf("renderClientConfig: %v", err)
	}
	cfg := string(out)

	if !strings.Contains(cfg, `- name: "日本 家宽 01"`) {
		t.Fatalf("carrier proxy missing from config:\n%s", cfg)
	}
	// The carrier must come first: the first list item is the outermost hop and
	// that is the one the dialer-proxy line was injected into.
	if iCarrier, iSecond := strings.Index(cfg, `"日本 家宽 01"`), strings.Index(cfg[strings.Index(cfg, `"日本 家宽 01"`)+1:], "  - name:"); iCarrier < 0 || iSecond < 0 {
		t.Fatalf("carrier should precede the WARP outbound (carrier@%d, second@%d)", iCarrier, iSecond)
	}
	if !strings.Contains(cfg, `dialer-proxy: "日本 家宽 01"`) {
		t.Fatalf("WARP outbound is not dialled through the carrier:\n%s", cfg)
	}
	// Exactly one dialer-proxy: a doubled line would mean the injection landed
	// on two outbounds (or twice on one) and mihomo would reject the config.
	if n := strings.Count(cfg, "dialer-proxy:"); n != 1 {
		t.Fatalf("want exactly 1 dialer-proxy, got %d:\n%s", n, cfg)
	}
}

// Without the switch nothing about the config may change.
func TestRenderWithoutCarrierIsUnchanged(t *testing.T) {
	opts := defaultConnectOptions(protoWG, false, false)
	out, err := renderClientConfig(opts, cachedEndpoint{Endpoint: "162.159.192.1:2408"}, protoRun{kind: kindWG, name: protoWG})
	if err != nil {
		t.Fatalf("renderClientConfig: %v", err)
	}
	if strings.Contains(string(out), "dialer-proxy:") {
		t.Fatalf("plain session gained a dialer-proxy:\n%s", out)
	}
}

// A carrier parsed from a subscription is not always flat: vmess/vless nodes
// carry ws-opts, reality-opts, headers. If those blocks are spliced at the same
// indent as the proxy's own keys, mihomo reads `path`/`Host` as unknown proxy
// fields and refuses to load - the tunnel dies with a config error that names
// nothing useful. This runs the rendered config through the real core, so the
// verdict is mihomo's, not ours.
//
// Skipped unless WARP_TEST_MIHOMO points at a mihomo executable.
func TestMihomoAcceptsNestedSubscriptionCarrier(t *testing.T) {
	bin := os.Getenv("WARP_TEST_MIHOMO")
	if bin == "" {
		t.Skip("set WARP_TEST_MIHOMO=<path to mihomo> to run the core integration test")
	}
	savedPriv, savedPub := warpPrivateKey, warpPublicKey
	defer func() { warpPrivateKey, warpPublicKey = savedPriv, savedPub }()
	warpPrivateKey = base64.StdEncoding.EncodeToString(make([]byte, 32))
	warpPublicKey = base64.StdEncoding.EncodeToString(make([]byte, 32))

	opts := defaultConnectOptions(protoWG, false, false)
	opts.mixedPort, opts.apiPort = freePort(t), freePort(t)
	opts.proxyMode = modeCustom
	opts.subCarrier = true
	opts.subURL = "https://example.com/sub"
	opts.subProxyName = "香港 01"
	opts.subProxyRaw = strings.Join([]string{
		`  - name: "香港 01"`,
		`    type: vmess`,
		`    server: 203.0.113.7`,
		`    port: 443`,
		`    uuid: 11111111-2222-3333-4444-555555555555`,
		`    alterId: 0`,
		`    cipher: auto`,
		`    tls: true`,
		`    servername: hk.example.com`,
		`    network: ws`,
		`    ws-opts:`,
		`      path: /ray`,
		`      headers:`,
		`        Host: hk.example.com`,
	}, "\n")

	cfg, err := renderClientConfig(opts, cachedEndpoint{Endpoint: "162.159.193.10:443"}, protoRun{kind: kindWG, name: protoWG})
	if err != nil {
		t.Fatalf("renderClientConfig: %v", err)
	}
	c, err := core.New(core.Config{BinaryPath: bin, WorkDir: t.TempDir(), MixedPort: opts.mixedPort, APIPort: opts.apiPort})
	if err != nil {
		t.Fatalf("new core: %v", err)
	}
	if err := c.WriteConfig(cfg); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := c.Start(); err != nil {
		t.Fatalf("start core: %v", err)
	}
	defer c.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := c.WaitReady(ctx); err != nil {
		t.Fatalf("mihomo rejected the carrier config: %v\n--- rendered ---\n%s", err, cfg)
	}
	proxies, err := controllerProxies(opts.apiPort)
	if err != nil {
		t.Fatalf("controller /proxies: %v", err)
	}
	if _, ok := proxies["香港 01"]; !ok {
		t.Fatalf("carrier missing from controller (have: %v)", proxyNames(proxies))
	}
}
