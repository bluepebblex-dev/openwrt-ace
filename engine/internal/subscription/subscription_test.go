package subscription

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A Clash subscription is spliced back verbatim, so the thing worth pinning is
// that the item boundaries, indentation and top-level scalars survive: a node
// whose keys drift under the wrong indent makes mihomo reject the whole config.
func TestParseClashYAML(t *testing.T) {
	body := `port: 7890
proxies:
  - name: "日本 家宽 01"
    type: ss
    server: 1.2.3.4
    port: 8443
    cipher: aes-256-gcm
    password: pass123
    ws-opts:
      path: /ws
      headers:
        Host: cdn.example.com
  - name: hk-02
    type: trojan
    server: hk.example.com
    port: 443
    password: pw
proxy-groups:
  - name: auto
    type: url-test
    proxies:
      - "日本 家宽 01"
rules:
  - MATCH,auto
`
	nodes, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes, got %d", len(nodes))
	}
	if nodes[0].Name != "日本 家宽 01" || nodes[0].Type != "ss" || nodes[0].Server != "1.2.3.4" || nodes[0].Port != 8443 {
		t.Fatalf("first node wrong: %+v", nodes[0])
	}
	// The nested ws-opts block must still be there and still be nested.
	if !strings.Contains(nodes[0].Raw, "    ws-opts:") {
		t.Fatalf("ws-opts lost its nesting:\n%s", nodes[0].Raw)
	}
	if !strings.HasPrefix(nodes[0].Raw, "  - name:") {
		t.Fatalf("item not indented for a proxies: block:\n%s", nodes[0].Raw)
	}
	if nodes[1].Name != "hk-02" || nodes[1].Port != 443 {
		t.Fatalf("second node wrong: %+v", nodes[1])
	}
}

// The plain /sub/ link is base64-wrapped and carries no YAML at all.
func TestParseBase64URIList(t *testing.T) {
	vmessJSON, _ := json.Marshal(map[string]any{
		"v": "2", "ps": "vmess-node", "add": "5.6.7.8", "port": "443",
		"id": "11111111-2222-3333-4444-555555555555", "aid": "0",
		"scy": "auto", "net": "ws", "host": "cdn.example.com", "path": "/ray", "tls": "tls",
	})
	list := strings.Join([]string{
		"ss://" + base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pw")) + "@9.9.9.9:8388#ss-node",
		"trojan://secret@t.example.com:443?sni=t.example.com&type=ws&path=%2Ft#trojan-node",
		"vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@v.example.com:443?encryption=none&security=tls&sni=v.example.com&type=grpc&serviceName=gsvc#vless-node",
		"vmess://" + base64.StdEncoding.EncodeToString(vmessJSON),
	}, "\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(list))

	nodes, err := Parse([]byte(encoded))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(nodes) != 4 {
		t.Fatalf("want 4 nodes, got %d: %+v", len(nodes), nodes)
	}
	want := map[string]string{
		"ss-node":     "ss",
		"trojan-node": "trojan",
		"vless-node":  "vless",
		"vmess-node":  "vmess",
	}
	for _, n := range nodes {
		if want[n.Name] != n.Type {
			t.Fatalf("node %q: type %q, want %q", n.Name, n.Type, want[n.Name])
		}
		if n.Port == 0 || n.Server == "" {
			t.Fatalf("node %q missing address: %+v", n.Name, n)
		}
	}

	// Spot-check the dialect conversion, not just the bookkeeping: vmess is the
	// one whose fields live in JSON and whose ws path/tls must reach mihomo.
	for _, n := range nodes {
		if n.Name != "vmess-node" {
			continue
		}
		for _, want := range []string{"type: vmess", "network: ws", "path: /ray", "tls: true", "servername: cdn.example.com"} {
			if !strings.Contains(n.Raw, want) {
				t.Fatalf("vmess node missing %q:\n%s", want, n.Raw)
			}
		}
	}
}

// An expired token answers 200 with an HTML page. That must read as "no nodes",
// not as a parse crash or, worse, as a node named after an HTML tag.
func TestParseRejectsNonSubscription(t *testing.T) {
	if _, err := Parse([]byte("<html><body>token expired</body></html>")); err == nil {
		t.Fatal("expected an error for an HTML body")
	}
	if _, err := Parse(nil); err == nil {
		t.Fatal("expected an error for an empty body")
	}
}

func TestPickFallsBackToFastest(t *testing.T) {
	nodes := []Node{{Name: "a"}, {Name: "b"}, {Name: "c"}}
	lat := map[string]int64{"a": 0, "b": 120, "c": 40}
	if n, _ := Pick(nodes, "a", lat); n.Name != "a" {
		t.Fatalf("pinned node not honoured: %+v", n)
	}
	if n, _ := Pick(nodes, "gone", lat); n.Name != "c" {
		t.Fatalf("fallback should pick the fastest reachable, got %+v", n)
	}
	if _, ok := Pick(nil, "", lat); ok {
		t.Fatal("empty list must not produce a node")
	}
}

// Names are user-visible and often contain spaces or colons; an unquoted colon
// would split the mapping and break the config.
func TestYAMLQuote(t *testing.T) {
	cases := map[string]string{
		`hk-02`:      `hk-02`,
		`日本 家宽 01`:   `"日本 家宽 01"`,
		`a:b`:        `"a:b"`,
		`#1`:         `"#1"`,
		`with"quote`: `"with\"quote"`,
	}
	for in, want := range cases {
		if got := yamlQuote(in); got != want {
			t.Fatalf("yamlQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

// A dead link is the single most common way this feature fails, and the panel
// answers 403 with a JSON reason rather than an empty body. Passing that reason
// through is what separates "your link expired" from "our client is broken", so
// the wording is pinned here.
func TestFetchSurfacesPanelReason(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		want    []string
		notWant []string
	}{
		{
			name:   "xboard token error",
			status: 403,
			body:   `{"status":"fail","message":"token is error","data":null,"error":null}`,
			want:   []string{"HTTP 403", "token is error", "重新复制订阅地址"},
		},
		{
			name:   "expired",
			status: 403,
			body:   `{"message":"订阅已过期"}`,
			want:   []string{"订阅已过期"},
		},
		{
			name:    "nginx default title is redundant",
			status:  404,
			body:    "<html><head><title>404 Not Found</title></head></html>",
			notWant: []string{"404 Not Found（HTTP"},
			want:    []string{"HTTP 404", "路径不对"},
		},
		{
			name:   "server fault",
			status: 502,
			body:   "",
			want:   []string{"HTTP 502", "稍后重试"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer srv.Close()
			_, err := Fetch(srv.URL)
			if err == nil {
				t.Fatal("expected an error for a non-200 subscription")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q missing %q", err.Error(), w)
				}
			}
			for _, nw := range tc.notWant {
				if strings.Contains(err.Error(), nw) {
					t.Errorf("error %q should not contain %q", err.Error(), nw)
				}
			}
		})
	}
}

// A real panel's YAML is far wider than the minimal fixture: nested option
// blocks, quoted names with colons, and entries whose extra keys mihomo owns.
// None of it may confuse the item splitter or the top-level scalar reader.
func TestParseRealisticPanelYAML(t *testing.T) {
	body := `mixed-port: 7890
proxies:
  - name: "🇭🇰 香港 01 | 1x"
    type: vmess
    server: hk1.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    alterId: 0
    cipher: auto
    tls: true
    servername: hk1.example.com
    network: ws
    ws-opts:
      path: /ray
      headers:
        Host: hk1.example.com
  - name: 日本 02: 专线
    type: trojan
    server: jp2.example.com
    port: 8443
    password: "p@ss:word"
    sni: jp2.example.com
    skip-cert-verify: true
  - {name: 新加坡 03, type: ss, server: sg3.example.com, port: 8388, cipher: aes-256-gcm, password: secret}
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - 日本 02: 专线
rules:
  - MATCH,PROXY
`
	nodes, err := Parse([]byte(body))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(nodes) != 3 {
		t.Fatalf("want 3 nodes, got %d: %+v", len(nodes), nodes)
	}
	if nodes[0].Name != "🇭🇰 香港 01 | 1x" || nodes[0].Server != "hk1.example.com" || nodes[0].Port != 443 {
		t.Errorf("node 0 mis-parsed: %+v", nodes[0])
	}
	// The nested host must not overwrite the node's server, and the block must
	// stay one level deeper than the keys or mihomo reads `path` as a proxy key.
	if !strings.Contains(nodes[0].Raw, "\n      path: /ray") {
		t.Errorf("ws-opts indentation lost from raw:\n%s", nodes[0].Raw)
	}
	if nodes[1].Name != "日本 02: 专线" || nodes[1].Port != 8443 {
		t.Errorf("quoted name with colon mis-parsed: %+v", nodes[1])
	}
	if nodes[2].Type != "ss" || nodes[2].Port != 8388 {
		t.Errorf("flow-style item mis-parsed: %+v", nodes[2])
	}
	// proxy-groups must not leak in as a node.
	for _, n := range nodes {
		if n.Name == "PROXY" {
			t.Error("proxy-groups leaked into the node list")
		}
	}
}

// Latency uses 0 as "unreachable", so a loopback handshake that completes in
// under a millisecond still has to come back non-zero - otherwise a local or
// LAN node sorts to the bottom of the picker as if it were dead.
func TestLatencyNeverReturnsZeroForAReachableNode(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	if ms := Latency(Node{Server: host, Port: port}, time.Second); ms < 1 {
		t.Fatalf("reachable node measured %dms, want >=1", ms)
	}
	// A closed port must stay at the sentinel.
	if ms := Latency(Node{Server: host, Port: 1}, 500*time.Millisecond); ms != 0 {
		t.Fatalf("closed port measured %dms, want 0", ms)
	}
}

// A plain subscription often mixes in bare http/socks5 hops. They used to be
// skipped, which could empty the whole picker when that was all the panel
// served; they must come out as first-class mihomo entries with credentials.
func TestParseHTTPAndSocks5URIs(t *testing.T) {
	list := strings.Join([]string{
		`http://alice:secret@203.0.113.9:8080#HTTP%20%E8%8A%82%E7%82%B9`,
		`socks5://bob:pw@203.0.113.10:1080#SOCKS%20%E8%8A%82%E7%82%B9`,
	}, "\n")
	nodes, err := Parse([]byte(base64.StdEncoding.EncodeToString([]byte(list))))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("want 2 nodes, got %d", len(nodes))
	}
	if nodes[0].Type != "http" || nodes[0].Port != 8080 || nodes[0].Name != "HTTP 节点" {
		t.Errorf("http node mis-parsed: %+v", nodes[0])
	}
	for _, want := range []string{"username: alice", "password: secret"} {
		if !strings.Contains(nodes[0].Raw, want) {
			t.Errorf("http node lost %q:\n%s", want, nodes[0].Raw)
		}
	}
	if nodes[1].Type != "socks5" || nodes[1].Port != 1080 || nodes[1].Name != "SOCKS 节点" {
		t.Errorf("socks5 node mis-parsed: %+v", nodes[1])
	}
	if !strings.Contains(nodes[1].Raw, "version: 5") {
		t.Errorf("socks5 version missing:\n%s", nodes[1].Raw)
	}
}
