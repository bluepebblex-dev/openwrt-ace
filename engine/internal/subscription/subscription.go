// Package subscription turns a Clash-style subscription link into the proxy
// entries this client can render as the outermost hop of a session.
//
// Two shapes cover essentially every panel people hand out a link for:
//
//   - a Clash/mihomo config whose `proxies:` block is what we want (CF New, BPB
//     and most "clash 订阅" endpoints serve this), and
//   - the plain URI list (ss/vmess/vless/trojan/hysteria2, plus plain
//     http/socks5 hops), usually base64 encoded, which is what a bare /sub/
//     link returns.
//
// The Clash case is deliberately textual: a proxy item can carry dozens of
// keys whose exact spelling mihomo owns (ws-opts, reality-opts,
// client-fingerprint, …). Round-tripping them through a struct would silently
// drop the ones we did not model, so the raw item text is kept verbatim and
// spliced back into the generated config. Only name/type/server/port are
// extracted, because those are what the picker shows and what the dialer-proxy
// reference needs.
package subscription

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Node is one proxy from the subscription.
type Node struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Server string `json:"server"`
	Port   int    `json:"port"`
	// Raw is the node as a list item ready for a top-level `proxies:` block,
	// i.e. `  - name: …` with continuation lines indented by four spaces.
	Raw string `json:"raw"`
}

// ErrNoNodes means the body parsed cleanly but carried nothing usable - a
// panel returning an HTML login page, an expired token, or an empty group.
var ErrNoNodes = errors.New("订阅里没有可用节点")

// maxBody caps a subscription at 8 MiB. Real ones are tens of kilobytes; the
// cap only exists so a misconfigured URL streaming a file cannot fill memory.
const maxBody = 8 << 20

// HTTPClient is the client Fetch uses. The zero value is fine: it honours the
// standard proxy environment, which is what a desktop install expects.
var HTTPClient = &http.Client{Timeout: 20 * time.Second}

// Fetch downloads rawURL and parses it.
func Fetch(rawURL string) ([]Node, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errors.New("订阅地址为空")
	}
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("订阅地址无效: %s", rawURL)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	// Panels branch on this: without a Clash UA they hand back the plain URI
	// list (or refuse), and the YAML form carries far more of the node's
	// settings intact than we can rebuild from a URI.
	req.Header.Set("User-Agent", "clash.meta/1.19.0 mihomo/1.19.0")
	req.Header.Set("Accept", "*/*")
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("订阅下载失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("订阅读取失败: %w", err)
	}
	return Parse(body)
}

// statusError renders a non-200 answer. Panels put the actual reason in the
// body ("token is error", "订阅已过期", "设备数超限"), and that one sentence is
// what tells the user to re-copy their link instead of blaming the network —
// so it is worth reading the body even though the request already failed.
func statusError(resp *http.Response) error {
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	msg := panelMessage(snippet)
	hint := statusHint(resp.StatusCode)
	if msg != "" {
		return fmt.Errorf("订阅被服务器拒绝（HTTP %d：%s）%s", resp.StatusCode, msg, hint)
	}
	return fmt.Errorf("订阅下载失败（HTTP %d）%s", resp.StatusCode, hint)
}

// statusHint turns the status code into the next thing the user should try,
// worded for the panel case rather than for a generic API.
func statusHint(code int) string {
	switch code {
	case http.StatusUnauthorized, http.StatusForbidden:
		return "，链接可能已过期、被重置或复制不完整，请到面板重新复制订阅地址"
	case http.StatusNotFound:
		return "，地址路径不对，请确认复制了完整的订阅链接"
	}
	if code >= 500 {
		return "，服务器暂时异常，请稍后重试"
	}
	return ""
}

// panelMessage digs the human-readable reason out of an error body: the JSON
// shape most panels (v2board / Xboard and forks) answer with, or failing that
// an HTML <title> that is more than nginx's default status line.
func panelMessage(body []byte) string {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return ""
	}
	if strings.HasPrefix(text, "{") {
		var m map[string]any
		if json.Unmarshal([]byte(text), &m) == nil {
			for _, k := range []string{"message", "msg", "error", "errors", "detail"} {
				if v, ok := m[k]; ok {
					if s := scalarText(v); s != "" {
						return clipRunes(s, 120)
					}
				}
			}
		}
	}
	if i := strings.Index(strings.ToLower(text), "<title>"); i >= 0 {
		rest := text[i+len("<title>"):]
		if j := strings.Index(rest, "</title>"); j >= 0 {
			title := strings.TrimSpace(rest[:j])
			// "403 Forbidden" adds nothing to the code we already print.
			if title != "" && !isStatusLine(title) {
				return clipRunes(title, 120)
			}
		}
	}
	return ""
}

// scalarText flattens the JSON value shapes a panel may use for its reason
// field: a string, a list of strings, or an object keyed by field name.
func scalarText(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			if s := scalarText(item); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "；")
	case map[string]any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			if s := scalarText(item); s != "" {
				parts = append(parts, s)
			}
		}
		sort.Strings(parts)
		return strings.Join(parts, "；")
	}
	return ""
}

// isStatusLine reports whether text is just "<code> <reason>", the generic
// phrasing every web server emits.
func isStatusLine(text string) bool {
	for code := 400; code < 600; code++ {
		if text == fmt.Sprintf("%d %s", code, http.StatusText(code)) {
			return true
		}
	}
	return false
}

func clipRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// Parse reads a subscription body in either supported shape.
func Parse(body []byte) ([]Node, error) {
	text := strings.TrimSpace(strings.TrimPrefix(string(body), "\ufeff"))
	if text == "" {
		return nil, ErrNoNodes
	}
	if nodes, ok := parseClash(text); ok {
		return nodes, nil
	}
	// A URI list is usually base64 (standard, then URL-safe, with or without
	// padding). Decode only when the body does not already look like URIs:
	// decoding plaintext would corrupt it.
	if !strings.Contains(text, "://") {
		if decoded, ok := decodeBase64(text); ok {
			text = strings.TrimSpace(decoded)
		}
	}
	nodes := parseURIs(text)
	if len(nodes) == 0 {
		return nil, ErrNoNodes
	}
	return nodes, nil
}

// parseClash extracts the `proxies:` block. ok is false when the body is not a
// Clash config at all, which sends Parse down the URI-list path.
func parseClash(text string) ([]Node, bool) {
	lines := strings.Split(text, "\n")
	start := -1
	for i, ln := range lines {
		if strings.TrimRight(ln, " \t\r") == "proxies:" {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return nil, false
	}
	// Collect items: a line starting with "- " (at any indent) opens a new
	// proxy; everything indented under it belongs to that proxy. The block
	// ends at the first top-level key after it (proxy-groups:, rules:, …).
	var items [][]string
	var cur []string
	dashIndent := -1
	for _, ln := range lines[start:] {
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			if len(cur) > 0 {
				cur = append(cur, ln)
			}
			continue
		}
		indent := len(ln) - len(strings.TrimLeft(ln, " "))
		if strings.HasPrefix(trimmed, "- ") {
			if dashIndent < 0 {
				dashIndent = indent
			}
			if indent == dashIndent {
				if len(cur) > 0 {
					items = append(items, cur)
				}
				cur = []string{ln}
				continue
			}
		} else if indent <= dashIndent && len(cur) > 0 {
			// Back at or above the list indent: the proxies block is over.
			items = append(items, cur)
			cur = nil
			break
		}
		if len(cur) > 0 {
			cur = append(cur, ln)
		}
	}
	if len(cur) > 0 {
		items = append(items, cur)
	}
	if dashIndent < 0 {
		return nil, false
	}
	out := make([]Node, 0, len(items))
	for _, item := range items {
		n, ok := nodeFromClashItem(item, dashIndent)
		if ok {
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// nodeFromClashItem normalises one collected item to the indentation our
// generated config uses, shifting it as a whole rather than re-indenting each
// line: a node's option blocks (ws-opts, reality-opts, headers) are nested one
// level deeper than its scalar keys, and flattening them would turn `path: /ray`
// into a bogus top-level proxy key that mihomo rejects.
func nodeFromClashItem(item []string, dashIndent int) (Node, bool) {
	var norm []string
	for _, ln := range item {
		trimmed := strings.TrimRight(ln, " \t\r")
		body := strings.TrimSpace(trimmed)
		if body == "" {
			continue
		}
		indent := len(trimmed) - len(strings.TrimLeft(trimmed, " "))
		if indent < dashIndent {
			indent = dashIndent
		}
		// 2 for the list item, 4 for its keys, 6+ for nested blocks.
		norm = append(norm, strings.Repeat(" ", 2+indent-dashIndent)+body)
	}
	if len(norm) == 0 {
		return Node{}, false
	}
	// `- {name: x, type: ss, …}` keeps the whole proxy on one line; it is a
	// valid Clash entry and some panels emit it, so expand it into a block.
	if strings.HasPrefix(strings.TrimPrefix(norm[0], "  "), "- {") {
		return flowNode(norm)
	}
	keyPad := 4
	if len(norm) > 1 {
		keyPad = len(norm[1]) - len(strings.TrimLeft(norm[1], " "))
	}
	raw := strings.Join(norm, "\n")
	fields := itemFields(raw, keyPad)
	name := fields["name"]
	if name == "" || fields["server"] == "" {
		return Node{}, false
	}
	port, _ := strconv.Atoi(fields["port"])
	return Node{
		Name:   name,
		Type:   fields["type"],
		Server: fields["server"],
		Port:   port,
		Raw:    raw,
	}, true
}

// flowNode expands a one-line flow mapping into the same block shape a normal
// entry produces, so downstream code never has to care which style the panel
// used. Only scalars are recovered: a flow entry carrying a nested block is rare
// enough that losing it beats emitting half a config.
func flowNode(norm []string) (Node, bool) {
	text := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(norm[0]), "- "))
	if !strings.HasPrefix(text, "{") || !strings.HasSuffix(text, "}") {
		return Node{}, false
	}
	kv := flowFields(strings.TrimSuffix(strings.TrimPrefix(text, "{"), "}"))
	name, server := kv["name"], kv["server"]
	if name == "" || server == "" {
		return Node{}, false
	}
	port, _ := strconv.Atoi(kv["port"])
	if port == 0 {
		return Node{}, false
	}
	b := &itemBuilder{name: name, typ: firstNonEmpty(kv["type"], "ss"), server: server, port: port}
	rest := make([]string, 0, len(kv))
	for k := range kv {
		switch k {
		case "name", "type", "server", "port":
			continue
		}
		rest = append(rest, k)
	}
	sort.Strings(rest)
	for _, k := range rest {
		v := kv[k]
		switch v {
		case "true", "false":
			b.flag(k, v)
		default:
			b.str(k, v)
		}
	}
	return b.node(), true
}

// flowFields splits the inside of a `{…}` mapping on commas that are not
// inside quotes or a nested collection, then unquotes each side.
func flowFields(s string) map[string]string {
	out := map[string]string{}
	var parts []string
	var cur strings.Builder
	var quote byte
	depth := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			cur.WriteByte(c)
			if c == quote && (i == 0 || s[i-1] != '\\') {
				quote = 0
			}
			continue
		case c == '"' || c == '\'':
			quote = c
		case c == '{' || c == '[':
			depth++
		case c == '}' || c == ']':
			depth--
		case c == ',' && depth == 0:
			parts = append(parts, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	if strings.TrimSpace(cur.String()) != "" {
		parts = append(parts, cur.String())
	}
	for _, p := range parts {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" || v == "" {
			continue
		}
		out[k] = yamlUnquote(v)
	}
	return out
}

// itemFields pulls the handful of scalar keys we need out of one YAML item.
// Only lines at the item's key indent are considered: a nested block indents
// its own keys, and matching those would mistake `host:` for the server address.
func itemFields(raw string, keyPad int) map[string]string {
	out := map[string]string{}
	for _, ln := range strings.Split(raw, "\n") {
		indent := len(ln) - len(strings.TrimLeft(ln, " "))
		body := strings.TrimSpace(ln)
		// The item's own `- name:` line sits one level left of the keys; both
		// carry scalars we need.
		if indent != keyPad && !(indent == 2 && strings.HasPrefix(body, "- ")) {
			continue
		}
		body = strings.TrimPrefix(body, "- ")
		k, v, ok := strings.Cut(body, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out[strings.TrimSpace(k)] = yamlUnquote(v)
	}
	return out
}

func yamlUnquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			inner := s[1 : len(s)-1]
			if s[0] == '"' {
				if u, err := strconv.Unquote(s); err == nil {
					return u
				}
			}
			return inner
		}
	}
	return s
}

// yamlQuote renders a scalar safely for the config we emit. A bare hyphen is
// left alone (node names are full of them, and "-" only matters at the start
// of a line); everything that could split a mapping or start a comment is
// quoted with a JSON encoder, which is valid YAML's double-quoted form.
func yamlQuote(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, ":#{}[],&*?|<>=!%@`\"' \t") || strings.HasPrefix(s, "-") || strings.HasPrefix(s, " ") || strings.HasSuffix(s, " ") {
		b, _ := json.Marshal(s)
		return string(b)
	}
	return s
}

// decodeBase64 tries the usual variants a panel may emit.
func decodeBase64(s string) (string, bool) {
	s = strings.Join(strings.Fields(s), "")
	if s == "" || len(s)%4 == 1 {
		return "", false
	}
	encs := []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	}
	for _, enc := range encs {
		if b, err := enc.DecodeString(s); err == nil && len(b) > 0 {
			out := string(b)
			if strings.Contains(out, "://") || strings.Contains(out, "proxies:") {
				return out, true
			}
		}
	}
	return "", false
}

// parseURIs converts the plain URI list. Unknown schemes are skipped rather
// than failing the whole subscription: one exotic node must not cost the user
// every other node in the list.
func parseURIs(text string) []Node {
	var out []Node
	seen := map[string]bool{}
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || !strings.Contains(ln, "://") {
			continue
		}
		n, ok := parseURI(ln)
		if !ok {
			continue
		}
		if n.Name == "" {
			n.Name = net.JoinHostPort(n.Server, strconv.Itoa(n.Port))
		}
		// A duplicate name would break the dialer-proxy reference (mihomo
		// matches groups and references by name), so make them unique.
		base := n.Name
		for i := 2; seen[n.Name]; i++ {
			n.Name = fmt.Sprintf("%s #%d", base, i)
		}
		seen[n.Name] = true
		out = append(out, n)
	}
	return out
}

func parseURI(raw string) (Node, bool) {
	scheme, rest, _ := strings.Cut(raw, "://")
	switch strings.ToLower(scheme) {
	case "vmess":
		return parseVmess(rest)
	case "vless":
		return parseVless(rest)
	case "trojan":
		return parseTrojan(rest)
	case "ss":
		return parseShadowsocks(rest)
	case "hysteria2", "hy2":
		return parseHysteria2(rest)
	case "http", "https":
		return parseSimpleProxy(rest, "http", strings.ToLower(scheme) == "https")
	case "socks", "socks5", "socks5h":
		return parseSimpleProxy(rest, "socks5", false)
	}
	return Node{}, false
}

// parseSimpleProxy handles the http/socks5 entries that plain (base64) lists
// often mix in with the proxy-protocol URIs. They are real usable hops, and
// skipping them can drop every node when a panel serves only this shape.
func parseSimpleProxy(rest, typ string, tls bool) (Node, bool) {
	body, name := splitFragment(rest)
	q := queryOf(body)
	main := stripQuery(body)
	at := strings.LastIndexByte(main, '@')
	var user, pass string
	if at >= 0 {
		cred := main[:at]
		if decoded, err := url.QueryUnescape(cred); err == nil {
			cred = decoded
		}
		user, pass, _ = strings.Cut(cred, ":")
		main = main[at+1:]
	}
	server, port, ok := hostPort(main)
	if !ok {
		return Node{}, false
	}
	b := &itemBuilder{name: firstNonEmpty(name, net.JoinHostPort(server, strconv.Itoa(port))), typ: typ, server: server, port: port}
	b.str("username", user)
	b.str("password", pass)
	if tls || strings.EqualFold(q.Get("tls"), "true") || q.Get("security") == "tls" {
		b.flag("tls", true)
	}
	if sni := firstNonEmpty(q.Get("sni"), q.Get("peer")); sni != "" {
		b.str("servername", sni)
	}
	if typ == "socks5" {
		b.flag("version", "5")
	}
	return b.node(), true
}

func splitFragment(s string) (body, name string) {
	if i := strings.IndexByte(s, '#'); i >= 0 {
		name, _ = url.QueryUnescape(s[i+1:])
		body = s[:i]
	} else {
		body = s
	}
	return body, strings.TrimSpace(name)
}

// hostPort splits the authority of a URI (no userinfo, no query).
func hostPort(authority string) (string, int, bool) {
	host, portStr, err := net.SplitHostPort(authority)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, false
	}
	return host, port, true
}

// queryOf parses the ?… part without requiring it to exist.
func queryOf(s string) url.Values {
	if i := strings.IndexByte(s, '?'); i >= 0 {
		if v, err := url.ParseQuery(s[i+1:]); err == nil {
			return v
		}
	}
	return url.Values{}
}

func stripQuery(s string) string {
	if i := strings.IndexByte(s, '?'); i >= 0 {
		return s[:i]
	}
	return s
}

func parseVmess(rest string) (Node, bool) {
	body, name := splitFragment(rest)
	raw, err := decodeAny(body)
	if err != nil {
		return Node{}, false
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return Node{}, false
	}
	str := func(k string) string {
		v, ok := m[k]
		if !ok || v == nil {
			return ""
		}
		switch t := v.(type) {
		case string:
			return t
		case float64:
			return strconv.Itoa(int(t))
		case int:
			return strconv.Itoa(t)
		}
		return fmt.Sprint(v)
	}
	port, _ := strconv.Atoi(str("port"))
	server := str("add")
	uuid := str("id")
	if server == "" || port == 0 || uuid == "" {
		return Node{}, false
	}
	if name == "" {
		name = str("ps")
	}
	network := str("net")
	tls := strings.EqualFold(str("tls"), "tls")
	b := &itemBuilder{name: name, typ: "vmess", server: server, port: port}
	b.str("uuid", uuid)
	b.str("alterId", firstNonEmpty(str("aid"), "0"))
	b.str("cipher", firstNonEmpty(str("scy"), "auto"))
	if tls {
		b.flag("tls", true)
		if sni := str("sni"); sni != "" {
			b.str("servername", sni)
		} else if host := str("host"); host != "" {
			b.str("servername", host)
		}
	}
	switch network {
	case "ws":
		b.flag("network", "ws")
		b.block("ws-opts", map[string]string{"path": firstNonEmpty(str("path"), "/"), "Host": str("host")})
	case "grpc":
		b.flag("network", "grpc")
		b.block("grpc-opts", map[string]string{"grpc-service-name": str("path")})
	}
	return b.node(), true
}

func parseVless(rest string) (Node, bool) {
	body, name := splitFragment(rest)
	q := queryOf(body)
	main := stripQuery(body)
	at := strings.LastIndexByte(main, '@')
	if at < 0 {
		return Node{}, false
	}
	uuid := main[:at]
	server, port, ok := hostPort(main[at+1:])
	if !ok || uuid == "" {
		return Node{}, false
	}
	b := &itemBuilder{name: firstNonEmpty(name, net.JoinHostPort(server, strconv.Itoa(port))), typ: "vless", server: server, port: port}
	b.str("uuid", uuid)
	if flow := q.Get("flow"); flow != "" {
		b.str("flow", flow)
	}
	security := q.Get("security")
	if security == "tls" || security == "reality" {
		b.flag("tls", true)
		if sni := firstNonEmpty(q.Get("sni"), q.Get("host")); sni != "" {
			b.str("servername", sni)
		}
		if fp := q.Get("fp"); fp != "" {
			b.str("client-fingerprint", fp)
		}
	}
	if security == "reality" {
		opts := map[string]string{"public-key": q.Get("pbk"), "short-id": q.Get("sid")}
		b.block("reality-opts", opts)
	}
	switch q.Get("type") {
	case "ws":
		b.flag("network", "ws")
		b.block("ws-opts", map[string]string{"path": firstNonEmpty(q.Get("path"), "/"), "Host": q.Get("host")})
	case "grpc":
		b.flag("network", "grpc")
		b.block("grpc-opts", map[string]string{"grpc-service-name": firstNonEmpty(q.Get("serviceName"), q.Get("path"))})
	case "http":
		b.flag("network", "http")
		b.block("http-opts", map[string]string{"path": []string{firstNonEmpty(q.Get("path"), "/")}[0], "Host": q.Get("host")})
	}
	return b.node(), true
}

func parseTrojan(rest string) (Node, bool) {
	body, name := splitFragment(rest)
	q := queryOf(body)
	main := stripQuery(body)
	at := strings.LastIndexByte(main, '@')
	if at < 0 {
		return Node{}, false
	}
	pass := main[:at]
	server, port, ok := hostPort(main[at+1:])
	if !ok || pass == "" {
		return Node{}, false
	}
	b := &itemBuilder{name: firstNonEmpty(name, net.JoinHostPort(server, strconv.Itoa(port))), typ: "trojan", server: server, port: port}
	b.str("password", pass)
	if sni := firstNonEmpty(q.Get("sni"), q.Get("peer"), q.Get("host")); sni != "" {
		b.str("sni", sni)
	}
	if v := q.Get("allowInsecure"); v == "1" || strings.EqualFold(v, "true") {
		b.flag("skip-cert-verify", true)
	}
	switch q.Get("type") {
	case "ws":
		b.flag("network", "ws")
		b.block("ws-opts", map[string]string{"path": firstNonEmpty(q.Get("path"), "/"), "Host": q.Get("host")})
	case "grpc":
		b.flag("network", "grpc")
		b.block("grpc-opts", map[string]string{"grpc-service-name": firstNonEmpty(q.Get("serviceName"), q.Get("path"))})
	}
	return b.node(), true
}

func parseShadowsocks(rest string) (Node, bool) {
	body, name := splitFragment(rest)
	body = stripQuery(body)
	var method, pass, host string
	var port int
	if at := strings.LastIndexByte(body, '@'); at >= 0 {
		cred, err := decodeAny(body[:at])
		if err != nil {
			return Node{}, false
		}
		m, p, ok := strings.Cut(string(cred), ":")
		if !ok {
			return Node{}, false
		}
		method, pass = m, p
		h, pt, ok := hostPort(body[at+1:])
		if !ok {
			return Node{}, false
		}
		host, port = h, pt
	} else {
		// Legacy form: base64(method:password@host:port).
		cred, err := decodeAny(body)
		if err != nil {
			return Node{}, false
		}
		m, p, ok := strings.Cut(string(cred), ":")
		if !ok {
			return Node{}, false
		}
		method, pass = m, p
		h, pt, ok := hostPort(pass[strings.LastIndexByte(pass, '@')+1:])
		if !ok {
			return Node{}, false
		}
		pass = pass[:strings.LastIndexByte(pass, '@')]
		host, port = h, pt
	}
	if method == "" || host == "" || port == 0 {
		return Node{}, false
	}
	b := &itemBuilder{name: firstNonEmpty(name, net.JoinHostPort(host, strconv.Itoa(port))), typ: "ss", server: host, port: port}
	b.str("cipher", method)
	b.str("password", pass)
	return b.node(), true
}

func parseHysteria2(rest string) (Node, bool) {
	body, name := splitFragment(rest)
	q := queryOf(body)
	main := stripQuery(body)
	at := strings.LastIndexByte(main, '@')
	if at < 0 {
		return Node{}, false
	}
	pass := main[:at]
	server, port, ok := hostPort(main[at+1:])
	if !ok || pass == "" {
		return Node{}, false
	}
	b := &itemBuilder{name: firstNonEmpty(name, net.JoinHostPort(server, strconv.Itoa(port))), typ: "hysteria2", server: server, port: port}
	b.str("password", pass)
	if sni := q.Get("sni"); sni != "" {
		b.str("sni", sni)
	}
	if v := q.Get("insecure"); v == "1" || strings.EqualFold(v, "true") {
		b.flag("skip-cert-verify", true)
	}
	return b.node(), true
}

func decodeAny(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("base64 解码失败")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// itemBuilder renders a proxy entry in the same shape our config generator
// writes, so a URI-derived node and a Clash-derived node splice in identically.
type itemBuilder struct {
	name, typ, server string
	port              int
	extra             [][2]string // ordered key/value, value already YAML-rendered
}

func (b *itemBuilder) str(k, v string) {
	if v == "" {
		return
	}
	b.extra = append(b.extra, [2]string{k, yamlQuote(v)})
}

func (b *itemBuilder) flag(k string, v any) {
	b.extra = append(b.extra, [2]string{k, fmt.Sprint(v)})
}

func (b *itemBuilder) block(k string, fields map[string]string) {
	var sb strings.Builder
	sb.WriteString("\n      ")
	first := true
	for key, val := range fields {
		if val == "" {
			continue
		}
		if !first {
			sb.WriteString("\n      ")
		}
		first = false
		fmt.Fprintf(&sb, "%s: %s", key, yamlQuote(val))
	}
	if first {
		return
	}
	b.extra = append(b.extra, [2]string{k, sb.String()})
}

func (b *itemBuilder) node() Node {
	var sb strings.Builder
	fmt.Fprintf(&sb, "  - name: %s\n", yamlQuote(b.name))
	fmt.Fprintf(&sb, "    type: %s\n", b.typ)
	fmt.Fprintf(&sb, "    server: %s\n", yamlQuote(b.server))
	fmt.Fprintf(&sb, "    port: %d", b.port)
	for _, kv := range b.extra {
		fmt.Fprintf(&sb, "\n    %s: %s", kv[0], kv[1])
	}
	return Node{Name: b.name, Type: b.typ, Server: b.server, Port: b.port, Raw: sb.String()}
}

// Latency measures a TCP handshake to the node: 0 when it does not answer in
// time. It is a reachability signal, not throughput — the same measure the
// endpoint list uses, and the one that predicts "will this hop even dial".
func Latency(n Node, timeout time.Duration) int64 {
	if n.Server == "" || n.Port == 0 {
		return 0
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(n.Server, strconv.Itoa(n.Port)), timeout)
	if err != nil {
		return 0
	}
	_ = conn.Close()
	ms := time.Since(start).Milliseconds()
	// 0 is the "unreachable" sentinel, so a handshake that finishes inside the
	// same millisecond (loopback, LAN, or a kernel that resolves it instantly)
	// must not be reported as dead.
	if ms < 1 {
		ms = 1
	}
	return ms
}

// Latencies probes every node with bounded concurrency and returns
// name → milliseconds (0 = unreachable).
func Latencies(nodes []Node, timeout time.Duration, workers int) map[string]int64 {
	if workers <= 0 {
		workers = 8
	}
	out := make(map[string]int64, len(nodes))
	var mu sync.Mutex
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			ms := Latency(n, timeout)
			mu.Lock()
			out[n.Name] = ms
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return out
}

// Pick returns the node with the given name, or the lowest-latency node when
// name is empty or gone from the list (subscriptions rotate).
func Pick(nodes []Node, name string, lat map[string]int64) (Node, bool) {
	if len(nodes) == 0 {
		return Node{}, false
	}
	if name != "" {
		for _, n := range nodes {
			if n.Name == name {
				return n, true
			}
		}
	}
	best := nodes[0]
	bestMS := int64(1<<62 - 1)
	for _, n := range nodes {
		ms := lat[n.Name]
		if ms > 0 && ms < bestMS {
			best, bestMS = n, ms
		}
	}
	return best, true
}
