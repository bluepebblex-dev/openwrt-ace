-- ACE 的 LuCI 入口。
--
-- 只做三件事：渲染页面、把 /etc/ace/state.json 变成 JSON、转发 start/stop。
-- 真正的连接逻辑在引擎里，这里不复制任何一份。
--
-- 安全模型：所有写接口（action/save/clearlog）只接受 POST，并校验 LuCI
-- 会话 token（context.authtoken）。没有这层，任何网页里一个 <img> 标签
-- 就能借已登录管理员的会话重启服务或改配置（CSRF）。读接口保持 GET。

module("luci.controller.ace", package.seeall)

local fs = require "nixio.fs"
local sys = require "luci.sys"
local http = require "luci.http"

-- 单份日志超过这个字节数就在被读取时截断（保 inode，见 api_action）。
-- run.sh 只在启动时截断一次，长跑期间引擎若循环报错会把 tmpfs 写满。
local LOG_MAX = 1024 * 1024

function index()
	if not fs.access("/etc/config/ace") then
		return
	end

	local page = entry({"admin", "services", "ace"}, template("ace/overview"), _("ACE"))
	page.order = 60
	page.icon = "luci-icon-luci-app-ace"

	entry({"admin", "services", "ace", "nodes"}, template("ace/nodes"), _("节点"), 5)
	entry({"admin", "services", "ace", "settings"}, template("ace/settings"), _("设置"), 10)
	entry({"admin", "services", "ace", "api", "status"}, call("api_status")).leaf = true
	entry({"admin", "services", "ace", "api", "action"}, call("api_action")).leaf = true
	entry({"admin", "services", "ace", "api", "log"}, call("api_log")).leaf = true
	entry({"admin", "services", "ace", "api", "settings"}, call("api_settings")).leaf = true
	entry({"admin", "services", "ace", "api", "save"}, call("api_save")).leaf = true
	entry({"admin", "services", "ace", "api", "nodes"}, call("api_nodes")).leaf = true
	entry({"admin", "services", "ace", "api", "scan"}, call("api_scan")).leaf = true
	entry({"admin", "services", "ace", "api", "pick"}, call("api_pick")).leaf = true
end

-- ---------------------------------------------------------------- CSRF
-- 写接口统一门槛：必须是 POST，且表单 token 与会话 token 一致。
-- 注意 LuCI 24.10 + luci-compat 下 cbi 的 authsession 桥是坏的，但 dispatcher
-- 的 context.authtoken（登录时写入 session 的 CSRF token）是独立机制，正常可用。
local function csrf_ok()
	if http.getenv("REQUEST_METHOD") ~= "POST" then
		return false
	end
	local ctx = require("luci.dispatcher").context
	local token = ctx and ctx.authtoken or nil
	if not token or token == "" then
		return false
	end
	return (http.formvalue("token") or "") == token
end

local function csrf_deny()
	http.status(403, "Forbidden")
	http.prepare_content("application/json")
	http.write_json({ ok = false, error = "csrf" })
end

local function cursor()
	return require("luci.model.uci").cursor()
end

-- 单引号 shell 转义：所有把 uci/缓存值拼进 sys.call 的地方都必须过这里。
local function shq(s)
	return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

-- 扫描缓存：引擎把每次端点扫描的结果写进 /etc/ace/cache.json
-- （键 scan-<proto>-v4/v6，payload 是 base64 的 JSON，TTL 6 小时）。
-- LuCI 直接读这份文件喂节点页，不经过引擎进程。
local SCAN_FLAG = "/var/run/ace-scanning"

local function read_cache_entries()
	local raw = fs.readfile("/etc/ace/cache.json")
	if not raw or raw == "" then
		return nil
	end
	local ok, tbl = pcall(function()
		return require("luci.jsonc").parse(raw)
	end)
	if ok and type(tbl) == "table" then
		return tbl
	end
	return nil
end

-- 纯 Lua base64 解码。ImmortalWrt 的 nixio.so 是精简编译，没有 nixio.bin
-- （b64decode 不存在，真机实测 require 直接报错）；不引第三方依赖。
local B64D = {}
for i, c in ipairs({ "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
	"N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
	"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
	"n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/" }) do
	B64D[c] = i - 1
end

local function b64decode(s)
	if not s then
		return nil
	end
	s = s:gsub("[^%w%+%/]", "")
	local out, buf, bits = {}, 0, 0
	for i = 1, #s do
		local v = B64D[s:sub(i, i)]
		if v then
			buf = buf * 64 + v
			bits = bits + 6
			if bits >= 8 then
				bits = bits - 8
				out[#out + 1] = string.char(math.floor(buf / 2 ^ bits) % 256)
				buf = buf % 2 ^ bits
			end
		end
	end
	return table.concat(out)
end

-- 取某一协议的扫描结果列表；过期（TTL 外）或损坏一律当没有。
local function scan_results_for(proto, fam)
	local entries = read_cache_entries()
	if not entries then
		return nil, nil
	end
	local e = entries["scan-" .. proto .. "-" .. fam]
	if type(e) ~= "table" or type(e.payload) ~= "string" then
		return nil, nil
	end
	if e.expires_at then
		-- Go time.Time 的 JSON 带小数秒，这里内联解析（parse_rfc3339 定义在后）
		local t = os.time()
		local y, mo, d, h, mi, sec, frac, tz =
			e.expires_at:match("^(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)(%.%d+)?([Z%+%-][%d:+]*)$")
		if y then
			local epoch = os.time({ year = tonumber(y), month = tonumber(mo), day = tonumber(d),
				hour = tonumber(h), min = tonumber(mi), sec = tonumber(sec), isdst = false })
			if tz and tz ~= "Z" then
				local sign, oh, om = tz:match("^([%+%-])(%d%d):(%d%d)$")
				if sign then
					local off = tonumber(oh) * 3600 + tonumber(om) * 60
					epoch = epoch - (sign == "+" and off or -off)
				end
			end
			if not epoch or epoch <= t then
				return nil, nil
			end
		end
	end
	local rawjson = b64decode(e.payload)
	if not rawjson then
		return nil, nil
	end
	local ok, cs = pcall(function()
		return require("luci.jsonc").parse(rawjson)
	end)
	if not ok or type(cs) ~= "table" or type(cs.results) ~= "table" then
		return nil, nil
	end
	return cs.results, cs.at
end

-- 端点白名单：只认缓存里出现过的 ip:port。pin/收藏都从这里过一遍，
-- 避免有人借 CSRF 写接口往 uci 里塞任意字符串（下游 run.sh 会拼命令行）。
local function cached_endpoints()
	local c = cursor()
	local proto = c:get("ace", "main", "proto") or "awg"
	local fam = (c:get("ace", "main", "ipv6") == "1") and "v6" or "v4"
	local results = scan_results_for(proto, fam) or {}
	-- masque 系协议没有端点缓存，回退看看 wg/awg 的（节点列表仍有用）
	if #results == 0 and proto:match("^masque") then
		results = scan_results_for("awg", fam) or scan_results_for("wg", fam) or {}
	end
	local set = {}
	for _, r in ipairs(results) do
		if type(r.endpoint) == "string" and r.endpoint:match("^[%w%.:%[%]%-]+$") then
			set[r.endpoint] = true
		end
	end
	return results, set, proto
end

-- state.json 是引擎唯一的对外状态；解析失败时退化成按行提取，
-- 保证界面上永远是"未知"而不是报错白屏。
local function read_state()
	local raw = fs.readfile("/etc/ace/state.json")
	if not raw or raw == "" then
		return nil
	end
	local ok, tbl = pcall(function()
		local jsonc = require "luci.jsonc"
		return jsonc.parse(raw)
	end)
	if ok and type(tbl) == "table" then
		return tbl
	end

	local st = {}
	local map = {
		connected = "connected", exit_ip = "exit_ip", country = "country",
		colo = "colo", node_city = "node_city", endpoint = "endpoint",
		proto = "proto", mixed_port = "mixed_port", core_pid = "core_pid",
		latency_ms = "latency_ms", started_at = "started_at", tun = "tun",
		family = "family", openvpn_mode = "openvpn_mode",
		openvpn_region = "openvpn_region",
	}
	for key in pairs(map) do
		local v = raw:match('"' .. key .. '"%s*:%s*"([^"]*)"')
			or raw:match('"' .. key .. '"%s*:%s*([%w%.%-]+)')
		if v ~= nil then
			if v == "true" then v = true
			elseif v == "false" then v = false
			elseif tonumber(v) then v = tonumber(v) end
			st[key] = v
		end
	end
	return st
end

local function pid_alive(pid)
	pid = tonumber(pid) or 0
	if pid <= 0 then
		return false
	end
	return fs.access("/proc/" .. pid) ~= nil
end

-- RFC3339 → epoch，纯 Lua 实现。之前用 `date -d` 拼 shell，状态文件一旦被
-- 污染就是 root 命令注入，且 busybox 的 -d 对带时区的 ISO 格式支持不齐。
-- 无时区后缀按路由器本地时区算；Z / ±HH:MM 都处理。Go 的 time.Time JSON
-- 序列化带小数秒（cache.json 的 expires_at），这里一并容忍。
local function parse_rfc3339(s)
	local y, mo, d, h, mi, sec, tz =
		s:match("^(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)(%.%d+)?([Z%+%-][%d:+]*)$")
	if not y then
		return nil
	end
	local t = os.time({ year = tonumber(y), month = tonumber(mo), day = tonumber(d),
		hour = tonumber(h), min = tonumber(mi), sec = tonumber(sec), isdst = false })
	if not t then
		return nil
	end
	if tz and tz ~= "Z" then
		local sign, oh, om = tz:match("^([%+%-])(%d%d):(%d%d)$")
		if sign then
			local off = tonumber(oh) * 3600 + tonumber(om) * 60
			t = t - (sign == "+" and off or -off)
		end
	end
	return t
end

function api_status()
	local st = read_state() or {}
	local running = st.connected and pid_alive(st.core_pid)
	local tun_up = fs.access("/sys/class/net/ace0") ~= nil
	-- ubus 调用本身永远成功，得看返回体里有没有这个服务才算数
	local svc = (sys.exec("ubus call service list 2>/dev/null") or ""):find('"ace"', 1, true) ~= nil

	-- start/stop 在 init.d 里同步跑(含 dnsmasq/防火墙),期间写 /var/run/ace.pending
	-- (内容 up 或 down)告诉界面「正在朝某方向走」。这里读它,并顺手清掉已经落到
	-- 目标态的过期标记(进程异常退出后标记不自己清,靠状态回落来兜底)。
	local pending = ""
	local pf = "/var/run/ace.pending"
	local praw = fs.readfile(pf)
	if praw then
		pending = (praw:match("^(%a+)%s*$") or ""):lower()
		if pending ~= "up" and pending ~= "down" then
			pending = ""
		end
	end
	if pending == "down" and (not running and not tun_up) then
		fs.remove(pf)
		pending = ""
	elseif pending == "up" and running then
		fs.remove(pf)
		pending = ""
	end

	local out = {
		connected = running and true or false,
		pending = pending ~= "" and pending or nil,
		service = svc,
		tun_up = tun_up,
		exit_ip = st.exit_ip or "",
		country = st.country or "",
		city = st.node_city or "",
		colo = st.colo or "",
		endpoint = st.endpoint or "",
		proto = st.proto or "",
		latency = st.latency_ms or 0,
		started_at = st.started_at or "",
		openvpn = st.openvpn_mode and true or false,
		openvpn_region = st.openvpn_region or "",
		core_pid = st.core_pid or 0,
	}

	-- 「本机 IP」卡片：桌面端显示的是本机局域网地址，路由器上对应 br-lan
	local lan = sys.exec("ip -4 addr show br-lan 2>/dev/null")
	out.lan_ip = (lan or ""):match("inet%s+([%d%.]+)") or ""

	-- 流量速率/累计：mihomo 控制接口只听 127.0.0.1 且无 secret，由本进程
	-- （root）代查。速率由前端用两次轮询的总量差算，后端不做有状态缓存。
	local aport = cursor():get("ace", "main", "api_port") or "9090"
	local conn = sys.exec("wget -q -T 2 -O- http://127.0.0.1:" .. aport .. "/connections 2>/dev/null")
	if conn and conn ~= "" then
		local ok, cj = pcall(function()
			return require("luci.jsonc").parse(conn)
		end)
		if ok and type(cj) == "table" then
			out.up_total = tonumber(cj.uploadTotal) or 0
			out.down_total = tonumber(cj.downloadTotal) or 0
		end
	end

	-- 出口选择（节点页「设为默认」写入）与后台扫描标记
	out.pick = cursor():get("ace", "main", "pick") or ""
	out.scanning = fs.access(SCAN_FLAG) and true or false
	if out.scanning then
		out.scan_proto = (fs.readfile(SCAN_FLAG) or ""):match("^([%w%-]+)") or ""
	end

	-- 会话时长由前端算不划算：这里直接给秒数
	if out.started_at ~= "" then
		local then_ = parse_rfc3339(out.started_at)
		if then_ then
			out.uptime = os.time() - then_
			if out.uptime < 0 then
				out.uptime = nil
			end
		end
	end

	http.prepare_content("application/json")
	http.write_json(out)
end

function api_action()
	if not csrf_ok() then
		return csrf_deny()
	end

	local action = http.formvalue("action") or ""

	-- 清日志单独处理：run.sh 用 >> 打开日志文件，截断而不删除才能保住
	-- 同一个 inode，正在写日志的内核/看门狗不会因为文件消失而丢日志。
	if action == "clearlog" then
		sys.call(": > /var/log/ace.log; : > /var/log/ace-watchdog.log")
		http.prepare_content("application/json")
		http.write_json({ ok = true, action = action })
		return
	end

	local allowed = { start = true, stop = true, restart = true }
	if not allowed[action] then
		http.status(400, "Bad Request")
		http.prepare_content("application/json")
		http.write_json({ ok = false, error = "unknown action" })
		return
	end

	-- 连接/断开都是秒级动作，同步跑完再回话，前端不用猜
	sys.call("/etc/init.d/ace " .. action .. " >/dev/null 2>&1")
	http.prepare_content("application/json")
	http.write_json({ ok = true, action = action })
end

function api_log()
	-- 读接口顺手做日志限额：超限就保留尾部并截断，防止 tmpfs 被写满
	for _, f in ipairs({ "/var/log/ace.log", "/var/log/ace-watchdog.log", "/etc/ace/ace.log" }) do
		local st = fs.stat(f)
		if st and (st.size or 0) > LOG_MAX then
			sys.call("{ tail -c 262144 '" .. f .. "' > '" .. f .. ".t' && mv '" .. f .. ".t' '" .. f .. "'; } 2>/dev/null")
		end
	end

	-- 日志分两个来源，都要给；顺序上引擎在前、服务事件在后 —— 面板会自动滚到底部，
	-- 带日期的服务事件（隧道就绪 / 加 zone / 看门狗）落在可视区里更有用。
	--   服务事件：init.d 里 logger -t ace 写的，只在 logread
	--   引擎输出：run.sh 把引擎 stdout 重定向到 /var/log/ace.log；引擎自身另有 /etc/ace/ace.log
	-- 之前只读 /var/log/ace.log —— 引擎在守护模式下几乎不写 stdout，面板长期显示「暂无日志」。
	local parts = {}
	local eng = sys.exec("tail -n 200 /var/log/ace.log 2>/dev/null")
	if not eng or eng:gsub("%s", "") == "" then
		eng = sys.exec("tail -n 200 /etc/ace/ace.log 2>/dev/null")
	end
	if eng and eng:gsub("%s", "") ~= "" then
		parts[#parts + 1] = "── 引擎 ──\n" .. eng
	end
	local svc = sys.exec("logread -e 'ace:' 2>/dev/null | tail -n 60 | sed 's/^\\(.*\\) user\\.[a-z]* ace: /\\1 /'")
	if svc and svc:gsub("%s", "") ~= "" then
		parts[#parts + 1] = "── 服务事件 ──\n" .. svc
	end

	local body = table.concat(parts, "\n")
	http.prepare_content("text/plain; charset=utf-8")
	http.write(body ~= "" and body or "（暂无日志）\n")
end

-- ---------------------------------------------------------------- 设置读写
-- 不走 luci.cbi：ImmortalWrt 24.10 的 luci-compat CBI 桥在渲染时拿不到
-- L.ctx.authsession，has_uci_access 恒为 false，整页只剩「权限不足，无法读取
-- UCI 配置。」。这里由服务端（uhttpd 以 root 运行）直接读写 uci，绕开这层。
local SETTING_KEYS = {
	tun = "flag", proto = "proto", openvpn = "flag", openvpn_region = "region",
	ipv6 = "flag", dns_takeover = "flag", dns_leak = "flag",
	lan_watchdog = "flag", watchdog_action = "waction", mixed_port = "port",
	api_port = "port", core = "core", enabled = "flag",
}

-- core 必须是白名单目录下、真实存在且有可执行位的文件。仅校验「以 / 开头」
-- 的话，叠加 CSRF 就能以 root 执行任意二进制。
local function core_ok(path)
	if not path or path == "" or path:sub(1, 1) ~= "/" then
		return false
	end
	for _, p in ipairs({ "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/etc/ace/core/" }) do
		if path:sub(1, #p) == p then
			local st = fs.stat(path)
			-- mode 形如 "rwxr-xr-x"，任意执行位为真即可
			return st ~= nil and (st.type == "reg") and (st.mode or ""):find("x", 1, true) ~= nil
		end
	end
	return false
end

function api_settings()
	local c = cursor()
	local out = {}
	for k in pairs(SETTING_KEYS) do
		out[k] = c:get("ace", "main", k) or ""
	end
	out.enabled = fs.access("/etc/rc.d/S99ace") and "1" or "0"
	http.prepare_content("application/json")
	http.write_json(out)
end

function api_save()
	if not csrf_ok() then
		return csrf_deny()
	end

	local c = cursor()

	-- 先全量校验、再落盘：部分提交后返回 400 会让 uci 与运行状态不一致
	local pending_vals, errs = {}, {}
	for k, kind in pairs(SETTING_KEYS) do
		local v = http.formvalue(k)
		if v ~= nil then
			v = v:gsub("^%s+", ""):gsub("%s+$", "")
			local ok = true
			if kind == "flag" then
				v = (v == "1" or v == "true" or v == "on") and "1" or "0"
			elseif kind == "proto" then
				ok = ({ awg = true, wg = true, wwarp = true, masque = true, ["masque-h2"] = true, ["masque-mm"] = true })[v] == true
			elseif kind == "port" then
				local n = tonumber(v)
				ok = n ~= nil and n >= 1 and n <= 65535
			elseif kind == "region" then
				v = v:upper()
				ok = (v == "") or (v:match("^[A-Z][A-Z]$") ~= nil)
			elseif kind == "waction" then
				ok = (v == "reboot" or v == "none")
			elseif kind == "core" then
				ok = core_ok(v)
			end
			if not ok then
				errs[#errs + 1] = k
			elseif k ~= "enabled" then
				pending_vals[k] = v
			end
		end
	end

	if #errs > 0 then
		http.status(400, "Bad Request")
		http.prepare_content("application/json")
		http.write_json({ ok = false, invalid = errs })
		return
	end

	for k, v in pairs(pending_vals) do
		c:set("ace", "main", k, v)
	end
	c:commit("ace")

	-- 开机自启是 rc.d 里的符号链接，不归 uci 管
	local want = http.formvalue("enabled")
	if want ~= nil then
		local on = (want == "1" or want == "true" or want == "on")
		local is_on = fs.access("/etc/rc.d/S99ace") ~= nil
		if on ~= is_on then
			sys.call("/etc/init.d/ace " .. (on and "enable" or "disable") .. " >/dev/null 2>&1")
		end
	end

	-- 重启放后台：隧道重建要十几秒，同步等会把 HTTP 请求挂住。
	-- restart=0 时只落盘不重启（首页协议快切在服务未运行时用：引擎没在跑，
	-- restart 会把一个故意停掉的服务拉起来）。
	if http.formvalue("restart") ~= "0" then
		sys.call("(sleep 1; /etc/init.d/ace restart) >/dev/null 2>&1 &")
	end
	http.prepare_content("application/json")
	http.write_json({ ok = true, saved = pending_vals })
end

-- ---------------------------------------------------------------- 节点页
-- 节点列表 = 引擎扫描缓存（/etc/ace/cache.json）+ uci 里的收藏/出口选择。
function api_nodes()
	local c = cursor()
	local results, at, proto = cached_endpoints()
	local starred = {}
	local raw_starred = c:get("ace", "main", "starred")
	if type(raw_starred) == "table" then
		for _, s in ipairs(raw_starred) do
			starred[s] = true
		end
	end
	local out = {
		proto = proto,
		at = type(at) == "string" and at or "",
		results = results,
		starred = starred,
		pick = c:get("ace", "main", "pick") or "",
		scanning = fs.access(SCAN_FLAG) and true or false,
		scan_proto = "",
	}
	if out.scanning then
		out.scan_proto = (fs.readfile(SCAN_FLAG) or ""):match("^([%w%-]+)") or ""
	end
	http.prepare_content("application/json")
	http.write_json(out)
end

-- 后台触发一次端点扫描。扫描要几分钟，放后台跑，完成与否靠轮询
-- api_nodes.scanning（标记文件由后台 shell 收尾时删除）。
function api_scan()
	if not csrf_ok() then
		return csrf_deny()
	end
	if fs.access(SCAN_FLAG) then
		http.status(409, "Busy")
		http.prepare_content("application/json")
		http.write_json({ ok = false, error = "busy" })
		return
	end

	local proto = http.formvalue("proto") or ""
	if proto == "" then
		proto = cursor():get("ace", "main", "proto") or "awg"
	end
	-- 只有 wg/awg/wwarp 有端点可扫；masque 没有端点缓存，扫了也白扫
	if not ({ wg = true, awg = true, wwarp = true })[proto] then
		http.status(400, "Bad Request")
		http.prepare_content("application/json")
		http.write_json({ ok = false, error = "proto " .. proto .. " has no endpoint cache" })
		return
	end
	local fam = (cursor():get("ace", "main", "ipv6") == "1") and " -6" or ""

	-- 标记文件内容写协议名，界面能显示「正在扫描 awg…」；后台 shell 收尾删标记。
	-- -account 必须给绝对路径：scan 子命令的账号文件默认是相对当前目录的
	-- ace-account.json（真机实测从 LuCI 触发时工作目录不对，报 no WARP account）。
	fs.writefile(SCAN_FLAG, proto .. "\n")
	sys.call("( WARP_CLIENT_HOME=/etc/ace /usr/bin/ace-engine scan -proto " .. shq(proto) ..
		fam .. " -account /etc/ace/ace-account.json -plain -no-report >>/var/log/ace-scan.log 2>&1; " ..
		"rm -f " .. shq(SCAN_FLAG) .. " ) >/dev/null 2>&1 &")
	http.prepare_content("application/json")
	http.write_json({ ok = true, proto = proto })
end

-- 设为默认出口（pick）/收藏（star）/取消收藏（unstar）。只落盘不重启：
-- pick 影响下一次连接；apply=1 表示顺带重建隧道（前端在已连接时才发）。
function api_pick()
	if not csrf_ok() then
		return csrf_deny()
	end
	local pick = http.formvalue("pick")
	local star = http.formvalue("star")
	local unstar = http.formvalue("unstar")
	if pick == nil and star == nil and unstar == nil then
		http.status(400, "Bad Request")
		http.prepare_content("application/json")
		http.write_json({ ok = false, error = "nothing to do" })
		return
	end

	local _, valid = cached_endpoints()
	local function known(v)
		return v == "" or (valid and valid[v] == true)
	end

	local c = cursor()
	if pick ~= nil then
		pick = pick:match("^%s*(.-)%s*$")
		if not known(pick) then
			http.status(400, "Bad Request")
			http.prepare_content("application/json")
			http.write_json({ ok = false, error = "unknown endpoint" })
			return
		end
		-- set 只改内存，必须 commit 才落盘（真机实测：不 commit 的话 init.d
		-- 下次读到的还是旧 pick，节点页显示已选、连接却走老端点）
		sys.call("uci -q set ace.main.pick=" .. shq(pick) .. "; uci -q commit ace")
	end

	if star ~= nil or unstar ~= nil then
		local raw = c:get("ace", "main", "starred")
		local list = {}
		if type(raw) == "table" then
			for _, s in ipairs(raw) do
				list[s] = true
			end
		end
		local target, want = (star ~= nil) and star or unstar, (star ~= nil)
		if not known(target) then
			http.status(400, "Bad Request")
			http.prepare_content("application/json")
			http.write_json({ ok = false, error = "unknown endpoint" })
			return
		end
		list[target] = want or nil
		-- 列表值用 shell 逐条 add_list 写（luci.model.uci 的列表 set 在
		-- 24.10 上行为不稳，shell 的 uci add_list/delete 是确定性的）
		local cmds = { "uci -q delete ace.main.starred" }
		for s in pairs(list) do
			cmds[#cmds + 1] = "uci add_list ace.main.starred=" .. shq(s)
		end
		cmds[#cmds + 1] = "uci -q commit ace"
		sys.call(table.concat(cmds, "; "))
	end

	if http.formvalue("apply") == "1" then
		-- 已连接时换出口：同步重建（与 api_action 的 start/stop 同级耗时）
		sys.call("/etc/init.d/ace restart >/dev/null 2>&1")
	end
	http.prepare_content("application/json")
	http.write_json({ ok = true })
end
