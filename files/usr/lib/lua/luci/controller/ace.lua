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

	entry({"admin", "services", "ace", "settings"}, template("ace/settings"), _("设置"), 10)
	entry({"admin", "services", "ace", "api", "status"}, call("api_status")).leaf = true
	entry({"admin", "services", "ace", "api", "action"}, call("api_action")).leaf = true
	entry({"admin", "services", "ace", "api", "log"}, call("api_log")).leaf = true
	entry({"admin", "services", "ace", "api", "settings"}, call("api_settings")).leaf = true
	entry({"admin", "services", "ace", "api", "save"}, call("api_save")).leaf = true
	entry({"admin", "services", "ace", "api", "core"}, call("api_core")).leaf = true
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

-- ---------------------------------------------------------------- 内核
-- 引擎的查找顺序：uci 指定路径 → /etc/ace/core/mihomo → 下载（内嵌 SHA256 校验）。
-- 界面照这个顺序判断，避免「界面说就绪、引擎却找不到」。
local CORE_DIR = "/etc/ace/core"
local CORE_FLAG = "/var/run/ace-core-installing"
local CORE_LOG = "/var/log/ace-core.log"
-- probe 结果按 (path, size, mtime) 缓存：一次 probe 要跑八次 mihomo -t（约 3 秒），
-- 而 api_status 每 2.5 秒被轮询一次，不缓存等于把 CPU 钉在配置解析上。
local PROBE_CACHE = "/var/run/ace-probe.json"
-- 缓存有效期。内核能力本身不会变，但 probe 顺带查的「官方最新版」会变，
-- 6 小时重探一次足够，也不会让设置页每分钟跑一遍配置测试。
local PROBE_TTL = 6 * 3600

-- 是否是一个可执行文件：返回字节数，不是就返回 nil。
-- 不能用 st.mode 判断——这台 ImmortalWrt 的 nixio 精简编译里 stat().mode 是 nil
-- （真机实测），只能靠 fs.access(p, "x") 问系统。
local function is_exe(p)
	if not p or p == "" then
		return nil
	end
	local st = fs.stat(p)
	if not st or st.type ~= "reg" then
		return nil
	end
	if not fs.access(p, "x") then
		return nil
	end
	return st.size or 0
end

-- 内核能力：这个二进制能不能跑 OpenVPN 出站。
-- 「内核存在」和「内核支持 OpenVPN 出站」是两件事：ImmortalWrt 24.10 自带的
-- mihomo v1.19.12 接受全部 WARP 协议，但拒绝 type: openvpn，连接时看起来像
-- 节点问题（握手失败/速度为零），实际上是内核太旧。用引擎自己的 probe 问一次。
local function core_probe(path, size)
	local st = fs.stat(path)
	local mtime = st and (st.mtime or 0) or 0
	local cached = nil
	local raw = fs.readfile(PROBE_CACHE)
	if raw and raw ~= "" then
		local ok, t = pcall(function() return require("luci.jsonc").parse(raw) end)
		-- TTL 只用来让 latest 跟上新发布：命中条件里除了内核文件指纹，还要
		-- 看这份缓存有多旧。没有 TTL 的话，第一次探测把 latest 定死，
		-- 上游发了新版本界面也永远说「已是最新」。
		if ok and type(t) == "table" and t.path == path and t.size == size
			and t.mtime == mtime and (os.time() - (t.at or 0)) < PROBE_TTL then
			cached = t
		end
	end
	if cached then
		return cached
	end

	local out = sys.exec("/usr/bin/ace-engine probe -core " .. shq(path) .. " 2>/dev/null")
	local res = { path = path, size = size, mtime = mtime, at = os.time(),
		openvpn = false, version = "", latest = "" }
	if out and out ~= "" then
		local ok, t = pcall(function() return require("luci.jsonc").parse(out) end)
		if ok and type(t) == "table" then
			res.openvpn = t.openvpn == true
			res.version = t.version or ""
			res.proto = t.proto
			res.latest = t.latest or ""
		end
	end
	fs.writefile(PROBE_CACHE, require("luci.jsonc").stringify(res) .. "\n")
	return res
end

-- "1.19.9" < "1.19.32"：按段比数字，不能按字符串比（否则 9 > 32）。
local function ver_lt(a, b)
	local function parts(v)
		local t = {}
		for n in tostring(v):gmatch("%d+") do t[#t + 1] = tonumber(n) end
		return t
	end
	local x, y = parts(a), parts(b)
	for i = 1, math.max(#x, #y) do
		local l, r = x[i] or 0, y[i] or 0
		if l ~= r then
			return l < r
		end
	end
	return false
end

local function core_state()
	local c = cursor()
	local want = c:get("ace", "main", "core") or ""
	-- run.sh 在 core 为空时用 /usr/bin/mihomo，这里保持同一套默认
	if want == "" then
		want = "/usr/bin/mihomo"
	end
	-- 顺序必须和引擎一致：EnsureBinary 先看 <home>/core/mihomo（下载版），
	-- 再回落到 -core 指定的路径。反过来的话界面会说「用着系统版」，
	-- 实际跑的是下载版，版本能力对不上。
	local dl = CORE_DIR .. "/mihomo"
	local sz = is_exe(dl)
	local st
	if sz then
		st = { ok = true, path = dl, src = "downloaded", size = sz, want = want }
	else
		sz = is_exe(want)
		if sz then
			st = { ok = true, path = want, src = "system", size = sz }
		else
			return { ok = false, path = dl, src = "none", size = 0, want = want }
		end
	end
	local p = core_probe(st.path, st.size)
	st.version = p.version
	st.openvpn = p.openvpn
	st.latest = p.latest or ""
	-- 「有更新」只按引擎查到的官方最新版判断：装上的是系统版 1.19.12 就是有，
	-- 已经是 1.19.32 就没有。两个都空（网络不通、API 取不到）时不提示，
	-- 绝不因为查不到就说「有新版本」。
	st.update = (st.version ~= "" and st.latest ~= "" and ver_lt(st.version, st.latest)) and true or false
	-- 旧内核缺的不止 OpenVPN：MASQUE 出站也是 v1.19.2x 之后才有。界面据此
	-- 提前说清「这个协议在现内核上跑不起来」，而不是让人对着握手失败猜。
	st.proto = p.proto
	return st
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

	-- 内核状态：引擎的查找顺序是「uci 里指定的路径 → /etc/ace/core/mihomo → 下载」，
	-- 界面按同样顺序判断，才不会出现「界面说就绪、引擎却找不到」。
	out.core = core_state()
	out.core_installing = fs.access(CORE_FLAG) and true or false
	-- 失败原因（下载不通、校验不过）直接给一行，别让人对着转圈猜
	if out.core_installing or not out.core.ok then
		out.core_log = (sys.exec("tail -n 1 " .. CORE_LOG .. " 2>/dev/null") or ""):gsub("%s+$", "")
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
			return is_exe(path) ~= nil
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
				-- 空 = 用 run.sh 的默认 /usr/bin/mihomo（界面上写的就是「留空则用」）
				ok = (v == "") or core_ok(v)
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

	-- OpenVPN 出口是「基础协议之上再挂一层 mihomo openvpn 出站」，链式协议
	-- （wwarp / masque-mm）本身已经是两层，再叠一层引擎会直接拒绝。这里提前
	-- 拦下并说清原因，比「保存成功、连接时失败」好。
	local ovpn = pending_vals.openvpn or c:get("ace", "main", "openvpn")
	local proto = pending_vals.proto or c:get("ace", "main", "proto")
	if ovpn == "1" and (proto == "wwarp" or proto == "masque-mm") then
		http.status(400, "Bad Request")
		http.prepare_content("application/json")
		http.write_json({ ok = false, error = "openvpn_chain", invalid = { "openvpn" } })
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

-- ---------------------------------------------------------------- 内核下载
-- 引擎自带 mihomo 下载：官方源 + 镜像，每个候选都过内嵌 SHA256（v1.19.32），
-- 校验不过直接拒绝，所以这里不需要再拼一套下载脚本。
-- 下载约 15 MB，放后台跑，界面轮询 api_status 的 core_installing。
function api_core()
	if not csrf_ok() then
		return csrf_deny()
	end

	if (http.formvalue("action") or "") ~= "install" then
		http.status(400, "Bad Request")
		http.prepare_content("application/json")
		http.write_json({ ok = false, error = "unknown action" })
		return
	end

	if fs.access(CORE_FLAG) then
		http.prepare_content("application/json")
		http.write_json({ ok = true, installing = true })
		return
	end

	-- 下载成功后让新内核真正生效：Linux 下替换正在执行的二进制，旧进程仍
	-- 持有旧 inode。只换文件不重启的话，界面读磁盘显示新版本，流量却还走旧内核，
	-- 看起来就是「下载了没更新」。所以下载命令返回 0 时接着重启服务（同一条
	-- 链路：stop 幂等清理 → 两阶段接管重建隧道）。
	-- 只在服务本就在跑时重启：用户故意停着服务时下载内核，不该把服务拉起来。
	local st = read_state() or {}
	local was_running = st.connected and pid_alive(st.core_pid)
	local restart = was_running
		and (" && /etc/init.d/ace restart >>" .. CORE_LOG .. " 2>&1")
		or ""

	-- 标记先落盘再起进程，否则界面第一次轮询会看不到进度
	fs.writefile(CORE_FLAG, "1\n")
	sys.call(": > " .. CORE_LOG .. "; ( WARP_CLIENT_HOME=/etc/ace /usr/bin/ace-engine core -dir " ..
		CORE_DIR .. " -force >>" .. CORE_LOG .. " 2>&1" .. restart ..
		"; rm -f " .. CORE_FLAG .. " ) >/dev/null 2>&1 &")

	http.prepare_content("application/json")
	http.write_json({ ok = true, installing = true })
end
