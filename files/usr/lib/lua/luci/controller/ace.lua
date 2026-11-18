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
-- 无时区后缀按路由器本地时区算；Z / ±HH:MM 都处理。
local function parse_rfc3339(s)
	local y, mo, d, h, mi, sec, tz =
		s:match("^(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)([Z%+%-][%d:+]*)$")
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
	for _, f in ipairs({ "/var/log/ace.log", "/var/log/ace-watchdog.log" }) do
		local st = fs.stat(f)
		if st and (st.size or 0) > LOG_MAX then
			sys.call("{ tail -c 262144 '" .. f .. "' > '" .. f .. ".t' && mv '" .. f .. ".t' '" .. f .. "'; } 2>/dev/null")
		end
	end
	local body = sys.exec("tail -n 300 /var/log/ace.log 2>/dev/null")
	http.prepare_content("text/plain; charset=utf-8")
	http.write(body or "")
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

local function cursor()
	return require("luci.model.uci").cursor()
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

	-- 重启放后台：隧道重建要十几秒，同步等会把 HTTP 请求挂住
	sys.call("(sleep 1; /etc/init.d/ace restart) >/dev/null 2>&1 &")
	http.prepare_content("application/json")
	http.write_json({ ok = true, saved = pending_vals })
end
