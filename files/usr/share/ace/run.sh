#!/bin/sh
# 由 procd 拉起：把 uci 配置翻译成引擎的命令行。
#
# exec 是关键——procd 拿到的 PID 必须就是引擎本身，否则 stop 时杀掉的只是
# 一层 shell，内核和 TUN 会留下来。

. /lib/functions.sh
config_load ace

proto=$(uci -q get ace.main.proto); proto=${proto:-awg}
mport=$(uci -q get ace.main.mixed_port); mport=${mport:-7890}
aport=$(uci -q get ace.main.api_port); aport=${aport:-9090}
core=$(uci -q get ace.main.core); core=${core:-/usr/bin/mihomo}
ovpn=$(uci -q get ace.main.openvpn)
region=$(uci -q get ace.main.openvpn_region)
ipv6=$(uci -q get ace.main.ipv6)
# TUN 是显式开关：dns_takeover 只在 tun=1 时才有意义（没 TUN 就没有内核
# 解析器可指），所以这里不反向推断，避免「打开 DNS 接管」顺手把 TUN 也带上。
tun=$(uci -q get ace.main.tun)
# 解析器查询跟随规则走隧道：不开的话内核从 WAN 直查明文上游，被墙域名
# 一律拿到污染结果（youtube/google → Facebook IP），流量走隧道也白搭。
dns_leak=$(uci -q get ace.main.dns_leak)

LOG=/var/log/ace.log
# 日志在 tmpfs 上，但长跑几天也会撑大；超过 1MB 就重开
[ -f "$LOG" ] && [ "$(wc -c < "$LOG")" -gt 1048576 ] && : > "$LOG"

# -hold 让 connect 连上之后不返回，procd 才有「一个活着的 PID」可看护。
# 不带它的话 connect 打完状态行就退出，procd 每隔几秒重生一次，每次都把
# 上一个内核杀掉重建隧道（日志里会看到一串 killed stale core + connected）。
set -- connect -hold -proto "$proto" -core "$core" \
	-mixed-port "$mport" -api-port "$aport" -no-proxy

# tun=1 才接管整屋流量；不带 TUN 时仍会起本地混合端口，可以先用
# curl -x http://127.0.0.1:7890 验通路，确认引擎正常再开 TUN
[ "$tun" = "1" ] && set -- "$@" -tun
[ "$dns_leak" != "0" ] && set -- "$@" -dns-leak

[ "$ovpn" = "1" ] && set -- "$@" -openvpn
[ -n "$region" ] && [ "$ovpn" = "1" ] && set -- "$@" -openvpn-region "$region"
[ "$ipv6" = "1" ] && set -- "$@" -6

{
	echo "=== $(date '+%F %T') ace $* ==="
	exec /usr/bin/ace-engine "$@" 2>&1
} >>"$LOG"
