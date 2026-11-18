#!/bin/sh
# 把 dist/ 下的两个 ipk 传到路由器并安装。
# 用法：ACE_SSH_PASS=路由器密码 ./install.sh [路由器IP]
set -e
cd "$(dirname "$0")"
HOST=${1:-192.168.1.1}
export ACE_HOST="$HOST"
[ -n "${ACE_SSH_PASS:-}" ] || { echo "请先 export ACE_SSH_PASS=你的路由器密码"; exit 1; }
S=$(ls -t dist/ace_*.ipk 2>/dev/null | head -1)
L=$(ls -t dist/luci-app-ace_*.ipk 2>/dev/null | head -1)
[ -n "$S" ] && [ -n "$L" ] || { echo "dist/ 里没有 ipk，先跑 ./build-ipk.sh"; exit 1; }

echo "==> 上传"
./tools/oscp.exp "$S" /tmp/ace.ipk
./tools/oscp.exp "$L" /tmp/luci-app-ace.ipk

echo "==> 安装"
./tools/osh.exp "opkg install /tmp/ace.ipk /tmp/luci-app-ace.ipk 2>&1 | tail -20; echo '--- 校验 ---'; opkg list-installed | grep -E '^(ace|luci-app-ace)'; ls -la /usr/bin/ace-engine /etc/init.d/ace /usr/lib/lua/luci/controller/ace.lua"

echo "==> 完成。打开 http://$HOST/cgi-bin/luci/admin/services/ace"
