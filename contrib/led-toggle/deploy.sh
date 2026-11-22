#!/bin/sh
# LED 氛围灯开关 — 一键部署（在路由器上执行）
# 幂等：重复运行不会重复注入。备份原文件到 *.led-bak-*。
set -e

DIR=$(cd "$(dirname "$0")" && pwd)
CTRL=/usr/lib/lua/luci/controller/ace.lua
MAIN=/usr/lib/lua/luci/view/quickstart/main.htm
TS=$(date +%Y%m%d%H%M%S)

echo "== 1/4 部署呼吸灯服务 =="
cp "$DIR/ace-led-breathd" /usr/bin/ace-led-breathd
cp "$DIR/ace-led-breath"  /etc/init.d/ace-led-breath
chmod +x /usr/bin/ace-led-breathd /etc/init.d/ace-led-breath

echo "== 2/4 给 controller 注入 api_led（幂等）=="
if ! grep -q 'function api_led' "$CTRL"; then
    cp "$CTRL" "$CTRL.led-bak-$TS"
    # 路由：在 index() 的 geo 行后追加 led 行
    sed -i '/api.*geo.*call("api_geo")/a\	entry({"admin", "services", "ace", "api", "led"}, call("api_led")).leaf = true' "$CTRL"
    # 函数：去掉片段开头的注释行后追加到文件末尾
    tail -n +4 "$DIR/controller-api-led.fragment" >> "$CTRL"
    echo "  controller 已打补丁"
else
    echo "  controller 已有 api_led，跳过"
fi
lua -e "assert(loadfile('$CTRL'))" && echo "  Lua 语法 OK"

echo "== 3/4 注入首页开关浮层（幂等）=="
if ! grep -q 'ace-led-toggle' "$MAIN"; then
    cp "$MAIN" "$MAIN.led-bak-$TS"
    cp "$DIR/main.htm.fragment" "$MAIN"
    echo "  main.htm 已替换"
else
    echo "  main.htm 已有开关，跳过"
fi

echo "== 4/4 启用服务、清缓存 =="
/etc/init.d/ace-led-breath enable >/dev/null 2>&1 || true
/etc/init.d/ace-led-breath start  >/dev/null 2>&1 || true
rm -rf /tmp/luci-indexcache* /tmp/luci-modulecache*

echo "完成。硬刷浏览器首页即可看到「氛围灯」开关。"
echo "验证: curl -s 'http://192.168.50.1/cgi-bin/luci/admin/services/ace/api/led?action=status'（需登录态）"
