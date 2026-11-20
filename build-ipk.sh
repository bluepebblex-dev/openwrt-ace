#!/bin/sh
# 生成两个 ipk：ace（引擎 + 服务）和 luci-app-ace（界面）。
# 不依赖 OpenWrt SDK：ipk 就是 ar 包着 control.tar.gz + data.tar.gz，
# 用 python 的 tarfile 打包能保证 uid/gid/权限干净。
set -e

cd "$(dirname "$0")"
ROOT=$(pwd)
SRC=${ACE_SRC:-$ROOT/engine}
ARCH=${ARCH:-aarch64_cortex-a53}
VER=${VER:-1.0.0}
DIST=$ROOT/dist
STAGE=$ROOT/build

# 交叉编译需要 go 工具链；默认取 PATH 里的 go，可用 GO= 覆盖。
GO=${GO:-$(command -v go 2>/dev/null || echo go)}

echo "==> 编译引擎 (linux/arm64)"
mkdir -p "$STAGE/bin"
(cd "$SRC" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 "$GO" build \
	-ldflags "-s -w -X main.version=$VER" -o "$STAGE/bin/ace-engine" .)

echo "==> 打包"
rm -rf "$DIST" "$STAGE/ace" "$STAGE/luci"
mkdir -p "$DIST" "$STAGE/ace" "$STAGE/luci"

# --- ace ---
mkdir -p "$STAGE/ace/usr/bin" "$STAGE/ace/etc/init.d" "$STAGE/ace/etc/config" \
	"$STAGE/ace/usr/share/ace"
cp "$STAGE/bin/ace-engine" "$STAGE/ace/usr/bin/ace-engine"
cp files/etc/init.d/ace "$STAGE/ace/etc/init.d/ace"
cp files/etc/config/ace "$STAGE/ace/etc/config/ace"
cp files/usr/share/ace/run.sh "$STAGE/ace/usr/share/ace/run.sh"

# --- luci-app-ace ---
mkdir -p "$STAGE/luci/usr/lib/lua/luci/controller" "$STAGE/luci/usr/lib/lua/luci/view/ace" \
	"$STAGE/luci/usr/share/rpcd/acl.d"
cp files/usr/lib/lua/luci/controller/ace.lua "$STAGE/luci/usr/lib/lua/luci/controller/"
cp files/usr/lib/lua/luci/view/ace/*.htm "$STAGE/luci/usr/lib/lua/luci/view/ace/"
# 缺这个 ACL，LuCI 24.10 的 CBI 页面会直接报
# 「Insufficient permissions to read UCI configuration.」，整个设置页空白。
cp files/usr/share/rpcd/acl.d/luci-app-ace.json "$STAGE/luci/usr/share/rpcd/acl.d/"

python3 - "$ROOT" "$STAGE" "$DIST" "$ARCH" "$VER" <<'PY'
import os, sys, tarfile, io, hashlib
root, stage, dist, arch, ver = sys.argv[1:6]

def mkdirs(p, mode):
    os.makedirs(p, exist_ok=True)
    os.chmod(p, mode)

def tar_from(base, out):
    """把 base 下的内容打成 ./ 开头的 tar.gz，uid/gid 归零。"""
    entries = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames.sort()
        for name in sorted(dirnames) + sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, base)
            entries.append((full, rel, os.path.isdir(full)))
    with tarfile.open(out, "w:gz", format=tarfile.GNU_FORMAT) as tf:
        for full, rel, isdir in entries:
            ti = tf.gettarinfo(full, arcname="./" + rel)
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            if isdir:
                ti.mode = 0o755
                tf.addfile(ti)
            else:
                # 脚本必须可执行，配置和页面保持 644。opkg 的维护脚本
                # （postinst/prerm/…）在 info 目录里没有 .sh 后缀，单独点名。
                base = os.path.basename(full)
                if ("/etc/init.d/" in full or full.endswith(".sh") or "/usr/bin/" in full
                        or base in ("postinst", "prerm", "preinst", "postrm")):
                    ti.mode = 0o755
                else:
                    ti.mode = 0o644
                with open(full, "rb") as fh:
                    tf.addfile(ti, fh)

def write_ipk(out, members):
    """ipk 是「tar.gz 里塞 debian-binary + control.tar.gz + data.tar.gz」，
    不是 dpkg 那种 ar 包。之前写成 ar，opkg 直接报 Malformed package file
    （官方包 hexdump 头两字节是 1f 8b 就能看出来）。"""
    with tarfile.open(out, "w:gz", format=tarfile.GNU_FORMAT) as tf:
        for name, data in members:
            ti = tarfile.TarInfo("./" + name)
            ti.size = len(data)
            ti.mtime = 0
            ti.mode = 0o644
            ti.uid = ti.gid = 0
            ti.uname = ti.gname = "root"
            tf.addfile(ti, io.BytesIO(data))

def ipk(name, version, arch, depends, desc, stage_dir, scripts, conffiles=()):
    work = os.path.join(stage, "_meta_" + name)
    os.makedirs(work, exist_ok=True)
    control = f"""Package: {name}
Version: {version}
Depends: {depends}
Architecture: {arch}
Maintainer: ACE <dev@xhwarp.local>
Section: net
Priority: optional
Description: {desc}
"""
    with open(os.path.join(work, "control"), "w") as f:
        f.write(control)
    # conffiles 必须列进 control.tar.gz 的 conffiles 文件，否则 opkg 升级时
    # 直接用包内的配置覆盖用户改过的 /etc/config/ace（真机实测 1.0.3 升级
    # 把用户设的 tun=1 打回默认 0，整屋静默回到裸 WAN）。
    if conffiles:
        with open(os.path.join(work, "conffiles"), "w") as f:
            for c in conffiles:
                f.write(c + "\n")
    for sname, body in scripts.items():
        p = os.path.join(work, sname)
        with open(p, "w") as f:
            f.write(body)
        os.chmod(p, 0o755)

    ctl = os.path.join(stage, "control.tar.gz")
    dat = os.path.join(stage, "data.tar.gz")
    tar_from(work, ctl)
    tar_from(stage_dir, dat)

    out = os.path.join(dist, f"{name}_{version}_{arch}.ipk")
    write_ipk(out, [
        ("debian-binary", open(os.path.join(stage, "debian-binary"), "rb").read()),
        ("control.tar.gz", open(ctl, "rb").read()),
        ("data.tar.gz", open(dat, "rb").read()),
    ])
    print("   ", os.path.basename(out), os.path.getsize(out), "bytes")

with open(os.path.join(stage, "debian-binary"), "w") as f:
    f.write("2.0\n")

postinst = """#!/bin/sh
[ -x /usr/bin/ace-engine ] || chmod 755 /usr/bin/ace-engine
[ -x /etc/init.d/ace ] || chmod 755 /etc/init.d/ace
[ -x /usr/share/ace/run.sh ] || chmod 755 /usr/share/ace/run.sh
mkdir -p /etc/ace
# 旧版 xehn → ace 一次性迁移：搬配置、搬数据目录、清旧防火墙 zone。
# 只在旧配置存在且新配置还没生成时做，避免覆盖用户已经改过的新配置。
# 部署时若先 opkg remove 旧包，修改过的 conffile 可能被改名保留，所以也认
# /tmp/xehn-migrate.conf（部署脚本提前做的快照）。
OLD_CONF=/etc/config/xehn
[ -f /etc/config/xehn ] || OLD_CONF=/tmp/xehn-migrate.conf
# 注意不能用「/etc/config/ace 不存在」做条件：opkg 先铺数据文件再跑 postinst，
# 包自带的默认 ace 配置此时已经在盘上，条件恒假、迁移永远不执行（1.1.0 首装实测）。
# 反向风险同理：ace 配置已被用户改过时也不能覆盖——只有当现有内容与包内默认
# 完全一致（或文件不存在）才迁移。包内默认的 md5 由打包脚本算好带进来。
ACE_DEFAULT_MD5=""
if [ -f "$OLD_CONF" ]; then
	CURRENT_MD5=$(md5sum /etc/config/ace 2>/dev/null | awk '{print $1}')
	if [ -f /etc/config/ace ] && [ -n "$ACE_DEFAULT_MD5" ] && [ "$CURRENT_MD5" != "$ACE_DEFAULT_MD5" ]; then
		logger -t ace "检测到用户已修改 ace 配置，跳过旧版 xehn 迁移"
	else
	/etc/init.d/xehn stop >/dev/null 2>&1
	/etc/init.d/xehn disable >/dev/null 2>&1
	cp "$OLD_CONF" /etc/config/ace
	[ -d /etc/xehn ] && cp -r /etc/xehn/. /etc/ace/ 2>/dev/null
	if uci -q get firewall.xehn >/dev/null 2>&1; then
		uci -q delete firewall.xehn
		for f in $(uci -q show firewall | sed -n "s/^\(firewall\.[^.]*\)=forwarding$/\1/p"); do
			[ "$(uci -q get $f.dest)" = "xehn" ] && uci -q delete $f
		done
		uci -q commit firewall
		/etc/init.d/firewall reload >/dev/null 2>&1
	fi
	logger -t ace "已迁移旧版 xehn 配置到 ace"
	mv /etc/config/xehn /etc/config/xehn.migrated 2>/dev/null
	rm -f /etc/rc.d/K10xehn /etc/rc.d/S99xehn
	fi
fi
rm -f /tmp/xehn-migrate.conf
# prerm 在升级开始前备份了用户改过的配置（opkg 的 conffiles 只对「已按
# conffiles 安装」的版本生效，跨版本首次升级保不住——真机实测 tun=1 被
# 打回 0，整屋静默回到裸 WAN）。这里先还原，再补新增选项的默认值。
if [ -f /tmp/ace-config.upgrade.bak ]; then
	cp /tmp/ace-config.upgrade.bak /etc/config/ace
	rm -f /tmp/ace-config.upgrade.bak
fi
# 内核不是 opkg 依赖（很多镜像里 mihomo 由 nikki 自带或手工放置），这里只提示
[ -x /usr/bin/mihomo ] || logger -t ace "提示：未找到 /usr/bin/mihomo，需在设置里指定内核路径"
# 老版本升级上来时配置里没有新增的选项，补默认值（已有的值一律不动）
if uci -q show ace.main >/dev/null 2>&1; then
	for kv in tun=0 lan_watchdog=1 dns_leak=1 watchdog_action=reboot; do
		k=${kv%%=*}; v=${kv#*=}
		[ -z "$(uci -q get ace.main.$k)" ] && uci -q set "ace.main.$k=$v"
	done
	uci -q commit ace
fi
# 版本号以引擎二进制为唯一事实来源，每次安装/升级刷新到 uci，首页图标下方显示。
# 这里读 /usr/bin/ace-engine（opkg 先铺数据文件再跑 postinst，它已在盘上），
# 不硬编码 VER，避免脚本里的 VER 与打进二进制的 main.version 不同步。
ACE_VER=$(/usr/bin/ace-engine version 2>/dev/null)
[ -n "$ACE_VER" ] && uci -q set "ace.main.version=$ACE_VER" && uci -q commit ace
# 升级前服务在跑就把它拉回来：之前 prerm stop 之后 postinst 只装文件不重启，
# opkg upgrade 一轮下来 ACE 静默停在「已停止」，用户还以为一切正常。
# 注意必须同步 start——后台 ( sleep 1; start ) & 会被 opkg 的脚本会话回收
# 掉（1.0.1 真机实测：标记在、条件满足、进程却没起来）。start_service 本身
# 是秒级（重活都在 procd/后台钩子里），同步跑不会拖住安装。
if [ -f /tmp/ace-was-running ]; then
	rm -f /tmp/ace-was-running
	if [ "$(uci -q get ace.main.tun)" = "1" ] || [ "$(uci -q get ace.main.enabled)" = "1" ]; then
		/etc/init.d/ace start >/dev/null 2>&1
	fi
fi
exit 0
"""
prerm = """#!/bin/sh
# 记录升级前服务是否在跑（有引擎进程即视为运行中），postinst 据此拉回。
# pidof 之外补 pgrep 兜底，个别精简镜像可能没编 pidof。
if ! pidof ace-engine >/dev/null 2>&1; then
	pgrep -f ace-engine >/dev/null 2>&1 || rm -f /tmp/ace-was-running
fi
: > /tmp/ace-was-running
[ -x /etc/init.d/ace ] && /etc/init.d/ace stop >/dev/null 2>&1
# 升级会把包内默认配置覆盖到 /etc/config/ace，先把用户改过的那份存起来，
# postinst 里还原（仅升级场景：卸载时不会有 postinst，备份留在 /tmp 无害）。
[ -f /etc/config/ace ] && cp /etc/config/ace /tmp/ace-config.upgrade.bak 2>/dev/null
exit 0
"""
postinst_luci = """#!/bin/sh
rm -rf /tmp/luci-indexcache /tmp/luci-modulecache 2>/dev/null
/etc/init.d/rpcd reload >/dev/null 2>&1
exit 0
"""

# 把包内默认配置的 md5 注进 postinst，迁移逻辑用它判断「现有 ace 配置
# 是否还是出厂默认」，避免覆盖用户改过的配置。
import hashlib
with open(os.path.join(root, "files", "etc", "config", "ace"), "rb") as _f:
    _md5 = hashlib.md5(_f.read()).hexdigest()
postinst = postinst.replace('ACE_DEFAULT_MD5=""', 'ACE_DEFAULT_MD5="%s"' % _md5)

# 不写死 mihomo 依赖：ImmortalWrt 上内核常由 nikki 之类自带或手工放置，
# opkg 里根本没有 mihomo 这个包，写上会让整包因「依赖无解」装不上。
ipk("ace", ver, arch, "libc", "ACE WARP/AmneziaWG client engine and service",
    os.path.join(stage, "ace"), {"postinst": postinst, "prerm": prerm},
    conffiles=("/etc/config/ace",))
ipk("luci-app-ace", ver, "all", "libc, ace, luci-compat",
    "LuCI interface for ACE", os.path.join(stage, "luci"), {"postinst": postinst_luci})
PY

echo
echo "==> checksums"
# 发布用：只写文件名（不带 dist/ 前缀），保证下载目录里 shasum -c 直接通过。
# 用 python3 而不是 shasum/sha256sum——两者在不同发行版上名字和选项都不一致。
(cd "$DIST" && python3 - <<'PYCHK'
import glob, hashlib
lines = []
for f in sorted(glob.glob("*.ipk")):
    h = hashlib.sha256(open(f, "rb").read()).hexdigest()
    lines.append("%s  %s" % (h, f))
    print("  %s  %s" % (h, f))
open("checksums.txt", "w").write("\n".join(lines) + "\n")
PYCHK
)

echo
echo "产物："
ls -la "$DIST"
