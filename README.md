<div align="center">

# ACE for OpenWrt

**在路由器上跑 Cloudflare WARP —— 整屋出口，点一下就连**

Go 引擎 + procd 服务 + LuCI 界面。注册账号、扫端点、挑最优、渲染 mihomo 配置、起 TUN、
验数据面、守护会话，全部在路由器本地完成，不依赖任何外部面板。

[![release](https://img.shields.io/github/v/release/bluepebblex-dev/openwrt-ace?style=flat-square&color=2ea043)](https://github.com/bluepebblex-dev/openwrt-ace/releases)
[![license](https://img.shields.io/github/license/bluepebblex-dev/openwrt-ace?style=flat-square)](LICENSE)
[![platform](https://img.shields.io/badge/OpenWrt-24.10-00a4d8?style=flat-square)](https://openwrt.org)
[![arch](https://img.shields.io/badge/arch-aarch64__cortex--a53-6e7781?style=flat-square)](#安装)
[![last commit](https://img.shields.io/github/last-commit/bluepebblex-dev/openwrt-ace?style=flat-square)](https://github.com/bluepebblex-dev/openwrt-ace/commits/main)

[安装](#安装) · [首次连接](#首次连接两步走) · [界面](#界面) · [协议](#支持的协议) · [设计取舍](#设计取舍) · [排障](#排障)

</div>

![ACE 首页：连接状态、实时速率与运行日志](docs/screenshots/luci-overview.png)

## 特性

| | |
|---|---|
| **6 种协议** | AmneziaWG / WireGuard / WARP-in-WARP / MASQUE（H3、H2、嵌套），首页就地切换，改完立即生效 |
| **整屋接管** | `ace0` TUN + 独立防火墙 zone（forward + masq），局域网设备零配置 |
| **DNS 不抢 53** | 内核解析器听 `127.0.0.1:7874`，dnsmasq 上游指过去；隧道挂了局域网照常解析 |
| **防污染** | `dns_leak=1` 时上游只留可信解析器，剔掉会被递归污染的国内解析器 |
| **自愈** | 探活连续三次失败自动断开；`br-lan` 载波丢失自动重启（可关） |
| **升级保配置** | conffiles + prerm/postinst 备份还原，升级不把 `tun` 打回 0 |
| **内核自举** | 路由器上没有 mihomo 也能用：设置页一键下载（官方源 + 镜像，装前校验 SHA256） |
| **界面同构** | 首页 / 设置两页，布局与 macOS 桌面端一致 |

## 安装

从 [Releases](https://github.com/bluepebblex-dev/openwrt-ace/releases) 下载两个包，传到路由器装：

```sh
opkg install ace_*_aarch64_cortex-a53.ipk luci-app-ace_*_all.ipk
```

或者用仓库里的脚本一条命令搞定（自动上传 + 安装 + 重启服务）：

```sh
ACE_SSH_PASS=路由器密码 ./install.sh 192.168.1.1
```

装完打开 **LuCI → 服务 → ACE**（浏览器强刷一次，旧缓存会看不到新界面）。

> 路由器上已经装了 mihomo（nikki / OpenClash 之类通常都会带）就直接复用；没有的话打开设置页点
> 「下载内核」：取官方 v1.19.32（GitHub 不通时自动换镜像），下载后校验 SHA256，装到
> `/etc/ace/core/mihomo`，约 15 MB。

| 包 | 内容 | 依赖 |
|---|---|---|
| `ace` | 引擎二进制、init.d、uci 配置 | `mihomo` 可选（没有时在设置页下载，或复用 nikki 自带的） |
| `luci-app-ace` | LuCI 控制器与页面 | `ace`、`luci-compat` |

> 目前只出 `aarch64_cortex-a53`（mediatek/filogic 等）。其他架构改 `build-ipk.sh` 里的
> `ARCH` 与 `GOARCH` 即可自行构建，引擎本身是纯 Go 无 CGO。

## 首次连接：两步走

**第一次务必先不开 TUN。** `tun` 默认是 `0`，此时服务只起一个本地混合端口，路由器网络毫无影响：

```sh
/etc/init.d/ace start
curl -x http://127.0.0.1:7890 -sI https://www.gstatic.com/generate_204
```

`204` 说明引擎在路由器上能连上出口。确认后再接管整屋：

```sh
uci set ace.main.tun=1 && uci commit ace && /etc/init.d/ace restart
```

这时才会建 `ace0`、改 dnsmasq 上游、加防火墙 zone。这个顺序不是保守，是踩过坑——真机上出现过跑
TUN 之后 LAN 侧设备直接失联、路由器 IP 不可达但 WAN 还活着的状况，只能人工断电。分两步至少保证
出问题只影响这个服务本身。

首次连接会自动注册 WARP 账号、扫端点（1~3 分钟），之后走缓存很快。

## 界面

两个页面，和 macOS 桌面端同一套结构。

**首页** —— 大圆钮一键连接/断开（连接过程显示阶段、可点取消）；协议与出口地区就地切换；信息卡显示
本机 IP / 出口国家（国旗 + Cloudflare 机房）/ 延迟 / 出口 IP；流量卡显示上下行实时速率与本次累计；
下方是运行日志（服务事件 + 引擎输出，可刷新、可清除）。

**设置页** —— 连接方式、TUN 接管、DNS 接管 / 防泄漏、LAN 失联自愈等运行参数，保存后服务自动重启
（隧道重建约 10~20 秒）。

<details>
<summary>设置页截图</summary>

![设置页：连接、DNS 与转发、自愈开关](docs/screenshots/luci-settings.png)

</details>

## 支持的协议

| 协议 | 说明 |
|---|---|
| `awg` | AmneziaWG，抗封锁最好（默认） |
| `wg` | WireGuard，更快 |
| `wwarp` | WARP-in-WARP，双层 wg/awg 链式 |
| `masque` | MASQUE，CONNECT-IP over HTTP/3/QUIC |
| `masque-h2` | MASQUE，CONNECT-IP over HTTP/2/TCP |
| `masque-mm` | MASQUE-in-MASQUE，嵌套隧道 |

> 端点由引擎自动挑选（扫描缓存 6 小时内复用）。MASQUE 系没有「端点池」的概念，走 Cloudflare 固定 anycast。

## 配置项

`/etc/config/ace`，也可以直接在设置页改。

| 键 | 默认 | 说明 |
|---|---|---|
| `enabled` | `0` | 随系统启动 |
| `proto` | `awg` | 底层协议，见上表 |
| `tun` | `0` | 是否 TUN 接管整屋流量 |
| `dns_takeover` | `1` | 把 dnsmasq 上游指向内核解析器（仅 `tun=1`） |
| `dns_leak` | `1` | 内核解析器跟随规则走隧道，并剔除国内解析器（仅 `tun=1`） |
| `lan_watchdog` | `1` | `br-lan` 载波丢失三次后自愈 |
| `watchdog_action` | `reboot` | 自愈动作：`reboot` / `none`（只记日志） |
| `openvpn` | `0` | 在 WARP 上再叠一层 VPN Gate 出口 |
| `openvpn_region` | 空 | 两位国家代码，空 = 按延迟自动挑 |
| `pick` | 空 | 固定出口端点 `ip:port`，空 = 引擎自动挑最优 |
| `starred` | 空 | 收藏的端点列表（仅界面筛选用） |
| `mixed_port` | `7890` | 本地混合代理端口（旁路调试用） |
| `ipv6` | `0` | 使用 IPv6 端点池 |
| `core` | 空 | 内核路径，空 = `/usr/bin/mihomo`；也可留空让引擎用 `/etc/ace/core/mihomo` |

## 设计取舍

**为什么不是另写一套路由逻辑。** 引擎本身就是完整的客户端：注册 WARP 账号、扫端点、挑最优、渲染
mihomo 配置、起内核、验数据面、守护会话。移植只需要补 Linux 侧的差异，不需要重写。

![数据路径：局域网 → br-lan → 防火墙 zone ace0 → ace0 TUN → WARP → 互联网](docs/screenshots/architecture.svg)

**TUN 而不是 TPROXY。** 引擎渲染的 mihomo 配置本来就带 `tun.auto-route + auto-detect-interface +
dns-hijack`，在 Linux 上是原生的；改用 TPROXY 要重做一整套 nft 规则，收益不明。

**DNS 不抢 53。** macOS 用 53 是因为系统解析器只能填 IP；路由器上 53 是 dnsmasq 的。内核改听
`127.0.0.1:7874`，再把 dnsmasq 上游指过去——隧道挂掉时局域网照常解析，不会整屋断网。

**DNS 防污染（`dns_leak=1`）。** 即使 DNS 查询跟随规则走隧道，国内公共解析器自身的递归查询仍会被
污染，而且 mihomo 并行竞速取最快的应答——污染结果稳定获胜。所以开启泄漏保护时，上游只保留可信
解析器（1.1.1.1 / 1.0.0.1，经隧道查询），国内域名策略与代理服务器解析保留完整列表。

**防火墙用 zone，不用 include。** fw4 的 include 塞进 chain 会和它自己的规则顺序打架；独立 zone
（`device ace0` + `masq 1`）是唯一同时解决 forward 放行与 SNAT 的地方。

**三层安全网**（都是踩坑后加的）：

1. `route-exclude-address` 排除 `192.168/10/172.16` —— 局域网流量永不进隧道；
2. 就绪后连续三次探活失败则自动断开，不让路由器挂在「显示已连接、实际不通」的状态；
3. 断开时按备份还原 dnsmasq、删掉 zone、`conntrack -F` 清流表。

**LAN 失联自愈（`lan_watchdog`）。** TUN 起来并探活通过后启一个看门狗，每 20 秒读一次
`/sys/class/net/br-lan/carrier`：曾经通过、之后连续三次读不到载波，就 `logger` 记一笔再 `reboot`
——替人拔电源。只在「通 → 断」时触发，开机没插网线不会乱重启；介意误重启可以设 `none`。

**升级保配置。** conffiles 声明 + prerm/postinst 备份还原双保险，opkg 升级不会把用户改过的
`/etc/config/ace` 打回默认值（曾真机实测 `tun=1` 被覆盖归零、整屋静默回到裸 WAN，故修）。

## 验证

只看到出口 IP 对**不算验证通过**——那只能证明「有这么个 IP」，证明不了「家里设备的流量真的穿过了
路由器隧道」。三步全过才算。

**① 流量确实穿 `ace0`（硬证据）**

```sh
cat /sys/class/net/ace0/statistics/rx_bytes /sys/class/net/ace0/statistics/tx_bytes
# —— 让家里某台设备访问一次外网（curl https://www.qq.com 之类）——
cat /sys/class/net/ace0/statistics/rx_bytes /sys/class/net/ace0/statistics/tx_bytes
```

计数器明显上涨说明 LAN 流量走了隧道。`conntrack -L` 里查不到局域网源 IP 是**正常的**：转发后源地址
被 masquerade 改写成 `ace0` 的 IP，且短连接很快回收，所以看计数器比翻连接表可靠。

**② 排除「其实是设备自己在跑隧道」（防假阳性）**

在被测的局域网设备上确认它自己没有独立隧道：默认路由指向路由器（不是本机某 utun）；没有本机
`mihomo` / WARP / ACE 进程；没有激活的 VPN 配置（如 macOS `scutil --nc list`）。任一条不满足，
出口 IP 就可能来自设备自己的隧道。

**③ 真实站点可达（不是只看状态码）**

```sh
curl -sL https://www.youtube.com | grep -oE '<title>[^<]*</title>' | head -1
curl -sL https://github.com     | grep -oE '<title>[^<]*</title>' | head -1
curl -sL https://www.google.com | grep -oE '<title>[^<]*</title>' | head -1
```

三个都返回真实 `<title>` 即通过。Google 首页可能 302 到 `google.com.hk`（WARP 出口被 Google 判为
HK），跟到 `.com.hk` 拿到 200 + 标题即正常，不是故障。

## 排障

| 现象 | 位置 |
|---|---|
| 提示「未检测到 mihomo 内核」 | 设置页点「下载内核」；或指定现成内核 `uci set ace.main.core=/usr/bin/mihomo` |
| 连不上、卡在扫描 | `tail -f /var/log/ace.log`，或在首页日志区看「服务事件」 |
| 内核起不来 | `/etc/ace/core/core.log` |
| 出口 IP 对但怀疑没走隧道 | 看 `ace0` 计数器是否增长（验证①），并确认设备自身无隧道（②） |
| Google 302 / 落到 .com.hk | 正常，WARP 出口被 Google 判为 HK 的 geo 重定向，跟到 200 即可 |
| 端口被占 | 日志会写明 `端口 7890 被 xxx (pid N) 占用` |
| DNS 不解析 | `uci show dhcp.@dnsmasq[0]`、`netstat -ln \| grep 7874` |
| 想彻底恢复 | `/etc/init.d/ace stop`，再 `uci set dhcp.@dnsmasq[0].noresolv=0` |
| init.d 动作挂死 | 查 flock 泄漏：`for d in /proc/[0-9]*/fd/1000; do readlink $d; done`，后台子进程继承 procd 锁 fd 会把它占成永久 |

**应急**：若某个版本导致 LAN 不可达，串口 / SSH 里 `/etc/init.d/ace stop` 即可；最坏情况断电重启，
服务不会自启，路由器回到干净状态。

## 与 macOS 版的差异

| | macOS | OpenWrt |
|---|---|---|
| 流量接管 | utun + 系统解析器 | `ace0` + dnsmasq 上游 |
| 系统代理 | 不设置（TUN 全接管） | 不涉及 |
| DNS 端口 | 127.0.0.1:53 | 127.0.0.1:7874 |
| 界面 | Swift 原生窗口 | LuCI 页面（首页 / 设置，同构布局） |
| 生命周期 | GUI 持有 | procd 看护 |
| 端点缓存 | settings.json | `/etc/ace/cache.json`（引擎共用，TTL 6 小时） |

## 构建

需要 Go 1.21+ 与 python3（打 ipk 用），引擎在仓库内，克隆即可构建，不需要 OpenWrt SDK：

```sh
./build-ipk.sh              # 默认 aarch64_cortex-a53
VER=1.2.1 ./build-ipk.sh    # 指定版本号
```

产物在 `dist/`，`-ldflags "-s -w"` 后引擎约 13.5 MB，ipk 约 5 MB。

## 目录结构

```
openwrt-ace/
├── build-ipk.sh              # 不依赖 OpenWrt SDK 直接产出 ipk
├── install.sh                # 上传 + 安装到路由器
├── engine/                   # Go 引擎（WARP 注册、端点扫描、mihomo 渲染、会话守护）
└── files/
    ├── etc/config/ace        # uci 配置
    ├── etc/init.d/ace        # procd 服务封装
    └── usr/
        ├── share/ace/run.sh  # uci → 命令行
        ├── share/rpcd/acl.d/ # LuCI ACL
        └── lib/lua/luci/     # 控制器 + 首页/设置页面
```

## License

MIT。引擎部分源自上游开源实现，路由器侧的服务封装、LuCI 界面与打包脚本为本仓库所有。
