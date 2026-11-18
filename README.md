# ACE for OpenWrt

Go 编写的 WARP/AmneziaWG/MASQUE 客户端引擎 + OpenWrt 插件打包：
引擎直接跑在路由器上，TUN 接管整屋流量，LuCI 里点一下就能连。

目标设备：ImmortalWrt 24.10 / aarch64_cortex-a53（mediatek/filogic），已在真机上验证编译与运行。

---

## 结构

```
openwrt-ace/
├── build-ipk.sh              # 不依赖 OpenWrt SDK 直接产出 ipk
├── install.sh                # 上传 + 安装到路由器
├── engine/                   # Go 引擎源码（WARP 注册、端点扫描、mihomo 渲染、会话守护）
└── files/
    ├── etc/config/ace        # uci 配置
    ├── etc/init.d/ace        # procd 服务封装
    └── usr/
        ├── share/ace/run.sh  # uci → 命令行
        ├── share/rpcd/acl.d/ # LuCI ACL
        └── lib/lua/luci/     # 控制器 + 概览/设置两个页面
```

两个包：

| 包 | 内容 | 依赖 |
|---|---|---|
| `ace` | 引擎二进制、init.d、uci 配置 | `mihomo`（内核，通常由 nikki 等自带） |
| `luci-app-ace` | LuCI 控制器与页面 | `ace`、`luci-compat` |

---

## 设计

**为什么不是另写一套路由逻辑。** 引擎本身就是完整的客户端：注册 WARP 账号、扫端点、挑最优、渲染 mihomo 配置、起内核、验数据面、守护会话。移植只需要补 Linux 侧的差异，不需要重写。

**TUN 而不是 TPROXY。** 引擎渲染的 mihomo 配置本来就带 `tun.auto-route + auto-detect-interface + dns-hijack`，在 Linux 上是原生的；改用 TPROXY 要重做一整套 nft 规则，收益不明。

**DNS 不抢 53。** macOS 用 53 是因为系统解析器只能填 IP；路由器上 53 是 dnsmasq 的。内核改听 `127.0.0.1:7874`，再把 dnsmasq 上游指过去——隧道挂掉时局域网照常解析，不会整屋断网。

**DNS 防污染（`option dns_leak '1'`）。** 即使 DNS 查询跟随规则走隧道，国内公共解析器自身的递归查询仍会被污染，而且 mihomo 并行竞速取最快的应答——污染结果稳定获胜。所以泄漏保护开启时，上游只保留可信解析器（1.1.1.1/1.0.0.1，经隧道查询），国内域名策略与代理服务器解析保留完整列表。

**防火墙用 zone，不用 include。** fw4 的 include 塞进 chain 会和它自己的规则顺序打架；独立 zone（`device ace0` + `masq 1`）是唯一同时解决 forward 放行与 SNAT 的地方。

**三层安全网**（都是踩坑后加的）：

1. `route-exclude-address` 排除 `192.168/10/172.16`——局域网流量永不进隧道；
2. 就绪后连续三次探活失败则**自动断开**，不让路由器挂在「显示已连接、实际不通」的状态；
3. 断开时按备份还原 dnsmasq，删掉 zone，`conntrack -F` 清流表。

**TUN 默认关（`option tun '0'`）。** 真机上出现过一次：跑 TUN 之后 LAN 侧设备直接失联、路由器 IP 不可达，WAN 却还活着——交换芯片/驱动哑了，只能人工断电。所以第一次安装先不接管整屋，只起本地混合端口验通路：

```sh
/etc/init.d/ace start                        # tun=0，局域网毫无影响
curl -x http://127.0.0.1:7890 -sI https://www.gstatic.com/generate_204
```

确认引擎在路由器上能连上出口后，再 `uci set ace.main.tun=1 && uci commit ace` 重启服务，把整屋流量导进去。

**LAN 失联自愈（`option lan_watchdog '1'`）。** TUN 起来并探活通过后启一个看门狗，每 20 秒读一次 `/sys/class/net/br-lan/carrier`：曾经通过、之后连续三次读不到载波，就 `logger` 记一笔再 `reboot`——替人拔电源。只在「通→断」时触发，开机没插网线不会乱重启。

**升级保配置。** conffiles 声明 + prerm/postinst 备份还原双保险，opkg 升级不会把用户改过的 `/etc/config/ace` 打回默认值（曾真机实测 tun=1 被覆盖归零、整屋静默回到裸 WAN，故修）。

---

## 构建

需要 Go 1.21+（交叉编译 `GOOS=linux GOARCH=arm64 CGO_ENABLED=0`）：

```sh
./build-ipk.sh              # 引擎源码在仓库内 engine/，克隆即可构建
VER=1.1.0 ./build-ipk.sh    # 指定版本号
```

产物在 `dist/`，`-ldflags "-s -w"` 后引擎约 13.5 MB。

## 安装

```sh
ACE_SSH_PASS=路由器密码 ./install.sh 192.168.1.1
```

或手动：

```sh
opkg install ace_*.ipk luci-app-ace_*.ipk
```

装完打开 **LuCI → 服务 → ACE**。

## 使用

1. 「设置」里选协议（默认 AmneziaWG）与是否用 OpenVPN 出口，保存后服务自动重启；
2. 回概览页点圆形按钮；
3. 首次连接会自动注册 WARP 账号、扫端点（1~3 分钟），之后走缓存很快；
4. 状态卡片显示出口 IP / 地区 / 延迟 / 已连接时长，下方是实时日志（可清除）。

**第一次务必分两步**：先保持「TUN 接管整屋流量」关闭，点连接确认引擎能连上（日志里出现 `connected ... country=XX`）；再回设置打开 TUN 保存，这时才会建 `ace0`、改 dnsmasq、加防火墙 zone，整屋才开始走隧道。

### 支持的协议

| 协议 | 说明 |
|---|---|
| `awg` | AmneziaWG，抗封锁最好（默认） |
| `wg` | WireGuard，更快 |
| `wwarp` | WARP-in-WARP，双层 wg/awg 链式 |
| `masque` | MASQUE，CONNECT-IP over HTTP/3/QUIC |
| `masque-h2` | MASQUE，CONNECT-IP over HTTP/2/TCP |
| `masque-mm` | MASQUE-in-MASQUE，嵌套隧道 |

## 验证

只看到出口 IP 对**不算验证通过**——那只能证明"有这么个 IP"，证明不了"家里设备的流量真的穿过了路由器隧道"。三步全过才算：

**① 流量确实穿 `ace0`（硬证据）**

隧道接口的收发计数在局域网发起外网请求后**必须增长**。采两次、做差：

```sh
cat /sys/class/net/ace0/statistics/rx_bytes /sys/class/net/ace0/statistics/tx_bytes
# —— 让家里某台设备访问一次外网（curl https://www.qq.com 之类）——
cat /sys/class/net/ace0/statistics/rx_bytes /sys/class/net/ace0/statistics/tx_bytes
```

计数器明显上涨，说明 LAN 流量走了隧道。`conntrack -L` 里查不到局域网源 IP 是**正常的**：转发后源地址被 masquerade 改写成 `ace0` 的 IP，且短连接很快回收，所以看计数器比翻连接表可靠。

**② 排除"其实是设备自己在跑隧道"（防假阳性）**

在**被测的局域网设备**上确认它自己没有独立隧道：
- 默认路由指向路由器（不是本机某 utun）；
- 没有本机 `mihomo` / WARP / ACE 进程；
- 没有激活的 VPN 配置（如 macOS `scutil --nc list`）。

任一条不满足，出口 IP 就可能来自设备自己的隧道，而不是路由器。

**③ 真实站点可达（不是只看状态码）**

```sh
curl -sL https://www.youtube.com | grep -oE '<title>[^<]*</title>' | head -1
curl -sL https://github.com     | grep -oE '<title>[^<]*</title>' | head -1
curl -sL https://www.google.com | grep -oE '<title>[^<]*</title>' | head -1
```

三个都返回真实 `<title>`（YouTube / GitHub / Google）即通过。注意：Google 首页可能 302 重定向到 `google.com.hk`（WARP 出口被 Google 判为 HK），跟到 `.com.hk` 拿到 200 + 标题即正常，不是故障。

## 排障

| 现象 | 位置 |
|---|---|
| 连不上、卡在扫描 | `tail -f /var/log/ace.log` |
| 内核起不来 | `/etc/ace/core/core.log` |
| 出口 IP 对但怀疑没走隧道 | 看 `ace0` 计数器是否增长（见「验证」①），并确认设备自身无隧道（②） |
| Google 302 / 落到 .com.hk | 正常，WARP 出口被 Google 判为 HK 的 geo 重定向，跟到 200 即可 |
| 端口被占 | 日志会写明 `端口 7890 被 xxx (pid N) 占用` |
| DNS 不解析 | `uci show dhcp.@dnsmasq[0]`、`netstat -ln \| grep 7874` |
| 想彻底恢复 | `/etc/init.d/ace stop`，再 `uci set dhcp.@dnsmasq[0].noresolv=0` |
| init.d 动作挂死 | 检查 flock 泄漏：`for d in /proc/[0-9]*/fd/1000; do readlink $d; done`，后台子进程继承 procd 锁 fd 会把它占成永久 |

**应急**：若某个版本导致 LAN 不可达，串口/SSH 里执行 `/etc/init.d/ace stop` 即可；最坏情况断电重启，服务不会自启，路由器回到干净状态。

## 与 macOS 版的差异

| | macOS | OpenWrt |
|---|---|---|
| 流量接管 | utun + 系统解析器 | ace0 + dnsmasq 上游 |
| 系统代理 | 不设置（TUN 全接管） | 不涉及 |
| DNS 端口 | 127.0.0.1:53 | 127.0.0.1:7874 |
| 界面 | Swift 原生窗口 | LuCI 页面 |
| 生命周期 | GUI 持有 | procd 看护 |

## License

MIT
