# AC LED 氛围灯开关 — 一键部署

在 iStoreOS / OpenWrt 的 LuCI 首页顶部横条加一个「氛围灯」拨动开关：
- 开 = 启动五色呼吸灯（红→黄→绿→蓝→紫）
- 关 = 停止并熄灭所有 LED

这是**真机定制**，不打进 ACE 的 ipk（避免改动系统主题文件影响所有装机用户）。
固件升级或重置后，在路由器上重新跑一次 `deploy.sh` 即可恢复。

## 依赖

1. `coreutils-sleep`（提供亚秒延时 `/usr/libexec/sleep-coreutils`）：
   ```
   opkg update && opkg install coreutils-sleep
   ```
2. 五色呼吸服务（两个文件，本目录提供）：
   - `ace-led-breathd` → `/usr/bin/ace-led-breathd`
   - `ace-led-breath` → `/etc/init.d/ace-led-breath`
3. ACE 插件的 LuCI controller 需带 `api_led` 接口（见 `controller-api-led.fragment`）。

## 部署（在路由器上执行）

```
cd /tmp && ./deploy.sh
```

脚本做三件事：
1. 备份并替换呼吸灯服务脚本，启用服务
2. 给 `/usr/lib/lua/luci/controller/ace.lua` 打 `api_led` 补丁（幂等，重复跑不会重复加）
3. 把 `main.htm.fragment` 的内容注入首页 `/usr/lib/lua/luci/view/quickstart/main.htm`（幂等）

然后清 LuCI 缓存、硬刷浏览器即可看到开关。

## 文件

| 文件 | 说明 |
|---|---|
| `ace-led-breathd` | 五色混色呼吸守护脚本（RGB 三路混色 + 两路 PWM 灯跟随） |
| `ace-led-breath` | rc.common 服务脚本（start/stop/enable/disable） |
| `main.htm.fragment` | 首页浮层开关的完整 HTML（含在 main.htm 中的插入位置） |
| `controller-api-led.fragment` | 给 ACE controller 增加 `api_led` 接口的代码片段（含路由） |
| `deploy.sh` | 一键部署脚本 |

## 硬件说明（Ruijie BE72 PRO）

本机 5 个 LED 全是 PWM 灯：`led_sys_red/green/blue` 是同一根 RGB 灯带的三通道，
红+绿混黄、红+蓝混紫；`led_red/led_green` 是两根独立灯，跟随红系/绿系同步呼吸。
这一物理事实是查设备树 `pwm-leds` 节点 + 肉眼混色实验确认的，换机型需重新验证。
