<div align="center">

# F50 · OpenWrt

**中兴 F50 / MU300 定制固件 · 内置存储更新 · Linux 6.18 LTS · Go KDAE · 节点小宝**

[![Build](https://img.shields.io/github/actions/workflow/status/Quan-0505/mu300-linux/f50-kdae-release.yml?branch=codex%2Ff50-internal-kdae&label=Build&style=flat-square)](https://github.com/Quan-0505/mu300-linux/actions/workflows/f50-kdae-release.yml)
[![OpenWrt](https://img.shields.io/badge/OpenWrt-25.12.5-00b5e2?style=flat-square)](https://openwrt.org/)
[![Kernel](https://img.shields.io/badge/Linux-6.18.56-orange?style=flat-square)](upstream)
[![KDAE](https://img.shields.io/badge/Go_KDAE-2.2.5-0b5?style=flat-square)](https://github.com/Quan-0505/daed-kdae)
[![Status](https://img.shields.io/badge/Status-待实机验证-yellow?style=flat-square)](https://github.com/Quan-0505/mu300-linux/releases)

**面向 ZTE F50 / MU300（Unisoc UMS9620 / ARM64）的 OpenWrt 构建**

[📦 固件下载](#download) · [✨ 功能介绍](#features) · [🚀 更新说明](#install) · [🔧 自行编译](#build) · [❤️ 开源致谢](#credits)

</div>

---

基于 [dikeckaan/mu300-linux](https://github.com/dikeckaan/mu300-linux)，整合 **F50 原生 Linux 适配、Go KDAE 和节点小宝**。本分支面向已有内置 OpenWrt 的更新，延续此前使用的 **6.18 + BTF** 路线，并保留 F50 的 SIPA RAWIP/veth 代理适配。

维护分支为 [`codex/f50-internal-kdae`](https://github.com/Quan-0505/mu300-linux/tree/codex/f50-internal-kdae)。基础源码来自作者 `clean-tf-7.2` 分支；这个名称不表示本固件采用 7.2，本包实际编译 **Linux 6.18.56**。

> [!IMPORTANT]
> 当前为 **待实机验证的预发布固件**。内核、模块、KDAE、存储工具及打包检查已通过；F50 尚未接回，未刷入本版本，也未验证该版本的蜂窝、Wi-Fi 或断电重启表现。

<a id="features"></a>
## ✨ 功能介绍

| 功能 | 说明 |
| --- | --- |
| **内置 OpenWrt** | OpenWrt 25.12.5，更新已有内置 Linux 区域，不重复安装或缩容 |
| **6.18 LTS 内核** | Linux 6.18.56，保留 BTF、BPF/JIT、veth、TC/clsact 与 TUN 等功能 |
| **Go KDAE** | daed-kdae 2.2.5，包含订阅、节点、群组、DNS、路由、实时日志及热重载管理 |
| **F50 专用代理适配** | 修正 SIPA RAWIP IPv4 出站包的 Ethernet 头识别；启用 veth 兼容路径并关闭不适用的 redirect_peer 路径 |
| **节点小宝** | 官方 ARM64 4.3.5-734 客户端，使用自己的账号登录绑定 |
| **设备管理** | 作者的 F50 蜂窝、热点、USB、短信及 LuCI 管理功能 |
| **插件与配置保留** | 保留原账号、网络/热点、防火墙、KDAE 数据与 CA、节点小宝身份，以及已有 KixDNS、Samba 设置和共享目录 |
| **构建校验** | 源码树与内核产物对应校验、实际 Image 内嵌配置、匹配模块、打包文件权限及内外层 SHA256 |

KDAE 保留两个必要兼容环境变量：`DAE_FORCE_VETH=1`、`DAE_DISABLE_REDIRECT_PEER=1`。F50 的适配补丁随源码提供，不能用未经适配的通用程序覆盖后就认定网络正常。

节点小宝的网关转发与回程路由需要按实际网络设置。TCP/UDP 单播互通不等于广播或 mDNS 自动发现；预装客户端也不代表第三方账号已绑定或已获得服务权限。

<a id="download"></a>
## 📦 固件下载

从 **[Releases](https://github.com/Quan-0505/mu300-linux/releases)** 选择明确标注 F50 的版本。当前版本保持 **Pre-release**，不设为稳定版或自动更新的 latest。

| 文件 | 用途 |
| --- | --- |
| `mu300-openwrt-rootfs.tar.gz` | OpenWrt 系统与预装插件，包含 LuCI |
| `mu300-kernel-6.18.tar.gz` | F50 6.18 内核、配套模块与通用启动更新段 |
| `mu300-update` | 本分支更新器，包含手工插件的数据保留规则 |
| `build.json` / `kernel.config` | 实际构建来源、软件版本及内核配置 |
| `SHA256SUMS` / `README.zh-CN.md` | 文件校验及本次更新说明 |

本包是 **已有安装的更新资产**，不是 Android PAC、可直接写入的 `boot.img`，也不是 armsr 整盘镜像。不能把这些 tar.gz 当作 LuCI 通用固件直接刷写。

<a id="install"></a>
## 🚀 更新说明

### 更新前

1. 接回实际 F50，核对机型、内核、内置 Linux 区域、启动槽、管理地址和可用空间。
2. 将当前 boot、GPT、系统、插件和配置备份到电脑，校验完整性；停止数据库写入后取得一致性快照。
3. 下载同一 Release 的系统、内核和更新器，核对全部 SHA256，并检查实际内核选择为 6.18。
4. 使用本分支更新器准备新系统、保留配置与设备运行文件，再更新启动镜像；验证成功前保留旧系统和 boot 回退文件。

当前设备离线，所以这里不提供未经实机预检的一键刷写命令。作者的原始安装资料保留在 [上游技术说明](README.upstream.md)，本分支的更新范围见 [F50 更新包说明](f50/README.zh-CN.md)。

### 存储与 Android

**已有内置 OpenWrt 更新不修改 GPT、不重新缩容、不格式化 userdata，也不自动回收 Android 分区。** 内置运行与删除全部 Android 分区是两件不同的操作。

如需改成仅使用 OpenWrt 并回收 Android 空间，必须先在实机上确认完整可恢复备份、分区布局及启动依赖，单独制定迁移方案。蜂窝基带、NV/校准和必要启动链始终需要保留。

### 访问与配置

| 入口 | 地址 |
| --- | --- |
| LuCI | `http://<F50管理地址>/` |
| KDAE | `http://<F50管理地址>:2023/` |
| 节点小宝 | `http://<F50管理地址>:9118/` |

更新沿用原来的管理网段、账号、热点、订阅和组网身份；公开固件不预置个人密码、订阅、节点或网络拓扑。已有 KixDNS 按原配置保留，不会在此次固件更新中自动改为另一套 DNS 策略。

### 验证范围

此前 F50 适配版本的代理、自启和组网测试，**不能替代本次新内核与新 KDAE 组合的实机验证**。接回设备后需要检查：

- 蜂窝注册、数据连接、Wi-Fi/USB 与管理登录。
- 直连与代理的真实 HTTPS、DNS、配置重载及重启自启。
- 节点小宝下游与远端的双向 TCP/UDP。
- 断电冷启动后上述服务能否恢复。

<a id="build"></a>
## 🔧 自行编译

Actions → **F50 internal OpenWrt with KDAE**，选择 `codex/f50-internal-kdae` 分支运行。构建使用 Linux runner，保留大小写不同的内核模块文件，不在 Windows 文件系统直接解包模块树。

```sh
git clone --branch codex/f50-internal-kdae https://github.com/Quan-0505/mu300-linux.git
cd mu300-linux
```

工作流分别构建内核、Go KDAE 和存储工具，再组装系统与更新包。KDAE 固定上游源码并应用 [F50 补丁](f50/kdae-f50.patch)；公开依赖按 SHA256 校验。生成的 Release 默认是待实机验证的预发布版。

源码、编译和打包检查见 [工作流](.github/workflows/f50-kdae-release.yml) 与 [构建脚本](f50/build.py)。完整来源、实际内核配置和校验和以对应 Release 为准。

<a id="credits"></a>
## ❤️ 开源致谢

感谢以下项目和作者的持续工作：

- **[dikeckaan/mu300-linux](https://github.com/dikeckaan/mu300-linux)**：F50 / MU300 Linux 项目、安装与更新工具、内核适配及设备管理基础。
- **[kanoqwq/mu300-linux](https://github.com/kanoqwq/mu300-linux)**：LuCI 管理、公共服务、安装器和硬件兼容改进。
- **[Enceka](https://github.com/Enceka)** 及相关 Unisoc/Linux 贡献者：设备适配、驱动研究与共享修复。
- **[OpenWrt](https://openwrt.org/)**、**[Linux](https://www.kernel.org/)**：路由系统、内核及软件包生态。
- **[daeuniverse](https://github.com/daeuniverse)**、**[olicesx/kdae](https://github.com/olicesx/dae/tree/kdae)**、**[ksong008/daed](https://github.com/ksong008/daed)**：代理引擎、控制器和管理界面的基础工作；通过 [daed-kdae](https://github.com/Quan-0505/daed-kdae) 集成。
- 所有贡献代码、测试、文档与问题反馈的维护者和使用者。

仓库脚本沿用原有 [许可](LICENSE)，Linux、KDAE 和其他组件保留各自版权与许可证。节点小宝使用[官方软件](https://iepose.com/)并遵循其授权及服务条款，不作为本仓库的开源组件。
