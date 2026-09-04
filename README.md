# 深澜校园网登录器 (srun-go) 🐹

<div align="center">

**高性能、高安全、极低资源占用的现代化深澜 (Srun 3k/4k) 校园网自动化认证与保活守护客户端**

[![Go Version](https://img.shields.io/github/go-mod/go-version/unskycel/srun-go?style=flat-square&logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![CI Status](https://img.shields.io/github/actions/workflow/status/unskycel/srun-go/ci.yml?branch=main&style=flat-square&logo=githubactions&label=CI)](https://github.com/unskycel/srun-go/actions)
[![Latest Release](https://img.shields.io/github/v/release/unskycel/srun-go?style=flat-square&logo=github)](https://github.com/unskycel/srun-go/releases)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6?style=flat-square&logo=windows)](https://github.com/unskycel/srun-go)

[功能特性](#-核心特性) • [快速上手](#-快速上手) • [开机自启与通知](#-开机自启与系统通知) • [工程架构](#-架构分层设计) • [本地编译与构建](#-本地开发与编译) • [开源协议](#-开源许可证)

</div>

---

## 🌟 核心特性

- ⚡ **毫秒级极速认证**：纯 Go 语言协程高并发驱动，深度原生实现深澜认证协议栈（Challenge 动态握手、`xEncode` 算法、非标自定义 Base64 字母表、HMAC-MD5 密码散列校验与 SHA1 校验和）。
- 🛡️ **Windows 原生 DPAPI 凭证加密**：用户密码绝不以明文落盘，直接通过 Windows 系统底层 `CryptProtectData` 与当前用户安全标识符 (SID) 密钥强绑定，换机或拷贝配置文件均无法还原明文。
- 🛑 **账号防锁安全熔断器**：内置智能防爆破与防冻结熔断机制，在网关提示密码错误或服务异常时自动暂停重试，坚决杜绝因盲目重试导致学号被网关锁定。
- 🔄 **开机自启与便携自愈 (Self-Healing)**：
  - 采用“注册表 `HKCU\Run` + 开始菜单启动文件夹”双重保障机制，防止安全杀软误删；
  - 作为单文件绿色软件，用户移动或重命名 exe 后，程序在启动时自动感知并静默纠偏系统启动项路径。
- 🔔 **Windows 系统通知正式接入 (AUMID + 双通道)**：
  - 自动注册 Windows 原生 `AppUserModelId` 身份，规范接入 Windows 10/11 系统“设置 - 系统 - 通知”集中管理面板；
  - 采用 **Win32 托盘原生通知 (`Shell_NotifyIconW`) 优先 + WinRT Toast 兜底** 双通道架构，覆盖登录成功、登录失败、后台重连与下线通知。
- 💓 **无感保活与系统唤醒自愈 (Power Resume)**：
  - 实时监听 Windows 底层网卡变动与网络链路切换；
  - 笔记本休眠唤醒时自动启动**阶梯突发探活序列**（800ms -> 2000ms -> 4000ms），解决 Wi-Fi 重连时延，实现“开盖即联网”。
- 🎨 **极简现代无边框 GUI**：
  - 基于 Windows 内置 WebView2 引擎渲染前端，零内存膨胀（通过 Win32 `SetProcessWorkingSetSize` 定期释放工作集，后台静默内存仅占用数 MB）；
  - 适配 Windows 11 DWM 原生大圆角、暗黑柔和投影与前端任意区域平滑拖拽。
- 👥 **多账号管理与一键自服务**：内置多账号存储与一键平滑切换，支持一键调起校园网自服务门户与网络出口 IP 复制。

---

## 🚀 快速上手

### 方式一：直接下载发布版（推荐）
前往 [GitHub Releases 最新发版页面](https://github.com/unskycel/srun-go/releases) 下载最新的绿色单文件：
- `srun_windows_amd64.exe` (适用于 64 位 Windows 10 / 11)
- `srun_windows_386.exe` (适用于 32 位 Windows 系统)

> [!TIP]
> 本程序为纯绿色便携软件，无需安装。建议将程序放置在固定的日常软件目录（例如 `D:\Software\srun\`），双击即可启动。

### 方式二：首次配置指引
1. **账号密码配置**：双击启动程序，在界面中输入您的校园网账号与密码。
2. **网关与网络检测**：首次启动会自动检测并推荐当前局域网网关（如 `10.200.21.50` 或学校专有认证域名），亦可在“设置向导”中自定义输入。
3. **一键保活与开机自启**：
   - 勾选**【开机自启】**：系统将在开机后自动拉起程序。
   - 勾选**【自动登录】/【断线保活】**：掉线时自动毫秒级重连。

---

## ⚙️ 开机自启与系统通知

### 1. 开机自启与静默运行机制
- **自启参数**：注册表与启动快捷方式中注册了 `--no-auto-open` 参数；
- **启动交互逻辑**：
  - **已配置账号**：开机时程序在后台静默启动至系统托盘，自动检测网络并登录，通过 Windows 系统横幅通知反馈联网状态，**不主动弹出大窗口打扰用户**；
  - **未配置账号**：开机时自动唤起配置窗口，引导用户填写账号信息，防止静默等待。

### 2. Windows 系统通知管理
程序已接入 Windows 官方通知体系（AUMID: `SRun.CampusNetwork`）。
用户可在 Windows **「设置」 -> 「系统」 -> 「通知」** 中找到 **【校园网登录器】**，自由定制横幅弹出、声音提醒以及在操作中心（Action Center）中的显示优先级。

---

## 🏗️ 架构分层设计

遵循标准 Go 工程分层架构设计，各层职责清晰隔离：

```text
srun-go
├── cmd/
│   └── srun/
│       ├── main.go                     # 程序入口与启动参数解析 (--no-auto-open)
│       ├── rsrc_windows_amd64.syso     # 64 位 PE 资源 (嵌入 logo 图标与高 DPI manifest)
│       └── rsrc_windows_386.syso       # 32 位 PE 资源
├── internal/
│   ├── domain/                         # 领域模型层
│   │   ├── event/bus.go                # 全局异步事件总线 (Pub/Sub)
│   │   └── model/config.go             # 核心业务实体与账号模型
│   ├── platform/windows/               # Windows 系统底层集成
│   │   ├── dpapi.go                    # DPAPI 加解密核心实现
│   │   ├── startup.go                  # 注册表与快捷方式自启管理与自愈逻辑
│   │   ├── tray.go                     # 原生 Win32 系统托盘与 Shell_NotifyIconW 通知
│   │   ├── toast.go                    # Windows AUMID 接入与 WinRT Toast 管道
│   │   ├── theme.go                    # 系统亮暗主题探测与监听
│   │   └── mutex.go                    # 单实例互斥锁与现有实例激活
│   ├── protocol/                       # 认证协议层 (纯 Go，跨平台可用)
│   │   ├── codec/                      # xEncode、非标 Base64 (srun_bx1)、HMAC 等算法
│   │   └── srun/                       # Srun 3k/4k 认证客户端 (Challenge 握手与报文解析)
│   ├── service/                        # 业务服务编排层
│   │   ├── auth_service.go             # 登录、注销与系统通知编排
│   │   ├── daemon_service.go           # 守护保活引擎、指数退避重试与睡眠唤醒自愈
│   │   ├── circuit_breaker.go          # 账号防锁安全熔断器
│   │   └── config_service.go           # 配置文件加密存储 (%APPDATA%\srun\config.json)
│   └── ui/                             # 表现层 (GUI)
│       ├── gui.go                      # WebView2 窗口控制器与 DWM 原生美化
│       ├── server.go                   # 轻量本地静态资源 Web Server
│       └── web/                        # 现代化响应式前端 UI (HTML5/CSS3/Vanilla JS)
├── build.bat                           # Windows 本地一键打包发布版脚本
├── srun.manifest                       # Windows 应用程序清单 (高 DPI 感知 + 权限控制)
├── HANDOVER.md                         # 开发者接手与工程架构全景文档
└── tests/                              # 分级测试体系 (Tier 1 ~ Tier 5 对抗性测试)
```

> [!NOTE]
> 更深入的系统时序、密码学细节与底层机制说明，请查阅完整工程文档 [HANDOVER.md](HANDOVER.md)。

---

## 🛠️ 本地开发与编译

### 1. 开发环境要求
- Go 1.24+
- Windows 10 或 Windows 11
- `rsrc` 资源编译器（用于向二进制注入高清图标和清单文件）：
  ```powershell
  go install github.com/akavel/rsrc@latest
  ```

### 2. 运行自动化测试
```powershell
# 运行全部单元测试与对抗性压力测试
go test -v ./...

# 运行平台底层集成测试 (托盘、通知、自启自愈)
go test -v ./internal/platform/windows/...
```

### 3. 本地一键打包发布版
在项目根目录下直接运行 [`build.bat`](build.bat)：
```powershell
.\build.bat
```
脚本将自动执行资源编译并调用 `go build -ldflags="-H windowsgui -s -w"`，在根目录下生成无黑色控制台窗口、内置高清图标的 `srun.exe`。

---

## 🤝 参与贡献与开发规范

1. **分支与提交规范**：严格遵循 [Conventional Commits](https://www.conventionalcommits.org/) 规范（例如 `feat(notification): ...`、`fix(startup): ...`、`docs: ...`）。
2. **安全与隔离**：严禁向源码中硬编码明文凭证或向系统盘写入未受控临时文件。
3. 提交 Pull Request 前请确保 `go test ./...` 全量通过并执行 `build.bat` 验证构建。

---

## 📄 开源许可证

本项目基于 [MIT License](LICENSE) 协议开源，欢迎高校师生与开发者自由使用、学习或定制衍生版本。
