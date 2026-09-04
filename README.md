# srun-go 🐹

<div align="center">

**高性能现代化校园网 (Srun 3k/4k) 自动化认证与保活守护客户端**

[![Go Version](https://img.shields.io/github/go-mod/go-version/unskycel/srun-go?style=flat-square&logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![CI Status](https://img.shields.io/github/actions/workflow/status/unskycel/srun-go/ci.yml?branch=main&style=flat-square&logo=githubactions&label=CI)](https://github.com/unskycel/srun-go/actions)
[![Latest Release](https://img.shields.io/github/v/release/unskycel/srun-go?style=flat-square&logo=github)](https://github.com/unskycel/srun-go/releases)

</div>

---

## 🌟 核心特性

- ⚡ **毫秒级极速认证**：基于 Go 语言原生协程与轻量 HTTP 客户端，极致并发挑战握手。
- 🛡️ **工业级凭证安全**：采用 Windows 原生 **DPAPI (Data Protection API)** 加密保存用户密码，彻底杜绝明文凭据外泄。
- 💓 **智能心跳保活守护**：自适应探测校园网网关状态，断网毫秒级无感重连，告别频繁手动登录。
- 🖥️ **现代化混合架构 GUI**：基于内置 WebView2 渲染极简设计 UI，搭配原生 Windows 系统托盘静默常驻。
- 📦 **单文件绿色无依赖**：静态打包为独立 `srun.exe`，免安装、零第三方运行时依赖。

---

## 🏗️ 架构分层设计

```text
srun-go
├── cmd/               # 应用程序入口 (CLI / GUI 启动引导)
├── internal/
│   ├── domain/        # 核心领域实体 (配置模型、会话、事件总线)
│   ├── platform/      # Windows 原生集成 (DPAPI 加密、托盘、Toast 通知、自启管理)
│   ├── protocol/      # Srun 认证协议实现 (Challenge 算法、xEncode 加密、报文收发)
│   ├── service/       # 业务调度服务 (登录认证、断网探活、守护进程、熔断器)
│   └── ui/            # 前端 Web 资源与 Go-Webview 跨端通信桥梁
└── tests/             # 单元测试与端到端回归验证
```

---

## 🚀 极速构建与运行

### 1. 环境准备
- Go SDK 1.24+
- Windows 10/11（内置 WebView2 运行时）

### 2. 本地快速构建
```powershell
# 克隆仓库
git clone git@github.com:unskycel/srun-go.git
cd srun-go

# 运行自动化构建脚本 (嵌入资源与无控制台打包)
.\build.bat
```

构建成功后将在根目录生成 `srun.exe`，直接双击即可运行。

---

## 🤝 参与贡献

欢迎提交 Issue 与 Pull Request 共同改进本项目！在提交 PR 前请确保：
1. 遵循项目的 Conventional Commits 提交规范（如 `feat:`, `fix:`）；
2. 运行本地测试并通过检验：`go test -v ./...`。

---

## 📄 开源许可证

本项目遵循 [MIT License](LICENSE) 开源协议。
