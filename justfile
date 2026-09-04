# srun-go 自动化工程任务定义 (justfile)
# 在终端直接输入 `just` 即可查看所有可用任务

# 默认列出所有任务
default:
    @just --list

# 一键编译 Windows 生产版 (自动嵌入 logo 图标与清单，无黑框控制台)
build:
    .\build.bat

# 运行全量单元测试与回归测试
test:
    go test -v ./...

# 仅运行平台无关的核心协议与加密算法测试
test-protocol:
    go test -v ./internal/protocol/...

# 代码静态质量检测 (go vet)
check:
    go vet ./...

# 清理本地编译产物与临时文件
clean:
    powershell -Command "Remove-Item srun.exe, test_build, build_out -Recurse -Force -ErrorAction SilentlyContinue; Write-Host 'Build artifacts cleaned!'"

# 一键发版 (使用方法: just release v1.0.2)
release version:
    git tag -a {{version}} -m "Release {{version}}"
    git push origin {{version}}
    @echo "Tag {{version}} pushed! GitHub Actions is building and publishing the release..."

# 在浏览器中快速打开 GitHub 仓库
repo:
    gh repo view --web
