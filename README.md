# computer-pipe

跨 Windows、Linux、macOS 的单二进制电脑管道。公网服务器运行 `relay`，目标电脑运行 `agent`，控制端可以使用 `client`，也可以完全不安装任何东西，直接通过局域网 HTTP API 调用。

## 公网 relay

使用非默认端口部署，例如 relay 用 `17600`，HTTPS 部署网页和下载用 `17601`：

```bash
./pipe-linux-amd64 relay \
  --listen :17600 \
  --web-listen :17601 \
  --web-root ./web \
  --token 'PIPE_TOKEN'
```

浏览器打开 `https://服务器地址:17601/`，页面只需要选择“外网 relay”或“内网直连”，再填写设备名称。relay 地址、HTTPS 下载地址、当前 token 和局域网 API 端口都由服务器自动填入。页面同时提供 Windows PowerShell、Linux/macOS 两套命令。

公网管理台位于 `/manage`。登录后可以查看在线设备卡片、设备级 Token、服务器调用地址、保存备注、打开部署页、修改密码和发送卸载下线操作。管理台使用侧边菜单切换概览、设备管理、接口文档、部署中心和安全设置。

服务器管理 API 只需要一个服务器 API Token，请求头统一写一次：

```text
Authorization: Bearer SERVER_API_TOKEN
```

接口帮助：

```bash
curl -H 'Authorization: Bearer SERVER_API_TOKEN' \
  https://服务器地址:17601/manage/api/help
```

查看已经接入的设备。返回内容包含 `name`、`online`、`hostname`、`os`、`arch`、`note`、设备级 `token` 和服务器转发用的 `api_base`：

```bash
curl -H 'Authorization: Bearer SERVER_API_TOKEN' \
  https://服务器地址:17601/manage/api/devices
```

以设备名 `B` 为例，设备调用地址为：

```text
https://服务器地址:17601/manage/api/devices/B
```

设备转发接口继续使用同一个服务器 API Token，不需要再传设备 Token：

```bash
curl -H 'Authorization: Bearer SERVER_API_TOKEN' \
  https://服务器地址:17601/manage/api/devices/B/health

curl -X POST \
  -H 'Authorization: Bearer SERVER_API_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"command":"hostname","timeout":30}' \
  https://服务器地址:17601/manage/api/devices/B/command

curl -o screen.png \
  -H 'Authorization: Bearer SERVER_API_TOKEN' \
  https://服务器地址:17601/manage/api/devices/B/snapshot
```

`POST /manage/api/device-token` 可以为设备名生成新的设备级 Token。部署页会自动调用这个接口，把新 Token 填入一键部署命令。

给 relay 配置证书后，17600 的 relay 连接和 17601 的页面/二进制下载都会使用 HTTPS/TLS：

```bash
./pipe-linux-amd64 relay --listen :17600 --web-listen :17601 --web-root ./web \
  --token 'PIPE_TOKEN' --cert server.crt --key server.key
```

然后 agent/client 加 `--tls`。如果是自签证书，再加 `--insecure`，或在网页中勾选“自签证书跳过校验”。

## 一键部署 agent

网页生成的 Linux/macOS 命令类似：

```bash
curl -kfsSL 'https://服务器地址:17601/install.sh' | \
  PIPE_DOWNLOAD_BASE='https://服务器地址:17601' \
  PIPE_MODE='relay' PIPE_RELAY='服务器地址:17600' \
  PIPE_NAME='B' PIPE_TOKEN='DEVICE_TOKEN' PIPE_TLS='1' PIPE_INSECURE='1' \
  PIPE_LISTEN='0.0.0.0:17602' sh
```

Windows PowerShell 命令类似：

```powershell
$env:PIPE_DOWNLOAD_BASE='https://服务器地址:17601';$env:PIPE_MODE='relay';$env:PIPE_RELAY='服务器地址:17600';$env:PIPE_NAME='B';$env:PIPE_TOKEN='DEVICE_TOKEN';$env:PIPE_TLS='1';$env:PIPE_INSECURE='1';$env:PIPE_LISTEN='0.0.0.0:17602';iex (irm 'https://服务器地址:17601/install.ps1')
```

安装脚本会自动识别系统和 CPU 架构，下载对应二进制，写入用户目录并启动 agent。已有进程会先停止再启动；日志位置会在安装输出中显示。

agent 会在 relay 连接断开后自动重连。连接使用 TCP keepalive，电脑短暂断网恢复后会重新建立设备在线状态。已有设备需要重新执行一次部署命令以获得这个版本的 agent。

Windows 安装时如果旧 agent 由管理员权限运行，脚本会弹出一次 UAC 请求来停止旧进程，然后继续更新。

如果不使用公网 relay，也可以直接启动目标机的局域网 API：

```powershell
.\computer-pipe.exe agent --direct --token PIPE_TOKEN --listen 0.0.0.0:17602
```

已有 frps 的高级模式仍可直接使用命令行：

```powershell
.\computer-pipe.exe agent --frps-addr frps.example.com:7000 --frps-token FRPS_TOKEN --frps-remote-port 16000 --name B --token PIPE_TOKEN --listen 0.0.0.0:17602
```

安装脚本会自动下载对应系统和架构的 frpc（默认 v0.72.0），生成临时配置并启动；可用 `PIPE_FRP_VERSION` 指定版本，或用 `PIPE_FRPC_PATH` 指定已有的 frpc。官方发行版来自 [fatedier/frp Releases](https://github.com/fatedier/frp/releases)。

## 局域网直连 API

agent 启动时加 `--listen 0.0.0.0:17602`，控制端只需要 HTTP 工具：

浏览器打开 `http://目标IP:17602/` 可以查看完整接口说明，`/api/v1/help` 返回机器可读的 JSON 帮助。

```bash
curl -H 'Authorization: Bearer LAN_TOKEN' \
  http://192.168.1.20:17602/api/v1/health

curl -X POST -H 'Authorization: Bearer LAN_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"command":"git status","cwd":"/workspace","timeout":120}' \
  http://192.168.1.20:17602/api/v1/command

curl -o screen.png -H 'Authorization: Bearer LAN_TOKEN' \
  http://192.168.1.20:17602/api/v1/snapshot

curl -H 'Authorization: Bearer LAN_TOKEN' \
  http://192.168.1.20:17602/api/v1/clipboard

curl -X POST -H 'Authorization: Bearer LAN_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"action":"key","key":"c","modifiers":["ctrl"]}' \
  http://192.168.1.20:17602/api/v1/input
```

帮助接口：

```bash
curl -H 'Authorization: Bearer LAN_TOKEN' http://192.168.1.20:17602/api/v1/help
```

支持的接口：

| 方法 | 路径 | 作用 |
| --- | --- | --- |
| GET | `/api/v1/health` | 主机信息和连通性 |
| POST | `/api/v1/command` | 执行命令，JSON 字段 `command/cwd/timeout` |
| GET | `/api/v1/snapshot` | 返回 PNG 主屏截图 |
| GET/POST | `/api/v1/clipboard` | 读写文本剪切板，写入字段 `text` |
| POST | `/api/v1/input` | `move/click/scroll/key/text` 键鼠操作 |
| GET | `/api/v1/help` | 返回接口帮助 |

请求头可以使用 `Authorization: Bearer TOKEN` 或 `X-Pipe-Token: TOKEN`。所有错误直接返回 JSON，便于脚本和 AI 工具定位问题。

## 本地构建

```powershell
$env:CGO_ENABLED="0"; $env:GOOS="windows"; $env:GOARCH="amd64"; go build -trimpath -ldflags="-s -w" -o web/pipe-windows-amd64.exe .
$env:CGO_ENABLED="0"; $env:GOOS="windows"; $env:GOARCH="arm64"; go build -trimpath -ldflags="-s -w" -o web/pipe-windows-arm64.exe .
$env:CGO_ENABLED="0"; $env:GOOS="linux"; $env:GOARCH="amd64"; go build -trimpath -ldflags="-s -w" -o web/pipe-linux-amd64 .
$env:CGO_ENABLED="0"; $env:GOOS="linux"; $env:GOARCH="arm64"; go build -trimpath -ldflags="-s -w" -o web/pipe-linux-arm64 .
$env:CGO_ENABLED="0"; $env:GOOS="darwin"; $env:GOARCH="amd64"; go build -trimpath -ldflags="-s -w" -o web/pipe-darwin-amd64 .
$env:CGO_ENABLED="0"; $env:GOOS="darwin"; $env:GOARCH="arm64"; go build -trimpath -ldflags="-s -w" -o web/pipe-darwin-arm64 .
```

Windows 截图和键鼠使用 PowerShell/Win32；macOS 截图使用 `screencapture`；Linux 截图需要 `gnome-screenshot` 或 `scrot`，键鼠需要 `xdotool`。macOS 需要在系统设置中允许屏幕录制和辅助功能。
