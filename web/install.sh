#!/bin/sh
set -eu

: "${PIPE_DOWNLOAD_BASE:?PIPE_DOWNLOAD_BASE is required}"
: "${PIPE_NAME:?PIPE_NAME is required}"
: "${PIPE_TOKEN:?PIPE_TOKEN is required}"

base=${PIPE_DOWNLOAD_BASE%/}
os=$(uname -s)
arch=$(uname -m)
case "$os:$arch" in
  Linux:x86_64|Linux:amd64) asset=pipe-linux-amd64 ;;
  Linux:aarch64|Linux:arm64) asset=pipe-linux-arm64 ;;
  Darwin:x86_64|Darwin:amd64) asset=pipe-darwin-amd64 ;;
  Darwin:arm64) asset=pipe-darwin-arm64 ;;
  *) echo "unsupported platform: $os $arch" >&2; exit 1 ;;
esac

bin_dir=${PIPE_INSTALL_DIR:-"$HOME/.local/bin"}
state_dir=${PIPE_STATE_DIR:-"$HOME/.config/computer-pipe"}
mkdir -p "$bin_dir" "$state_dir"
tmp="$state_dir/computer-pipe.download.$$"
trap 'rm -f "$tmp"' EXIT INT TERM
curl_flags=-fsSL
if [ "${PIPE_INSECURE:-0}" = "1" ]; then curl_flags=-kfsSL; fi
if command -v curl >/dev/null 2>&1; then
  curl "$curl_flags" "$base/$asset" -o "$tmp"
elif command -v wget >/dev/null 2>&1; then
  wget -qO "$tmp" "$base/$asset"
else
  echo "curl or wget is required" >&2
  exit 1
fi
install -m 0755 "$tmp" "$bin_dir/computer-pipe"

set -- agent --name "$PIPE_NAME" --token "$PIPE_TOKEN"
if [ "${PIPE_MODE:-relay}" = "direct" ] || [ "${PIPE_MODE:-relay}" = "lan" ]; then
  set -- agent --direct --token "$PIPE_TOKEN"
elif [ "${PIPE_MODE:-relay}" = "frps" ]; then
  : "${PIPE_FRPS_ADDR:?PIPE_FRPS_ADDR is required in frps mode}"
  : "${PIPE_FRPS_TOKEN:?PIPE_FRPS_TOKEN is required in frps mode}"
  : "${PIPE_FRPS_REMOTE_PORT:?PIPE_FRPS_REMOTE_PORT is required in frps mode}"
  set -- "$@" --frps-addr "$PIPE_FRPS_ADDR" --frps-token "$PIPE_FRPS_TOKEN" --frps-remote-port "$PIPE_FRPS_REMOTE_PORT"
  frp_version=${PIPE_FRP_VERSION:-0.72.0}
  frp_dir="$state_dir/frp-$frp_version"
  frpc_path=${PIPE_FRPC_PATH:-"$frp_dir/frpc"}
  if [ ! -x "$frpc_path" ]; then
    mkdir -p "$frp_dir"
    frp_tmp="$state_dir/frp.download.$$"
    trap 'rm -f "$tmp" "$frp_tmp"' EXIT INT TERM
    case "$os:$arch" in
      Linux:x86_64|Linux:amd64) frp_os=linux; frp_arch=amd64 ;;
      Linux:aarch64|Linux:arm64) frp_os=linux; frp_arch=arm64 ;;
      Darwin:x86_64|Darwin:amd64) frp_os=darwin; frp_arch=amd64 ;;
      Darwin:arm64) frp_os=darwin; frp_arch=arm64 ;;
      *) echo "unsupported frpc platform: $os $arch" >&2; exit 1 ;;
    esac
    frp_url=${PIPE_FRPC_BASE:-"https://github.com/fatedier/frp/releases/download/v$frp_version"}/frp_${frp_version}_${frp_os}_${frp_arch}.tar.gz
    if command -v curl >/dev/null 2>&1; then curl "$curl_flags" "$frp_url" -o "$frp_tmp"; else wget -qO "$frp_tmp" "$frp_url"; fi
    tar -xzf "$frp_tmp" -C "$frp_dir" --strip-components=1
    chmod 0755 "$frp_dir/frpc"
    frpc_path="$frp_dir/frpc"
  fi
  set -- "$@" --frpc "$frpc_path"
else
  : "${PIPE_RELAY:?PIPE_RELAY is required in relay mode}"
  set -- "$@" --relay "$PIPE_RELAY"
fi
if [ -n "${PIPE_LISTEN:-}" ]; then set -- "$@" --listen "$PIPE_LISTEN"; fi
if [ "${PIPE_TLS:-0}" = "1" ]; then set -- "$@" --tls; fi
if [ "${PIPE_INSECURE:-0}" = "1" ]; then set -- "$@" --insecure; fi
if [ -n "${PIPE_FRPC_PATH:-}" ]; then set -- "$@" --frpc "$PIPE_FRPC_PATH"; fi

pid_file="$state_dir/agent.pid"
log_file="$state_dir/agent.log"
if [ -f "$pid_file" ]; then
  old_pid=$(cat "$pid_file" 2>/dev/null || true)
  if [ -n "$old_pid" ]; then kill "$old_pid" 2>/dev/null || true; fi
fi
# Arguments are passed as individual values so names and credentials with spaces remain intact.
nohup "$bin_dir/computer-pipe" "$@" >"$log_file" 2>&1 &
echo $! >"$pid_file"
echo "computer-pipe installed: $bin_dir/computer-pipe"
echo "agent started, pid $(cat "$pid_file")"
echo "local API: ${PIPE_LISTEN:-disabled}"
