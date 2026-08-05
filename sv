#!/usr/bin/env python3
from pwn import *; import sys; import os; import select

args = sys.argv
if "-u" in args or len(args) > 1:
    if "-u" in args:
        start = args.index("-u")+1
    elif "-u" not in args:
        start = 1
    serv = args = sys.argv[start:]
    with open("/home/kali/remote/picoCTF", "w") as f:
        f.write("\n".join(serv))
    
with open("/home/kali/remote/picoCTF", "r") as o:
    input = o.read().splitlines()
HOST = input[0]
PORT = int(input[1])
try:
    io = remote(HOST, PORT)
except Exception as e:
    print("\nFailed to connect\nCheck if host is reachable")
    sys.exit(1)

if not sys.stdin.isatty():
    io.send(sys.stdin.buffer.read())

    sys.stdin = open("/dev/tty")

sock = io.sock

while True:
    readable, _, _ = select.select([sock, sys.stdin], [], [])

    if sock in readable:
        data = sock.recv(4096)
        if not data:
            break
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()

    if sys.stdin in readable:
        data = sys.stdin.buffer.readline()
        if not data:
            continue
        sock.sendall(data)

io.close()