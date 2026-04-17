"""
TCP connect test — replacement for `nc` (unreliable in E2B sandboxes).

Usage: python3 tcp-connect.py <host> <port>
Connects, reads first bytes, prints them, exits.
"""
import socket, sys

host = sys.argv[1]
port = int(sys.argv[2])

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect((host, port))
    data = s.recv(1024)
    s.close()
    print(data.decode("utf-8", errors="replace"))
except Exception as e:
    print(f"ERR:{e}")
