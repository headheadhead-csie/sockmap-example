import socket
import sys
import time

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python tcp-client.py <ip_addr> <port_num>")

    addr, port = sys.argv[1], int(sys.argv[2])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((addr, port))

    while True:
        msg = s.recv(1024)
        print(msg.decode())
        s.send(b"Hi from TCP client")
        print("Sleep 1 second")
        time.sleep(1)
