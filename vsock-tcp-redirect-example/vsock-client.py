import socket
import sys
import time

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tcp-server.py <port_num>")
        exit()

    port = int(sys.argv[1])
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.connect((socket.VMADDR_CID_HOST, port))

    while True:
        msg = s.recv(1024)
        print(msg.decode())
        s.send(b"Hi from VSOCK client")
        print("Sleep 1 second")
        time.sleep(1)
