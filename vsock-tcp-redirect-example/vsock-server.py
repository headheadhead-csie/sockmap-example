import socket
import sys
import time

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tcp-server.py <port_num>")
        exit()

    port = int(sys.argv[1])
    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    s.bind((socket.VMADDR_CID_HOST, port))
    s.listen(32)

    (conn, (client_cid, client_port)) = s.accept()
    while True:
        conn.send(b"Hi from VSOCK server")
        reply = conn.recv(1024)
        print(reply.decode())
        print("Sleep 1 second")
        time.sleep(1)
