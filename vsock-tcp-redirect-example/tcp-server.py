import socket
import sys
import time

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python tcp-server.py <ip_addr> <port_num>")
        exit()

    addr, port = sys.argv[1], int(sys.argv[2])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((addr, port))
    s.listen(32)

    conn, addr = s.accept()
    while True:
        conn.send(b"Hi from TCP server")
        reply = conn.recv(1024)
        print(reply.decode())
        print("Sleep 1 second")
        time.sleep(1)
