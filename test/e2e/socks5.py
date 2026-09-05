#!/usr/bin/env python3

import os
import select
import socket
import struct
import threading
import time


LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "1080"))
CONNECT_DELAY = float(os.environ.get("CONNECT_DELAY_MS", "0")) / 1000
NODE_NAME = os.environ.get("NODE_NAME", "socks5")


def read_exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected EOF")
        data += chunk
    return data


def relay(client, upstream):
    sockets = [client, upstream]
    while True:
        readable, _, _ = select.select(sockets, [], [], 30)
        for source in readable:
            data = source.recv(65536)
            if not data:
                return
            destination = upstream if source is client else client
            destination.sendall(data)


def handle(client, peer):
    upstream = None
    try:
        version, method_count = read_exact(client, 2)
        if version != 5:
            raise ValueError("only SOCKS5 is supported")
        read_exact(client, method_count)
        client.sendall(b"\x05\x00")

        version, command, _, address_type = read_exact(client, 4)
        if version != 5 or command != 1:
            raise ValueError("only SOCKS5 CONNECT is supported")
        if address_type == 1:
            host = socket.inet_ntoa(read_exact(client, 4))
        elif address_type == 3:
            host = read_exact(client, read_exact(client, 1)[0]).decode()
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, read_exact(client, 16))
        else:
            raise ValueError("unsupported address type")
        port = struct.unpack("!H", read_exact(client, 2))[0]

        time.sleep(CONNECT_DELAY)
        upstream = socket.create_connection((host, port), timeout=10)
        upstream.settimeout(None)
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        print(f"{NODE_NAME} CONNECT {host}:{port}", flush=True)
        relay(client, upstream)
    except Exception as exc:
        try:
            client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        except OSError:
            pass
        print(f"{NODE_NAME} ERROR peer={peer} error={exc}", flush=True)
    finally:
        if upstream is not None:
            upstream.close()
        client.close()


def main():
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    server.bind(("::", LISTEN_PORT))
    server.listen(128)
    print(f"{NODE_NAME} LISTEN [::]:{LISTEN_PORT} delay={CONNECT_DELAY}s", flush=True)
    while True:
        client, peer = server.accept()
        threading.Thread(target=handle, args=(client, peer), daemon=True).start()


if __name__ == "__main__":
    main()
