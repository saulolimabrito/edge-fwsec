"""Send and capture UDP datagrams in the disposable policy topology."""

import select
import socket
import sys
import time
from pathlib import Path


def receive(ready_path):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ipv4, socket.socket(
        socket.AF_INET6, socket.SOCK_DGRAM
    ) as ipv6:
        ipv6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        ipv4.bind(("0.0.0.0", 68))
        ipv6.bind(("::", 546))
        Path(ready_path).touch()
        deadline = time.monotonic() + 5
        while (remaining := deadline - time.monotonic()) > 0:
            readers, _, _ = select.select([ipv4, ipv6], [], [], remaining)
            for reader in readers:
                payload, _ = reader.recvfrom(256)
                print(payload.decode("ascii"))


def send(family, source, source_port, target, target_port, label):
    af = socket.AF_INET6 if family == "ipv6" else socket.AF_INET
    with socket.socket(af, socket.SOCK_DGRAM) as udp:
        if af == socket.AF_INET:
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        local = socket.getaddrinfo(source, source_port, af, socket.SOCK_DGRAM)
        peer = socket.getaddrinfo(target, target_port, af, socket.SOCK_DGRAM)
        udp.bind(local[0][4])
        udp.sendto(label.encode("ascii"), peer[0][4])


if sys.argv[1] == "receive":
    receive(sys.argv[2])
else:
    send(*sys.argv[2:])
