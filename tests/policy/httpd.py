"""Dual-stack test HTTP server that logs client addresses.

Unlike `python3 -m http.server`, it never calls socket.getfqdn(), which
stalls in namespaces without a reachable DNS resolver.
usage: python3 httpd.py <port> <directory>
"""
import functools
import http.server
import socket
import socketserver
import sys


class DualStack(http.server.ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self):
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        socketserver.TCPServer.server_bind(self)  # skip HTTPServer's getfqdn()
        self.server_name, self.server_port = "efw-test", self.server_address[1]


port, root = int(sys.argv[1]), sys.argv[2]
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=root)
with DualStack(("::", port), handler) as srv:
    srv.serve_forever()
