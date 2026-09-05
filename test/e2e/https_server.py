#!/usr/bin/env python3

import http.server
import os
import ssl


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"dae isolated e2e ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"target {self.client_address[0]} {fmt % args}", flush=True)


server = http.server.ThreadingHTTPServer(("0.0.0.0", 443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(os.environ["CERT_FILE"], os.environ["KEY_FILE"])
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
