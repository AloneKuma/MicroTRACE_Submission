#!/usr/bin/env python3
"""Echo server: returns the received workload headers and the kernel-reported TCP peer."""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

KEEP = ("traceparent", "x-request-id", "x-forwarded-for")


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"headers": {k.lower(): v for k, v in self.headers.items() if k.lower() in KEEP},
                           "tcp_peer": self.client_address[0]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


HTTPServer(("0.0.0.0", 8080), H).serve_forever()
