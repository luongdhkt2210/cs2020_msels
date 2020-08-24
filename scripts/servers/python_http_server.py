#!/usr/bin/python
from SimpleHTTPServer import SimpleHTTPRequestHandler
import requests, SocketServer, ssl
from pwn import *
from sys import argv

# openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
context.log_level = 'info'


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, req, client_addr, server):
        self.payload = server.payload
        SimpleHTTPRequestHandler.__init__(self, req, client_addr, server)

    def do_GET(self):
        log.debug('received connection')
        response = open(self.payload, 'rb').read()
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-length", len(response))
        self.end_headers()
        self.wfile.write(response)

    def do_POST(self):
        log.debug('received connection')
        response = open(self.payload, 'rb').read()
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.send_header("Content-length", len(response))
        self.end_headers()
        self.wfile.write(response)


class Server(SocketServer.TCPServer):
    def __init__(self, payload, ip_address='0.0.0.0', port=80):
        self.payload = payload
        SocketServer.TCPServer.__init__(self, (ip_address, port), Handler)
        if port == 443:
            self.socket = ssl.wrap_socket(self.socket, certfile='./server.pem', server_side=True)

    def start_limited(self):
        self.handle_request()
        return self

    def start(self):
        self.serve_forever()
        return self


if __name__ == '__main__':
    payload = argv[1]
    server = Server(payload=payload)
    server.start_limited()
