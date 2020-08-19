#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Fake FTP Server
~~~~~~~~~~~~~~~

This is a simple fake FTP daemon.  It stores the login data (username and
password) given to it and then terminates the connection.

It was made to easily recover forgotten passwords which are still stored (but
scrambled) by an FTP client without the need for using a sniffer tool.

Beware: Although the script reacts on ``<Ctrl-C>``, it won't exit until
another connect has happened because ``socket.accept()`` is blocking.  Also,
due to the use of threads, it may take some time until the port will be
available again.

Some useful resources for implementing this were the IETF's `RFC 959`_ and the
`FTP reference`_ by D. J. Bernstein.

.. _RFC 959:        http://tools.ietf.org/rfc/rfc959.txt
.. _FTP reference:  http://cr.yp.to/ftp.html

:Copyright: 2007 Jochen Kupperschmidt
:Date: 13-Jul-2007
:License: MIT
"""

from datetime import datetime
from optparse import OptionParser
from SocketServer import BaseRequestHandler, ThreadingTCPServer
from sys import stdout


class FTPLoginHandler(BaseRequestHandler):
    """Handler for FTP authentication."""

    def debug(self, message):
        """Show log message."""
        if self.server.debug:
            print '***', message

    def respond(self, code, explanation):
        """Send a response to the client."""
        self.request.send('%d %s\r\n' % (code, explanation))

    def process_request(self):
        """Parse input into a command and an argument."""
        data = self.request.recv(64)
        parts = data.strip().split(' ')
        return parts.pop(0), parts

    def log_auth(self, user, password):
        """Write username and password to logfile."""
        now = datetime.now().isoformat(' ')[:19]
        client = '%s:%d' % self.client_address
        line = ' '.join((now, client, user, password))
        self.server.logfile.write(line + '\n')
        self.server.logfile.flush()

    def handle(self):
        """Handle incoming data."""
        self.debug('Connection from %s:%d.' % self.client_address)
        self.respond(220, self.server.banner)
        user = None
        while True:
            cmd, args = self.process_request()
            if cmd == 'USER':
                if user is not None:
                    self.respond(503, 'Incorrect sequence of'
                        ' commands: PASS required after USER.')
                    continue
                user = (args and args[0] or '*missing*')
                self.debug('User "%s" has identified.' % user)
                self.respond(331, 'Please specify the password.')
                continue
            elif cmd == 'PASS':
                if user is None:
                    self.respond(503, 'Incorrect sequence of'
                        ' commands: USER required before PASS.')
                    continue
                password = (args and args[0] or '*missing*')
                self.debug('User "%s" supplied password "%s", storing.'
                    % (user, password))
                self.log_auth(user, password)
                self.respond(530, 'Login incorrect.')
                break
            else:
                self.debug('Rejecting request "%s".' % ' '.join(args))
                self.respond(530, 'Please login with USER and PASS.')
                break
        self.request.close()
        self.debug('Connection with %s:%d closed.' % self.client_address)


class FTPLoginServer(ThreadingTCPServer):

    def __init__(self, host='', port=21, banner='', debug=False, logfile=None,
            append=False):
        ThreadingTCPServer.__init__(self, (host, port), FTPLoginHandler)
        self.banner = banner
        self.debug = debug
        mode = (append and 'a' or 'w')
        self.logfile = (logfile and open(logfile, mode) or stdout)

    def server_close(self):
        ThreadingTCPServer.server_close(self)
        self.logfile.close()


if __name__ == '__main__':
    parser = OptionParser(usage='%prog [options] <port>')
    parser.add_option('-a', '--append', dest='append', action='store_true',
        help='append to LOGFILE ')
    parser.add_option('-b', '--banner', dest='banner',
        help='custom banner string')
    parser.add_option('-d', '--debug', dest='debug', action='store_true',
        help='show debugging messages')
    parser.add_option('-l', '--logfile', dest='logfile',
        help='write collected user/password data to LOGFILE')
    opts, args = parser.parse_args()

    # Parse arguments.
    if len(args) != 1:
        parser.print_help()
        parser.exit()
    try:
        port = int(args[0])
    except ValueError:
        parser.print_help()
        parser.exit()

    # Serve.
    server = FTPLoginServer(port=port, **opts.__dict__)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print 'Ctrl-C pressed, exiting...'
    server.server_close()