#!/usr/bin/env python2
#-*- coding:utf-8 -*-

### LICENCE ###
# This file is part of DNScapy.
# DNScapy is a free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# DNScapy is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details: <http://www.gnu.org/licenses/>

### ABOUT DNScapy ###
# DNScapy creates a SSH tunnel through DNS packets
# SSH connection, SCP and proxy socks (SSH -D) are supported
# See http://code.google.com/p/dnscapy/ for more informations
# Copyright (C) Pierre Bienaimé <pbienaim@gmail.com>
#               and Pascal Mazon <pascal.mazon@gmail.com>
# DNScapy uses Scapy, wrote by Philippe Biondi <phil@secdev.org>

### DISCLAIMER ###
# We are not responsible for misuse of DNScapy
# Making a DNS tunnel to bypass a security policy may be forbidden
# Do it at your own risks

from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, Raw, send, Automaton, ATMT, StreamSocket, log_interactive #, txtfy
from random import randint
from threading import Thread
from optparse import OptionParser
from base64 import b64encode, b64decode
import socket, sys

CNAME = 5
TXT = 16  

_CON = "a"
_ACK = "b"
_IWT = "c"
_DATA = "d"
_DONE = "e"
_FAST = "f"

class Core(Automaton):
    dn = "" 
    def parse_qname(self, pkt):
        return pkt[DNSQR].qname.rsplit(self.dn, 1)[0].split(".")
        
    def master_filter(self, pkt):
        return ((self.state.state == "WAITING" or
                self.state.state == "DATA_RECEPTION") and
                IP in pkt and UDP in pkt and
                pkt[UDP].dport == 53 and DNS in pkt and
                pkt[DNS].qr == 0 and DNSQR in pkt and
                pkt[DNSQR].qname.endswith(self.dn + "."))

    def forge_packet(self, pkt, rdata="", rcode=0):
        d = pkt[IP].src 
        dp = pkt[UDP].sport
        id = pkt[DNS].id
        q = pkt[DNS].qd    
        t = pkt[DNSQR].qtype
        if t == TXT:
            # if scapy is patched:
            # rdata = txtfy(rdata) 
            for i in range(0, len(rdata), 0xff+1):
                rdata = rdata[:i] + chr(len(rdata[i:i+0xff])) + rdata[i:]   
        an = (None, DNSRR(rrname=self.dn, type=t, rdata=rdata, ttl=60))[rcode == 0]        
        ns = DNSRR(rrname=self.dn, type="NS", ttl=3600, rdata="ns."+self.dn)
        return IP(dst=d)/UDP(dport=dp)/DNS(id=id, qr=1, rd=1, ra=1, rcode=rcode, qd=q, an=an, ns=ns)


class Parent(Core):
    def parse_args(self, dn, ext_ip, debug=0, nb_clients=10, ssh_p=22):
        self.dn = dn
        self.ext_ip = ext_ip
        self.dbg = debug
        self.nb_clients = nb_clients
        self.ssh_p = ssh_p
        bpf = "udp port 53"
        Automaton.parse_args(self, filter=bpf, debug=debug)
     
    def master_filter(self, pkt):
        if Core.master_filter(self, pkt) and pkt[IP].src != self.ext_ip:
            self.qname = Core.parse_qname(self, pkt)                     
            return len(self.qname) >= 2
        else:
            return False
            
    def get_identifier(self):
        if len(self.empty_slots) >= 1:
            return self.empty_slots.pop()
        elif self.kill_children() >= 1:
            return self.empty_slots.pop()
        else:
            return None
            
    def kill_children(self):
        for k in self.childs.keys():
            if self.childs[k].state.state == "END":
                self.childs[k].stop()
                del(self.childs[k])
                self.empty_slots.add(k)
        return len(self.empty_slots)

    @ATMT.state(initial=True)
    def START(self):
        self.childs = {}
        self.empty_slots = set(range(1, self.nb_clients+1))
        raise self.WAITING()

    @ATMT.state()
    def WAITING(self):
        pass

    @ATMT.receive_condition(WAITING)
    def true_dns_request(self, pkt):
        if not self.qname[-2].isdigit():
            qtype = pkt[DNSQR].sprintf("%qtype%")
            raise self.WAITING().action_parameters(pkt, qtype)

    @ATMT.action(true_dns_request)
    def true_dns_reply(self, pkt, qtype):
        if qtype == "A":
            reply = Core.forge_packet(self, pkt, rdata=self.ext_ip)
        elif qtype == "SOA":
            reply = Core.forge_packet(self, pkt, rdata="ns.{0} root.{0} {1} 28800 14400 3600000 0".format(self.dn, randint(1, 65535)))
        elif qtype == "NS":
            reply = Core.forge_packet(self, pkt, rdata="ns."+self.dn)
        elif qtype == "MX":
            reply = Core.forge_packet(self, pkt, rdata="mail."+self.dn)
        elif qtype == "CNAME" or qtype == "TXT":
            reply = Core.forge_packet(self, pkt, rcode=3) 
        elif qtype == "AAAA" or qtype == "NULL":
            reply = Core.forge_packet(self, pkt, rcode=4)
        else:
            reply = Core.forge_packet(self, pkt, rcode=2)
        send(reply, verbose=0)

    @ATMT.receive_condition(WAITING)
    def connection_request(self, pkt):
        if len(self.qname) >=3 and self.qname[-3] == _CON:
            raise self.WAITING().action_parameters(pkt)

    @ATMT.action(connection_request)
    def childbirth(self, pkt):
        i = self.get_identifier()
        if i is not None:
            thread = Child(self.dn, i, pkt, self.dbg, self.ssh_p)
            self.childs[i] = thread
            thread.runbg()


class Child(Core):
    def parse_args(self, dn, con_id, first_pkt, dbg=0, ssh_p=22):
        self.dn = dn
        self.con_id = str(con_id)
        self.first_pkt = first_pkt
        self.ssh_p = ssh_p
        Automaton.parse_args(self, debug=dbg)

    def master_filter(self, pkt):        
        if (Core.master_filter(self, pkt) and pkt[IP].src == self.ip_client):
            qname = Core.parse_qname(self, pkt)    
            if len(qname) >= 4:
                if qname[-2].isdigit() and qname[-3] == self.con_id:
                    self.msg_type = qname[-4]
                    if len(qname) == 4 and self.msg_type in [_IWT]:
                        return True
                    if len(qname) > 4 and self.msg_type in [_ACK, _DATA, _FAST, _DONE]:
                        self.arg = qname[-5]
                        self.payload = qname[:-5] 
                        return True
        return False
    
    def calculate_limit_size(self, pkt):
        s = self.pkt_max_size - len(pkt[DNS]) - 2*len(DNSRR()) - 3*len(self.dn) - len("ns.") - 10
        if pkt[DNSQR].qtype == TXT:
            max_size = 512
            s -= len(str(s))
        else:
            max_size = self.qname_max_size
        return min((s, 1)[s<1], max_size) 

    def fragment_data(self, data, limit_size, qtype):
        if qtype == CNAME:
            qname = []
            rest = data
            while len(rest) > 0:
                d = rest[:limit_size]
                qname.append('.'.join([d[i:i+self.label_size] for i in range(0, len(d), self.label_size)]))
                rest = rest[limit_size:]
        elif qtype == TXT:
            qname = [data[i:i+limit_size] for i in range(0, len(data), limit_size)]
        return qname
        
    def compress(self, l):
        """ [1,2,4,12,7,11,3,14,13] => '1-4.7.11-14' """
        l.sort()
        temp = [[l[0]]]
        result = []
        j = 0
        for i in range(1,len(l)):
            if l[i] == l[i-1]+1:
                temp[j] += [l[i]]
            else:
                temp.append([l[i]])
                j += 1
        for r in temp:
            if len(r) > 1:
                result.append("{0}-{1}".format(r[0],r[-1]))
            else:
                result.append(str(r[0]))
        return ".".join(result)
          
    @ATMT.state(initial=True)
    def START(self):
        self.label_size = 63
        self.qname_max_size = 253
        self.pkt_max_size = 512
        self.recv_data = {}
        self.ip_client = self.first_pkt[IP].src
        self.is_first_wyw_pkt = True
        self.iwt_pkt = None
        raise self.TICKLING()

    @ATMT.state()
    def TICKLING(self):
        s = socket.socket()
        s.connect(("127.0.0.1", self.ssh_p))
        self.stream = StreamSocket(s, Raw)
        ssh_msg = self.stream.recv()
        raise self.CON(ssh_msg.load)
        
    @ATMT.state()
    def CON(self, ssh_msg):
        if ssh_msg == "":
            raise self.TICKLING()
        s = self.calculate_limit_size(self.first_pkt)
        qtype = self.first_pkt[DNSQR].qtype 
        self.frag_reply = self.fragment_data(b64encode(ssh_msg), s, qtype)
        if len(self.frag_reply) == 1:
            pkt = Core.forge_packet(self, self.first_pkt, "{0}.{1}.0.{2}".format(_CON, self.con_id, self.frag_reply[0]))
        else:
            pkt = Core.forge_packet(self, self.first_pkt, "{0}.{1}.{2}".format(_CON, self.con_id, str(len(self.frag_reply)-1)))
        send(pkt, verbose=0)
        raise self.WAITING()

    @ATMT.state()
    def WAITING(self):
        pass
    
    @ATMT.timeout(WAITING, 600)
    def timeout_reached(self):
        raise self.END()

    @ATMT.receive_condition(WAITING)
    def data_pkt(self, pkt):
        if self.msg_type in [_ACK, _FAST]:
            pkt_nb = self.arg
            if pkt_nb.isdigit():
                raise self.DATA_RECEPTION(pkt, int(pkt_nb))
                
    @ATMT.receive_condition(WAITING)
    def iwt_pkt(self, pkt):
        if self.msg_type == _IWT:
            raise self.IWT(pkt)

    @ATMT.receive_condition(WAITING)
    def ttm_pkt(self, pkt):
        if self.msg_type == _DATA:
            asked_pkt = self.arg
            if asked_pkt.isdigit():
                raise self.DATA_EMISSION(pkt, int(asked_pkt))

    @ATMT.receive_condition(WAITING)
    def done_pkt(self, pkt):
        if self.msg_type == _DONE:
            code = self.arg
            if code == _ACK or code == _DATA:
                raise self.DONE(pkt, code)

    @ATMT.state()
    def DATA_RECEPTION(self, pkt, pkt_nb):
        if not self.recv_data.has_key(pkt_nb):
            self.recv_data[pkt_nb] = "".join(self.payload)
        if self.msg_type == _ACK:
            ack_pkt = Core.forge_packet(self, pkt, "{0}.{1}".format(_ACK, pkt_nb))
            send(ack_pkt, verbose=0)
            raise self.WAITING()
        elif self.msg_type == _FAST:
            self.fast_pkt = pkt
            self.to_ack = [pkt_nb]
        
    @ATMT.receive_condition(DATA_RECEPTION)
    def got_data(self, pkt):
        if self.msg_type == _FAST:
            if self.arg.isdigit():
                self.fast_pkt = pkt
                pkt_nb = int(self.arg)
                if not self.recv_data.has_key(pkt_nb):
                    self.recv_data[pkt_nb] = "".join(self.payload)
                if pkt_nb not in self.to_ack:
                    self.to_ack.append(pkt_nb)    
    
    @ATMT.timeout(DATA_RECEPTION, 0.5)
    def ack(self):
        #TODO check the limit size
        l = self.compress(self.to_ack)
        ack_pkt = Core.forge_packet(self, self.fast_pkt, "{0}.{1}".format(_FAST, l))
        send(ack_pkt, verbose=0)
        raise self.WAITING()

    @ATMT.state()
    def IWT(self, pkt):
        """IWT (I Want This) state of the Child automaton.
        After receiving a WYW (What You Want) pkt from the client, the server
        says how many DNS pkts he needs to send the reply
        """
        if self.iwt_pkt is not None:
            send(self.iwt_pkt, verbose=0)
        else:
            ssh_reply = self.stream.sniff(count=1, timeout=0.1)
            iwt_pkt = Core.forge_packet(self, pkt, _DONE)
            if len(ssh_reply) > 0:
                qtype = pkt[DNSQR].qtype
                s = self.calculate_limit_size(pkt)
                self.frag_reply = self.fragment_data(b64encode(ssh_reply[0].load), s, qtype)
                self.iwt_pkt = Core.forge_packet(self, pkt,"{0}.{1}".format(_IWT, str(len(self.frag_reply))))
                iwt_pkt = self.iwt_pkt
            send(iwt_pkt, verbose=0)
        raise self.WAITING()

    @ATMT.state()
    def DATA_EMISSION(self, pkt, asked_pkt):
        if asked_pkt <= len(self.frag_reply):
            data_pkt = Core.forge_packet(self, pkt, "{0}.{1}.{2}".format(_DATA, str(asked_pkt), self.frag_reply[-(asked_pkt+1)]))
            send(data_pkt, verbose=0)
        raise self.WAITING()

    @ATMT.state()
    def DONE(self, pkt, code):
        if code == _ACK:
            if self.recv_data.keys() == range(0,len(self.recv_data)):
                d = "".join(self.recv_data.values())
                ssh_request = Raw(b64decode(d))
                self.stream.send(ssh_request)
                self.recv_data.clear()
                send(Core.forge_packet(self, pkt, _DONE), verbose=0)
        elif code == _DATA:
            self.iwt_pkt = None
            send(Core.forge_packet(self, pkt, _DONE), verbose=0)
        raise self.WAITING()
 
    @ATMT.state(final=True)
    def END(self):
        pass

        
if __name__ == "__main__":
    v = "%prog 0.99b - 2011"
    u = "usage: %prog [options]  DOMAIN_NAME  EXTERNAL_IP  [options]"
    parser = OptionParser(usage=u, version=v)
    parser.add_option("-g", "--graph", dest="graph", action="store_true", help="Generate the graph of the automaton, save it to /tmp and exit. You will need some extra packages. Refer to www.secdev.org/projects/scapy/portability.html. In short: apt-get install graphviz imagemagick python-gnuplot python-pyx", default=False)
    parser.add_option("-d", "--debug-lvl", dest="debug", type="int", help="Set the debug level, where D is an integer between 0 (quiet) and 5 (very verbose). Default is 0", metavar="D", default=0)
    parser.add_option("-p", "--ssh-port", dest="port", type="int", help="P is the listening port of your SSH server. Default is 22.", metavar="P", default=22)
    parser.add_option("-c", "--clients", dest="nb_clients", type="int", help="C is the max number of simultaneous clients your server will handle with. Max is 1000. Default is 10.", metavar="C", default=10)
    (opt, args) = parser.parse_args()
    if opt.graph:
        Parent.graph(target="> /tmp/dnscapy_server_parent.pdf")
        Child.graph(target="> /tmp/dnscapy_server_child.pdf")
        sys.exit(0)
    if opt.nb_clients > 1000:
        parser.error("the max number of simultaneous clients is 1000")
    if len(args) != 2:
        parser.error("incorrect number of arguments. Please give the domain name to use and the external IP address of the server")
    dn = args[0]
    ext_ip = args[1]
    log_interactive.setLevel(1)
    dnscapy = Parent(dn, ext_ip, debug=opt.debug, nb_clients=opt.nb_clients, ssh_p=opt.port)
    dnscapy.run()

