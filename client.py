#!/usr/bin/env python2

import sys
import socket
import argparse
from contextlib import closing
from pydns import DNSPacket

DNS_CLIENT_VERSION = "0.1"

def cli_handle():
    """Process CLI input"""
    parser = argparse.ArgumentParser(version=DNS_CLIENT_VERSION,
                                     description="DNS query utility")

    parser.add_argument("hostname", help="hostname to lookup")
    parser.add_argument("-s", "--server", help="DNS server to query")
    parser.add_argument("-p", "--port", help="DNS server port",
                        type=int, default=53)
    parser.add_argument("-t", "--timeout", help="response wait timeout",
                        type=int, default=5)
    parser.add_argument("-r", "--retries", help="number of request retries",
                        type=int, default=3)
    parser.add_argument("-d", "--debug", help="increase output verbosity",
                        action="count", default=0)

    args = parser.parse_args()
    return args

def chunk_string(str, num):
    for loc in range(0, len(str), num):
        yield str[loc:loc+num]

def print2byte(str, newline=2):
    for chunk in chunk_string(str,newline):
            print ":".join("{:02x}".format(ord(c)) for c in chunk)

def main():
    args = cli_handle()
    server_ip = args.server
    if server_ip is None:
        print "TODO: Read /etc/resolv.conf if it exists"
        sys.exit(1)
    dns_port = args.port
    #timeout = args.timeout
    #retries = args.retries

    #Create the packet to send
    q = DNSPacket()
    if args.debug >= 3:
        print q.header.str_me()
        print2byte(q.header.get_pack())
    q.add_q(args.hostname)
    if args.debug >= 2:
        tmp_pack = q.get_pack()
        print str(len(tmp_pack)), " ", tmp_pack
        print2byte(tmp_pack, newline=6)
    if args.debug >= 1:
        print "### Query Packet"
        print q.str_me()
        print "### END Query Packet"

    #Send the packet out and wait for response from server
    with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as soc:
        try:
            soc.sendto(q.get_pack(),(server_ip,dns_port))
        except socket.error:
            print "send failed"
        reply, remote = soc.recvfrom(1024)
        while remote != (server_ip, dns_port):
            print "ERROR: response from unknown server %s" % str(remote)
            reply, remote = soc.recvfrom(1024)

    if args.debug >= 2:
        print str(len(reply)), " ", reply
        print2byte(reply, newline=6)

    #Parse the reply packet
    r = DNSPacket()
    r.from_pack(reply)

    if args.debug >= 1:
        print "### Reply Packet"
        print r.str_me()
        print "### END Reply Packet"
    print r.str_answers()

    return 0

if __name__ == "__main__":
    status = main()
    sys.exit(status)
