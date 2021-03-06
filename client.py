#!/usr/bin/env python

import argparse
import os.path
import socket
import sys
from contextlib import closing

from pydns import DNSPacket

DNS_CLIENT_VERSION = "0.2"


def cli_handle():
    """Process CLI input"""
    parser = argparse.ArgumentParser(description="DNS query utility")

    parser.add_argument("-v", "--version", action="version", version=DNS_CLIENT_VERSION)
    parser.add_argument("hostname", help="hostname to lookup")
    parser.add_argument(
        "querytype", help="Specify type of query", nargs="?", type=int, default=1
    )
    parser.add_argument("-s", "--server", help="DNS server to query")
    parser.add_argument("-p", "--port", help="DNS server port", type=int, default=53)
    parser.add_argument(
        "-t", "--timeout", help="response wait timeout", type=int, default=5
    )
    parser.add_argument(
        "-r", "--retries", help="number of request retries", type=int, default=3
    )
    parser.add_argument(
        "-d", "--debug", help="increase output verbosity", action="count", default=0
    )

    args = parser.parse_args()
    return args


def chunk_string(string, num):
    for loc in range(0, len(string), num):
        yield string[loc : loc + num]


def print2byte(string, newline=2):
    for chunk in chunk_string(string, newline):
        print(
            ":".join(
                "{:02x}".format(c if isinstance(c, int) else ord(c)) for c in chunk
            )
        )


def valid_addr(family, string):
    try:
        socket.inet_pton(family, string)
        return True
    except socket.error:
        return False


def read_resolve():
    if not os.path.isfile("/etc/resolv.conf"):
        print("ERROR: /etc/resolv.conf not found")
        return None
    dns_servers = []
    with open("/etc/resolv.conf", "r") as resolv:
        for line in resolv:
            if line.startswith("nameserver"):
                for chunk in line.split():
                    if valid_addr(socket.AF_INET, chunk):
                        dns_servers.append((socket.AF_INET, chunk))
                    elif valid_addr(socket.AF_INET6, chunk):
                        dns_servers.append((socket.AF_INET6, chunk))
    return dns_servers


def send_query(family, proto, query, timeout, server, port):
    with closing(socket.socket(family, proto)) as soc:
        if timeout > 0:
            soc.settimeout(timeout)
        try:
            soc.sendto(query.get_pack(), (server, port))
        except socket.error:
            print("ERROR: send failed")
        reply, remote = soc.recvfrom(1024)
        while (remote[0], remote[1]) != (server, port):
            print("ERROR: response from unknown server %s" % str(remote))
            reply, remote = soc.recvfrom(1024)
        return reply


def main():
    args = cli_handle()
    server_ip = args.server
    if server_ip is None:
        dns_servers = read_resolve()
        if not dns_servers:
            print("ERROR DNS server not specified and found no defaults")
            sys.exit(1)
        else:
            server_ip = dns_servers[0][1]  # TODO: rotate through available
            server_family = dns_servers[0][0]
    elif valid_addr(socket.AF_INET, server_ip):
        server_family = socket.AF_INET
    elif valid_addr(socket.AF_INET6, server_ip):
        server_family = socket.AF_INET6
    else:
        print("ERROR, did not recognize %s as a valid IP" % server_ip)
        sys.exit(2)
    dns_port = args.port
    timeout = args.timeout
    retries = args.retries

    # Create the packet to send
    q = DNSPacket()
    if args.debug >= 3:
        print(q.header)
        print2byte(q.header.get_pack())
    q.add_q(args.hostname, q_type=args.querytype)
    if args.debug >= 2:
        tmp_pack = q.get_pack()
        print(b" ".join((bytes(len(tmp_pack)), tmp_pack)))
        print2byte(tmp_pack, newline=6)
    if args.debug >= 1:
        print("### Query Packet")
        print(q)
        print("### END Query Packet")

    # Send the packet out and wait for response from server
    for attempt in range(retries):
        try:
            reply = send_query(
                server_family, socket.SOCK_DGRAM, q, timeout, server_ip, dns_port
            )
            break
        except socket.timeout:
            output_str = "Attempt %d/%d timed out," % (attempt + 1, retries)
            if (attempt + 1) < retries:
                print(" ".join([output_str, "retrying..."]))
            else:
                print(" ".join([output_str, "quitting"]))
                sys.exit(3)

    if args.debug >= 2:
        print(b" ".join((bytes(len(reply)), reply)))
        print2byte(reply, newline=6)

    # Parse the reply packet
    try:
        r = DNSPacket(reply)
    except ValueError:
        print("UDP packet truncated, retrying with TCP")
        reply = send_query(
            server_family, socket.SOCK_STREAM, q, timeout, server_ip, dns_port
        )
        r = DNSPacket(reply)

    if args.debug >= 1:
        print("### Reply Packet")
        print(r)
        print("### END Reply Packet")
    print(r.str_answers())

    return 0


if __name__ == "__main__":
    status = main()
    sys.exit(status)
