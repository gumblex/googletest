#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import ssl
import _ssl
import time
import random
import socket
import itertools
import ipaddress
import urllib.request
import multiprocessing.dummy
from eta import ETA
from operator import itemgetter
from argparse import ArgumentParser

TMOUT = 2

GOOGLE_ISSUER = ((('countryName', 'US'),),
                 (('organizationName', 'Google Inc'),),
                 (('commonName', 'Google Internet Authority G2'),))


class NoCheckHTTPSHandler(urllib.request.HTTPSHandler):

    def __init__(self):
        urllib.request.AbstractHTTPHandler.__init__(self, 0)
        self._context = sslctx
        self._check_hostname = False

socket.setdefaulttimeout(TMOUT)
sslctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
sslctx.options |= ssl.OP_NO_SSLv2
sslctx.options |= ssl.OP_NO_SSLv3
sslctx.options |= getattr(_ssl, "OP_NO_COMPRESSION", 0)
sslctx.verify_mode = ssl.CERT_REQUIRED
sslctx.set_default_verify_paths()
try:
    sslctx.check_hostname = False
except AttributeError:
    pass

urlopener = urllib.request.build_opener(NoCheckHTTPSHandler)


def checkcert(host, port=443, domain='www.google.com', timeout=TMOUT, issuer=GOOGLE_ISSUER):
    addr = (host, port)
    try:
        with socket.create_connection(addr) as sock:
            sock.settimeout(timeout)
            with sslctx.wrap_socket(sock) as sslsock:
                cert = sslsock.getpeercert()
    except Exception as ex:
        return False
    if issuer and cert['issuer'] != issuer:
        return False
    try:
        ssl.match_hostname(cert, domain)
        return True
    except ssl.CertificateError as ex:
        return False


class GoogleIPManager:

    def __init__(self, networklist):
        self.networks = list(map(ipaddress.IPv4Network, networklist))
        self.count = sum(net.num_addresses for net in self.networks)
        self.host = 'www.google.com'
        self.headers = {}
        self.avail = {}
        self.progress = None

    def sethost(self, host=None):
        if host:
            self.host = host
            self.headers = {"Host": host}
        else:
            self.host = 'www.google.com'
            self.headers = {}

    def randomip(self):
        # Every IP RANGE has equal chance
        net = random.choice(self.networks)
        ip = str(net[random.randrange(net.num_addresses)])
        return ip

    def ips(self):
        for net in self.networks:
            for ip in net:
                yield str(ip)

    def randomips(self, num):
        for n in range(num):
            yield self.randomip()

    def checkip(self, ip):
        if not checkcert(ip, 443, self.host):
            return False
        req = urllib.request.Request("https://" + ip, headers=self.headers)
        start = time.time()
        try:
            with urlopener.open(req, timeout=TMOUT) as f:
                page = f.read()
                if b'<title>Google</title>' not in page:
                    return False
        except Exception as ex:
            return False
        return time.time() - start

    def checkoneip(self, ip):
        if ip not in self.avail:
            res = self.checkip(ip)
            if res:
                self.avail[ip] = res
        self.progress.print_status()

def checksslhosts(hostsfile):
    validlines = []
    for ln in hostsfile.splitlines(True):
        try:
            ip, host = ln.split('#')[0].strip().split()
        except ValueError as ex:
            continue
        if ip == '127.0.0.1' or checkcert(ip, 443, host, 5, None):
            validlines.append(ln)
    return ''.join(validlines)


def batchcheck(gm, count=10000, workers=100):
    try:
        p = multiprocessing.dummy.Pool(workers)
        workers = min(workers, count)
        chunksize = max(count // workers, 1)
        if count < gm.count:
            gm.progress = ETA(count)
            it = p.imap_unordered(
                gm.checkoneip, gm.randomips(count), chunksize)
        else:
            gm.progress = ETA(gm.count)
            it = p.imap_unordered(gm.checkoneip, gm.ips(), chunksize)
        for _ in it:
            pass
    except KeyboardInterrupt:
        p.terminate()
    finally:
        gm.progress.done()
    return sorted(gm.avail.items(), key=itemgetter(1))


def main():
    parser = ArgumentParser()
    parser.add_argument("-n", "--num", default=10000, type=int,
                        help="how many IPs to test")
    parser.add_argument("-w", "--workers", default=100, type=int,
                        help="how many threads to use")
    parser.add_argument("-o", "--host", help="set 'Host' header to")
    parser.add_argument("-t", "--time", action='store_true',
                        help="show connection time")
    #parser.add_argument("-c", "--checkhosts", action='store_true',
                        #help="check 'hosts' file")
    parser.add_argument("file", nargs='?', default='googleip.txt',
                        help="Google IP list file or hosts file to check")
    args = parser.parse_args()

    #if args.checkhosts:
        #with open(args.file) as f:
            #sys.stdout.write(checksslhosts(f.read()))
            #sys.stdout.flush()
    #else:
    with open(args.file) as f:
        ipnetlist = f.read().strip().splitlines()

    GM = GoogleIPManager(ipnetlist)
    GM.sethost(args.host)
    for i, t in batchcheck(GM, args.num, args.workers):
        if args.time:
            print(i, t)
        else:
            print(i)

if __name__ == '__main__':
    main()
