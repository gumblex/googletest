#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os    #
import re    #
import sys   #
import ssl    #
import _ssl    #
import time     #
import socket     #
import random       #
import itertools      #
import ipaddress        #
import urllib.error        #
import urllib.request         #
import multiprocessing.dummy     #
from operator import itemgetter     #     #
from argparse import ArgumentParser    #_ #
from collections import defaultdict    ####
from eta import ETA

TMOUT = 2

GOOGLE_ISSUER = ((('countryName', 'US'),),
                 (('organizationName', 'Google Inc'),),
                 (('commonName', 'Google Internet Authority G2'),))


class NoCheckHTTPSHandler(urllib.request.HTTPSHandler):

    def __init__(self):
        urllib.request.AbstractHTTPHandler.__init__(self, 0)
        self._context = sslctx
        self._check_hostname = False

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, headers):
        result = urllib.error.HTTPError(req.get_full_url(), code, msg, headers, fp)
        result.status = code
        return result
    http_error_301 = http_error_303 = http_error_307 = http_error_302

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

urlopener = urllib.request.build_opener(NoCheckHTTPSHandler(), NoRedirectHandler())

def get_dnsnames(cert):
    if not cert:
        raise ValueError("empty or no certificate, match_hostname needs a "
                         "SSL socket or SSL context with either "
                         "CERT_OPTIONAL or CERT_REQUIRED")
    dnsnames = []
    san = cert.get('subjectAltName', ())
    for key, value in san:
        dnsnames.append(value)
    if not dnsnames:
        # The subject is only checked when there is no dNSName entry
        # in subjectAltName
        for sub in cert.get('subject', ()):
            for key, value in sub:
                # XXX according to RFC 2818, the most specific Common Name
                # must be used.
                if key == 'commonName':
                    dnsnames.append(value)
    return dnsnames

def generate_hostname(dnsnames):
    wildcard = None
    for name in dnsnames:
        if name.startswith('*.'):
            wildcard = name[1:]
        elif '*' not in name:
            return name
    return 'www' + wildcard


def checkcert(host, port=443, timeout=TMOUT, issuer=GOOGLE_ISSUER):
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
    return get_dnsnames(cert)


class GoogleIPManager:

    def __init__(self, networklist):
        self.networks = list(map(ipaddress.IPv4Network, networklist))
        self.count = sum(net.num_addresses for net in self.networks)
        self.avail = {}
        self.hosts = defaultdict(set)
        self.progress = None

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
        dnsnames = checkcert(ip, 443)
        if not dnsnames:
            return False
        hostname = generate_hostname(dnsnames)
        req = urllib.request.Request("https://" + ip, headers={"Host": hostname})
        start = time.time()
        try:
            with urlopener.open(req, timeout=TMOUT) as f:
                page = f.read(2048)
        except Exception as ex:
            return False
        return (dnsnames, time.time() - start)

    def checkoneip(self, ip):
        if ip not in self.avail:
            res = self.checkip(ip)
            if res:
                self.avail[ip] = res[1]
                for host in res[0]:
                    self.hosts[host].add(ip)
        self.progress.print_status()

    def outputip(self):
        out = []
        for host in self.hosts:
            out.extend((host, ip, self.avail[ip]) for ip in sorted(self.hosts[host], key=self.avail.__getitem__))
        return out


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
    except (KeyboardInterrupt, BrokenPipeError):
        p.terminate()
    finally:
        gm.progress.done()
    return gm.outputip()


def main():
    parser = ArgumentParser()
    parser.add_argument("-n", "--num", default=100000, type=int,
                        help="how many IPs to test")
    parser.add_argument("-w", "--workers", default=100, type=int,
                        help="how many threads to use")
    parser.add_argument("-t", "--time", action='store_true',
                        help="show connection time")
    parser.add_argument("-o", "--hosts", action='store_true',
                        help="output hosts format")
    parser.add_argument("file", nargs='?', default='googleip.txt',
                        help="Google IP list file")
    args = parser.parse_args()

    with open(args.file) as f:
        ipnetlist = f.read().strip().splitlines()

    GM = GoogleIPManager(ipnetlist)
    if args.hosts:
        print('127.0.0.1\tlocalhost')
        print('')
        print('# Hosts generated by GoogleTest')
        print('# Updated at ' + time.asctime())
    for h, i, t in batchcheck(GM, args.num, args.workers):
        if args.hosts:
            if not h.startswith('*.'):
                print('%s\t%s' % (i, h))
        elif args.time:
            print(h, i, t)
        else:
            print(h, i)

if __name__ == '__main__':
    main()
