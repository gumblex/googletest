#!/usr/bin/env python
# -*- coding: utf-8 -*-

from itertools import chain

# Change the two value according to your actual configuration
HOSTS = 'hosts.txt'
HOSTSFORMAT = False

SR = None

def uniq(seq):
    seen = set()
    return [x for x in seq if x not in seen and not seen.add(x)]


class StaticResolver:

    def __init__(self, recordfile, hostsformat=False):
        self.trie = {}
        with open(recordfile, 'r') as f:
            for ln in f:
                ln = ln.split('#')[0].strip()
                if not ln:
                    continue
                a, b = ln.split()[:2]
                if hostsformat:
                    self.addrecord(b, a)
                else:
                    self.addrecord(a, b)

    def addrecord(self, host, ip):
        host = host.split('.')
        host.reverse()
        root = self.trie
        for lv in host[:-1]:
            if lv not in root:
                root[lv] = {}
            root = root[lv]
        lv = host[-1]
        if lv == '*':
            if lv not in root:
                root[lv] = [ip]
            else:
                root[lv].append(ip)
        else:
            if lv not in root:
                root[lv] = {0: [ip]}
            else:
                if 0 not in root[lv]:
                    root[lv][0] = [ip]
                else:
                    root[lv][0].append(ip)

    def resolve(self, host):
        host = host.strip(' .').split('.')
        host.reverse()
        root = self.trie
        iplist = []
        for lv in host[:-1]:
            if '*' in root:
                iplist.append(root['*'])
            if lv not in root:
                break
            root = root[lv]
        else:
            lv = host[-1]
            if '*' in root:
                iplist.append(root['*'])
            if lv in root:
                iplist.append(root[lv].get(0, ()))
        ips = uniq(chain.from_iterable(reversed(iplist)))
        return ips


def init(id, cfg):
    global SR
    log_info("pythonmod: init called, module id is %d port: %d script: %s" % (id, cfg.port, cfg.python_script))
    SR = StaticResolver(HOSTS, HOSTSFORMAT)
    return True


def deinit(id):
    return True


def inform_super(id, qstate, superqstate, qdata):
    return True


def operate(id, event, qstate, qdata):
    if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
        # query name ends with localdomain
        if (qstate.qinfo.qtype == RR_TYPE_A) or (qstate.qinfo.qtype == RR_TYPE_ANY):
            qstr = qstate.qinfo.qname_str
            rst = SR.resolve(qstr)
            if not rst:
                qstate.ext_state[id] = MODULE_WAIT_MODULE
                return True
            # create instance of DNS message (packet) with given parameters
            msg = DNSMessage(
                qstr, RR_TYPE_A, RR_CLASS_IN, PKT_QR | PKT_RA | PKT_AA)
            # append RR
            for ip in rst[:10]:
                msg.answer.append("%s 3600 IN A %s" % (qstr, ip))
            # set qstate.return_msg
            if not msg.set_return_msg(qstate):
                qstate.ext_state[id] = MODULE_ERROR
                return True

            # we don't need validation, result is valid
            qstate.return_msg.rep.security = 2

            qstate.return_rcode = RCODE_NOERROR
            qstate.ext_state[id] = MODULE_FINISHED
            return True
        else:
            # pass the query to validator
            qstate.ext_state[id] = MODULE_WAIT_MODULE
            return True

    if event == MODULE_EVENT_MODDONE:
        log_info("pythonmod: iterator module done")
        qstate.ext_state[id] = MODULE_FINISHED
        return True

    log_err("pythonmod: bad event")
    qstate.ext_state[id] = MODULE_ERROR
    return True

