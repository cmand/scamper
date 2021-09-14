#!/usr/bin/env python
# 
# Program:      $Id: $
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  Experimental tracebox warts parser
import sys
import struct
import dpkt
from sc_warts import *

if dpkt.__version__ == '1.8':
  print("Upgrade dpkt")
  sys.exit(-1)

TRACEBOXTYPE = 0x0c

def dict_diff(a, b):
  diff = dict()
  for k in a:
    if k in b:
      if b[k] != a[k]:
        diff[k] = (a[k],b[k])
  return diff
  
#  return set(a.items()) ^ set(b.items())

class WartsTraceBoxReader(WartsReader): 
  def __init__(self, wartsfile, verbose=False):
    super(WartsTraceBoxReader, self).__init__(wartsfile, verbose)

  def __next__(self):
    while True:
      obj = self.next_object()
      if not obj:
        return (False, False)
      if (obj.typ == TRACEBOXTYPE):
        return (obj.flags, obj.pkts)

  def next_object(self):
    # read warts object header
    self.header = self.fd.read(8)
    # sanity check
    if len(self.header) != 8:
      return None
    (magic, typ, length) = struct.unpack('!HHI', self.header)
    if self.verbose:
      print("Magic: %02X Obj: %02X Len: %02x" % (magic, typ, length))
    assert(magic == obj_type['MAGIC'])
    # read remainder of object
    data = self.fd.read(length)
    if typ == obj_type['LIST']:
      return WartsList(data, verbose=self.verbose)
    elif typ == obj_type['CYCLESTART']:
      return WartsCycle(data, verbose=self.verbose)
    elif typ == obj_type['CYCLE']:
      return WartsCycle(data, verbose=self.verbose)
    elif typ == obj_type['CYCLE_STOP']:
      return WartsCycleStop(data, verbose=self.verbose)
    elif typ == TRACEBOXTYPE:
      return WartsTraceBox(data, verbose=self.verbose) 
    else:
      print("Unsupported object: %02x Len: %d" % (typ, length))
      assert False

class WartsTraceBox(WartsBaseObject):
  def __init__(self, data, verbose=False):
    super(WartsTraceBox, self).__init__(TRACEBOXTYPE, verbose)
    self.data = data
    self.flagdata = data
    self.pkts = []
    self.flag_defines = [
     ('listid', unpack_uint32_t),
     ('cycleid', unpack_uint32_t),
     ('userid', unpack_uint32_t),
     ('srcaddr', self.unpack_address),
     ('dstaddr', self.unpack_address),
     ('sport', unpack_uint16_t),
     ('dport', unpack_uint16_t),
     ('start', read_timeval),
     ('result', unpack_uint16_t),
     ('rtt', unpack_uint8_t),
     ('qtype', unpack_uint8_t),
     ('udp', unpack_uint8_t),
     ('printmode', unpack_uint8_t),
     ('pktc16', unpack_uint16_t),
     ('pktc', unpack_uint32_t),
    ]
    flag_bytes = self.read_flags()
    if self.verbose:
      print("TB Params:", self.flags)
    offset = flag_bytes
    for i in range(self.flags['pktc']):
      pkt = WartsTraceBoxPkt(data[offset:], self.referenced_address, self.verbose)
      self.pkts.append(pkt.flags)
      offset+=pkt.flag_bytes 
      if self.verbose: print("Pkt %d: %s" % (i+1, pkt.flags))

class WartsTraceBoxPkt(WartsBaseObject):
  def __init__(self, data, refs, verbose=False):
    super(WartsTraceBoxPkt, self).__init__(TRACEBOXTYPE, verbose)
    self.update_ref(refs)
    self.flagdata = data
    self.flag_defines = [
     ('dir', unpack_uint8_t),
     ('time', read_timeval),
     ('len', unpack_uint16_t),
     ('data', self.read_pass),
    ]
    self.flag_bytes = self.read_flags()
    datalen = self.flags['len']
    self.flags['data'] = self.read_tracebox_pkt(data[self.flag_bytes:self.flag_bytes+datalen])
    self.flag_bytes += self.flags['len']

  def read_pass(self, b):
    return ("pass", 0)

  def read_tracebox_pkt(self, data):
    fields = dict()
    ip = dpkt.ip.IP(data)
    fields['hop'] = socket.inet_ntoa(ip.src)
    if ip.p == dpkt.ip.IP_PROTO_ICMP:
      # This is a reply from a hop
      fields['hop'] = socket.inet_ntoa(ip.src)
      icmp = ip.data
      #print "ICMP quote:", icmp.type, icmp.code, "LEN:", len(icmp.data.data)
      # icmp.data is type dpkt.icmp.TimeExceed
      # so, icmp.data.data is a dpkt.ip.IP
      ip = icmp.data.data
    fields['IP::Version'] = ip.v
    fields['IP::IHL'] = ip.hl
    dscp = (ip.tos & 0xFC) >> 2
    ecn = (ip.tos & 0x03)
    fields['IP::DiffServicesCP'] = hex(dscp)
    fields['IP::ECN'] = hex(ecn)
    fields['IP:Length'] = hex(ip.len)
    fields['IP:ID'] = ip.id
    flags = (ip.df >> 1) + ip.mf
    fields['IP:Flags'] = hex(flags)
    fields['IP:FragmentOffset'] = ip.offset
    fields['IP:TTL'] = ip.ttl
    fields['IP::Protocol'] = ip.p
    fields['IP::Checksum'] = hex(ip.sum)
    fields['IP::SourceAddr'] = socket.inet_ntoa(ip.src)
    fields['IP::DestAddr'] = socket.inet_ntoa(ip.dst)
    if ip.p == dpkt.ip.IP_PROTO_TCP:
      tcp = ip.data
      if not isinstance(tcp, dpkt.tcp.TCP):
        #print "Partial quote!"
        z = struct.pack('12sB',ip.data,0x50) + struct.pack('7B',*([0]*7))
        tcp = dpkt.tcp.TCP(z)
        #print type(tcp)
      if len(ip.data) >= 4:
        fields['TCP::SPort'] = hex(tcp.sport)
        fields['TCP::DPort'] = hex(tcp.dport)
      if len(ip.data) >= 8:
        fields['TCP::SeqNumber'] = hex(tcp.seq)
      if len(ip.data) >= 12:
        fields['TCP::AckNumber'] = hex(tcp.ack)
      if len(ip.data) >= 16:
        fields['TCP::Offset'] = hex(tcp.off)
        fields['TCP::Flags'] = hex(tcp.flags)
        fields['TCP::Window'] = hex(tcp.win)
      if len(ip.data) == 20:
        fields['TCP::Checksum'] = hex(tcp.sum)
        fields['TCP::UrgentPtr'] = hex(tcp.urp)
      if len(ip.data) >= 20:
        if len(tcp.opts) > 0:
          opts = dpkt.tcp.parse_opts(tcp.opts)
          for o,d in opts:
            if o == dpkt.tcp.TCP_OPT_EOL:
              fields['TCP::OPT_EOL'] = d
            elif o == dpkt.tcp.TCP_OPT_NOP:
              fields['TCP::OPT_NOP'] = d
            elif o == dpkt.tcp.TCP_OPT_MSS:
              fields['TCP::OPT_MSS'] = d
            elif o == dpkt.tcp.TCP_OPT_WSCALE:
              fields['TCP::OPT_WSCALE'] = d
            elif o == dpkt.tcp.TCP_OPT_SACKOK:
              fields['TCP::OPT_SACKOK'] = d
            elif o == dpkt.tcp.TCP_OPT_SACK:
              fields['TCP::OPT_SACK'] = d
            elif o == dpkt.tcp.TCP_OPT_TIMESTAMP:
              fields['TCP::OPT_TIMESTAMP'] = d
    return fields


if __name__ == "__main__":
  assert len(sys.argv) == 2
  w = WartsTraceBoxReader(sys.argv[1], verbose=False)
  while True:
    (flags, pkts) = next(w)
    if flags == False: break
    print("tracebox from %s to %s (result: %d)" % (flags['srcaddr'], flags['dstaddr'], flags['result']))
    last_tx = None
    last_tx_ts = 0
    i = 0
    for pkt in pkts:
      ts = pkt['time'] - flags['start']
      if pkt['dir'] == 1: #TX
        #print " TX at %1.3f:" % (ts)
        if last_tx != None:
          i+=1
          print(" %d: *" % (i))
        last_tx = pkt['data']
        last_tx_ts = pkt['time']
      else: #RX
        #print " RX at %1.3f:" % (ts)
        i+=1
        rtt = (pkt['time'] - last_tx_ts)*1000.0
        if last_tx:
          diff = dict_diff(last_tx, pkt['data'])
          print(" %d: %s RTT:%1.3f: %s" % (i, pkt['data']['hop'], rtt, " ".join(list(diff.keys()))))
        last_tx = None
