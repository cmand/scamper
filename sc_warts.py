#!/usr/bin/env python
# 
# Program:      $Id: sc_warts.py 1551 2015-02-11 14:14:09Z rbeverly $
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  Parse a binary warts capture according to warts.5
#
import struct
import socket
import gzip, bz2
import sys

class WartsReader(object):
  def __init__(self, wartsfile, verbose=False):
    self.address_ref = dict()
    self.verbose = verbose
    # Auto-detect if warts file is using deprecated, type=5 addresses
    self.deprecated_addresses = False
    self.wartsfile = wartsfile
    self.fd = warts_open(self.wartsfile)

    # For each object, define a list of optional variables that may be
    # in the record (dependent on flags indicator) and the callback 
    # to read the variable
    self.list_flags = [
     ('description', self.read_string),
     ('monitor', self.read_string),
    ]

    self.cycle_flags = [
     ('stoptime', self.read_uint32_t),
     ('hostname', self.read_string),
    ]

    self.ping_flags = [
     ('listid', self.read_uint32_t),
     ('cycleid', self.read_uint32_t),
     ('srcipid', self.read_referenced_address),
     ('dstipid', self.read_referenced_address),
     ('timeval', self.read_timeval),
     ('stopreas', self.read_uint8_t),
     ('stopdata', self.read_uint8_t),
     ('datalen', self.read_uint16_t),
     ('data', self.read_uint8_t),
     ('pcount', self.read_uint16_t),
     ('size', self.read_uint16_t),
     ('wait', self.read_uint8_t),
     ('ttl', self.read_uint8_t),
     ('rcount', self.read_uint16_t),
     ('psent', self.read_uint16_t),
     ('method', self.read_uint8_t),
     ('sport', self.read_uint16_t),
     ('dport', self.read_uint16_t),
     ('userid', self.read_uint32_t),
     ('srcaddr', self.read_address),
     ('dstaddr', self.read_address),
     ('flags', self.read_uint8_t),
     ('tos', self.read_uint8_t),
     ('tsps', self.read_address),
     ('icmpsum', self.read_uint16_t),
     ('pmtu', self.read_uint16_t),
     ('timeout', self.read_uint8_t),
     ('waitus', self.read_uint32_t),
    ]

    self.ping_reply_flags = [
     ('dstipid', self.read_referenced_address),
     ('flags', self.read_uint8_t),
     ('replyttl', self.read_uint8_t),
     ('replysize', self.read_uint16_t),
     ('icmp', self.read_uint16_t),
     ('rtt', self.read_uint32_t),
     ('probeid', self.read_uint16_t),
     ('replyipid', self.read_uint16_t),
     ('probeipid', self.read_uint16_t),
     ('replyproto', self.read_uint8_t),
     ('tcpflags', self.read_uint8_t),
     ('addr', self.read_address),
     ('v4rr', self.read_address),
     ('v4ts', self.read_address),
     ('replyipid32', self.read_uint32_t),
     ('tx', self.read_timeval),
     ('tsreply', self.read_uint32_t), # broken; should read 12B
    ]

    self.trace_flags = [
     ('listid', self.read_uint32_t),
     ('cycleid', self.read_uint32_t),
     ('srcipid', self.read_referenced_address),
     ('dstipid', self.read_referenced_address),
     ('timeval', self.read_timeval),
     ('stopreas', self.read_uint8_t),
     ('stopdata', self.read_uint8_t),
     ('traceflg', self.read_uint8_t),
     ('attempts', self.read_uint8_t),
     ('hoplimit', self.read_uint8_t),
     ('tracetyp', self.read_uint8_t),
     ('probesiz', self.read_uint16_t),
     ('srcport', self.read_uint16_t),
     ('dstport', self.read_uint16_t),
     ('firsttl', self.read_uint8_t),
     ('iptos', self.read_uint8_t),
     ('timeout', self.read_uint8_t),
     ('loops', self.read_uint8_t),
     ('probehop', self.read_uint16_t),
     ('gaplimit', self.read_uint8_t),
     ('gaprch', self.read_uint8_t),
     ('loopfnd', self.read_uint8_t),
     ('probesent', self.read_uint16_t),
     ('minwait', self.read_uint8_t),
     ('confid', self.read_uint8_t),
     ('srcaddr', self.read_address),
     ('dstaddr', self.read_address),
     ('usrid', self.read_uint32_t),
    ]

    self.hop_flags = [
     ('addrid', self.read_referenced_address),
     ('probettl', self.read_uint8_t),
     ('replyttl', self.read_uint8_t),
     ('hopflags', self.read_uint8_t),
     ('probeid', self.read_uint8_t),
     ('rtt', self.read_uint32_t),
     ('icmp', self.read_uint16_t),       # type, code
     ('probesize', self.read_uint16_t),
     ('replysize', self.read_uint16_t),
     ('ipid', self.read_uint16_t),
     ('tos', self.read_uint8_t),
     ('mtu', self.read_uint16_t),
     ('qlen', self.read_uint16_t),
     ('qttl', self.read_uint8_t),
     ('tcpflags', self.read_uint8_t),
     ('qtos', self.read_uint8_t),
     ('icmpext', self.read_icmpext),
     ('addr', self.read_address),
    ]

  def next(self):
    while True:
      (obj, length) = self.read_header()
      if obj == -1: return (False, False)
      #print "Object: %02x Len: %d" % (obj, length)
      if obj == 0x01: self.read_list()
      elif obj == 0x02: self.read_cycle()
      elif obj == 0x03: self.read_cycle()
      elif obj == 0x04: self.read_cycle_stop()
      elif obj == 0x05: 
        self.deprecated_addresses = True
        self.read_old_address()
      elif obj == 0x06: 
        return self.read_trace()
      elif obj == 0x07: 
        return self.read_ping()
      else: 
        print "Unsupported object: %02x Len: %d" % (obj, length)

  def read_flags(self, flag_defines):
    """ Warts flag magic. """
    flags_set = []
    while True:
      flag = self.read_uint8_t(self.fd)
      #print "FLAG: %02X" % flag
      flags_set += [self.bit_set(flag, i) for i in range(1,8)]
      if not self.more_flags(flag): break
    flags = dict()
    if flag > 0 or len(flags_set) > 8:
      paramlen = self.read_uint16_t(self.fd)
      #print "PARAMLEN:", paramlen
      for i in range(len(flags_set)):
        if (flags_set[i]):
          read_cb = flag_defines[i][1]
          val = read_cb(self.fd)
          #print "Flag %d: %s %s" % (i+1, flag_defines[i][0], val)
          flags[flag_defines[i][0]] = val
    return flags

  def read_trace(self):
    # deprecated (type 5) referenced addresses are trace-global
    if not self.deprecated_addresses:
      self.address_ref.clear()
    hops = []
    flags = self.read_flags(self.trace_flags)
    # be consistent in populating srcaddr/dstaddr even when deprecated addrs used
    if ('srcipid' in flags) and ('srcaddr' not in flags):
      flags['srcaddr'] = flags['srcipid']
    if ('dstipid' in flags) and ('dstaddr' not in flags):
      flags['dstaddr'] = flags['dstipid']
    if self.verbose: print "Flags:", flags
    records = self.read_uint16_t(self.fd)
    if self.verbose: print "Hops recorded:", records
    for record in range(records):
      hflags = self.read_flags(self.hop_flags)
      if ('addrid' in hflags) and ('addr' not in hflags):
        hflags['addr'] = hflags['addrid']
      # IPID flag not set if IPID is zero
      if ('ipid' not in hflags):
        hflags['ipid'] = 0
      # the quoted TTL is assumed to be 1 unless the q-ttl flag is set
      if ('qttl' not in hflags):
        hflags['qttl'] = 1 
      # the 2B icmp field encodes type (1B) and code (1B).  decode.
      if ('icmp' in hflags):
        hflags['icmp-type'] = hflags['icmp'] >> 8
        hflags['icmp-code'] = hflags['icmp'] & 0xFF
        del hflags['icmp']
      hops.append(hflags)
      if self.verbose: print "\t", hflags
    end = WartsReader.read_uint16_t(self.fd)
    assert (end == 0)
    return (flags, hops)

  def read_ping(self):
    if not self.deprecated_addresses:
      self.address_ref.clear()
    flags = read_flags(ping_flags)
    if verbose: print "Ping Params:", flags
    rcount = read_uint16_t(self.fd)
    pings = []
    for i in range(rcount):
      ping = read_flags(ping_reply_flags)
      pings.append(ping)
      if verbose: print "Reply %d: %s:" % (i+1, ping)
    return (flags, pings)

  def read_list(self):
    wlistid = self.read_uint32_t(self.fd)
    listid = self.read_uint32_t(self.fd)
    lname = self.read_string(self.fd)
    flags = self.read_flags(self.list_flags)
    if self.verbose:
      print "WlistID:", wlistid, "ListID:", listid, "Name:", lname
      print "Flags:", flags

  def read_cycle(self):
    wcycleid = self.read_uint32_t(self.fd)
    listid = self.read_uint32_t(self.fd)
    cycleid = self.read_uint32_t(self.fd)
    start = self.read_uint32_t(self.fd)
    flags = self.read_flags(self.cycle_flags)
    if self.verbose:
      print "ListID:", listid, "CycleID:", cycleid, "Start:", start
      print "Flags:", flags

  def read_cycle_stop(self):
    wcycleid = self.read_uint32_t(self.fd)
    stop = self.read_uint32_t(self.fd)
    flags = self.read_flags(self.cycle_flags)
    if self.verbose:
      print "WCycleID:", wcycleid, "Stop:", stop
      print "Flags:", flags

  def read_header(self):
    """ read warts object header """
    buf = self.fd.read(8)
    if len(buf) != 8:
      return (-1, -1)
    (magic, obj, length) = struct.unpack('!HHI', buf)
    if self.verbose:
      print "Magic: %02X Obj: %02X Len: %02x" % (magic, obj, length)
    assert(magic == 0x1205)
    return (obj, length)

  def read_old_address(self):
    """ Read a warts deprecated (type 5) style referenced address """
    # deprecated address references start at 1
    addr_id = len(self.address_ref) + 1
    id_mod = read_uint8_t(self.fd)
    typ = read_uint8_t(self.fd)
    # "reader...can sanity check the ID number it determines by comparing the
    # lower 8 bits of the computed ID with the ID that is embedded in the record"
    assert(addr_id % 255 == id_mod)
    if typ == 0x01:
      addr = self.fd.read(4)
      quad = socket.inet_ntop(socket.AF_INET, addr) 
    elif typ == 0x02:
      addr = self.fd.read(16)
      quad = socket.inet_ntop(socket.AF_INET6, addr) 
    else:
      print "Addr type:", typ, "not implemented"
      assert False
    self.address_ref[addr_id] = quad
    #print "Address ID:", addr_id, "->", quad

  def read_address(self, fd):
    """ read a warts-style ip/mac address """
    length = WartsReader.read_uint8_t(self.fd)
    addr = 0
    typ = 0
    # an embedded (non-referenced) address
    if length != 0:
      typ = WartsReader.read_uint8_t(fd)
      addr = self.fd.read(length)
      addr_id = len(self.address_ref)
      self.address_ref[addr_id] = addr 
    # a referenced address
    else:
      addr_id = WartsReader.read_uint32_t(fd)
      try:
        addr = self.address_ref[addr_id]
      except:
        print "Die: couldn't find referenced address %d" % addr_id
        sys.exit(-1)
    if typ == 0:
      if len(addr) == 4: typ = 1
      if len(addr) == 16: typ = 2
    if typ == 1:
      return socket.inet_ntop(socket.AF_INET, addr)
    elif typ == 2:
      return socket.inet_ntop(socket.AF_INET6, addr)
    else:
      print "Addr type:", typ, "not implemented"
      assert False

  def read_referenced_address(self):
    """ Resolve a warts deprecated (type 5) style referenced address """
    addr_id = read_uint32_t(self.fd)
    assert (addr_id in self.address_ref)
    addr = self.address_ref[addr_id]
    return addr

  @staticmethod
  def more_flags(b):
    """ Is high order bit set on flag byte? """
    return (b & 0x80 == 0x80)

  @staticmethod
  def hexdump(buf):
    return ''.join('{:02x}'.format(ord(x)) for x in buf)
  
  @staticmethod
  def bit_set(b, i):
    """ Warts flag magic: is the i'th bit of byte b set to 1? """
    return ( (b >> (i-1)) & 0x01 == 0x01)

  @staticmethod
  def read_uint8_t(f):
    return (struct.unpack('B', f.read(1)))[0]

  @staticmethod
  def read_uint16_t(f):
    return (struct.unpack('!H', f.read(2)))[0]

  @staticmethod
  def read_uint32_t(f):
    return (struct.unpack('!I', f.read(4)))[0]

  @staticmethod
  def read_timeval(f):
    sec = WartsReader.read_uint32_t(f)
    usec = WartsReader.read_uint32_t(f)
    return (sec + usec/1000000.0)

  @staticmethod
  def read_icmpext(f):
    """ read ICMP extension header """
    l = WartsReader.read_uint16_t(f)
    ic = WartsReader.read_uint8_t(f)
    it = WartsReader.read_uint8_t(f)
    buf = f.read(l-2)
    return "class: " + str(ic) + " type: " + str(it) + " buf: " + WartsReader.hexdump(buf)

  @staticmethod
  def read_string(f):
    """ read a null terminated string """
    s = ''
    while True:
      b = f.read(1)
      if len(b) != 1: break
      if ord(b) == 0x00: break
      s += b
    return s


def warts_open(infile):
  fd = None
  # try reading as a bz2 file
  try:
    fd = bz2.BZ2File(infile, 'rb')
    fd.read(1)
    fd = bz2.BZ2File(infile, 'rb')
    return fd
  except IOError, e:
    pass
  # try reading as a gzip file
  try:
    fd = gzip.open(infile, 'rb')
    fd.read(1)
    fd = gzip.open(infile, 'rb')
    return fd
  except IOError, e:
    pass
  return open(infile, 'rb')


if __name__ == "__main__":
  assert len(sys.argv) == 2
  w = WartsReader(sys.argv[1], verbose=True)
  while True:
    (flags, hops) = w.next()
    if flags == False: break
