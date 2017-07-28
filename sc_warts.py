#!/usr/bin/env python
#
# Copyright (c) 2015-2016, Robert Beverly
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# 
# Program:      $Id: sc_warts.py 1551 2015-02-11 14:14:09Z rbeverly $
# Author:       Robert Beverly <rbeverly@cmand.org>
# Description:  Parse a binary warts capture according to warts.5
#

__author__ = 'Robert Beverly <rbeverly@cmand.org>'
__copyright__ = 'Copyright (c) 2015-2016 Robert Beverly'
__url__ = 'https://github.com/cmand/scamper'
__version__ = 1.2

import struct
import socket
import gzip, bz2
import sys

obj_type = {'NONE' : 0x00, 'LIST' : 0x01, 'CYCLESTART' : 0x02, 'CYCLE' : 0x03,
            'CYCLESTOP': 0x04, 'ADDRESS': 0x05, 'TRACE' : 0x06, 'PING' : 0x07,
            'MAGIC' : 0x1205}

def unpack_uint8_t(b):
  return (struct.unpack('B', b[0])[0], 1)

def unpack_uint16_t(b):
  return (struct.unpack('!H', b[0:2])[0], 2)

def unpack_uint32_t(b):
  return (struct.unpack('!I', b[0:4])[0], 4)

def read_string(b):
  (string, remainder) = b.split('\x00', 1)
  return (string, len(string)+1)

def read_timeval(b):
  (sec, usec) = struct.unpack('!II', b[0:8])
  return (sec + usec/1000000.0, 8)

def hexdump(buf):
  return ''.join('{:02x}'.format(ord(x)) for x in buf)


class WartsBaseObject(object):
  def __init__(self, objtype=obj_type['NONE'], verbose=False):
    self.typ = objtype
    # For each object, define a list of optional variables that may be
    # in the record (dependent on flags indicator) and the callback
    # to read the variable
    self.flag_defines = []
    self.flags = dict()
    self.verbose = verbose
    self.flagdata = ""
    self.referenced_address = dict()

  @staticmethod
  def more_flags(b):
    """ Is high order bit set on flag byte? """
    return (b & 0x80 == 0x80)

  @staticmethod
  def bit_set(b, i):
    """ Warts flag magic: is the i'th bit of byte b set to 1? """
    return ( (b >> (i-1)) & 0x01 == 0x01)

  def read_flags(self, debug=False):
    """ Warts flag magic. """
    flags_set = []
    current_byte = 0
    byte = 0
    for byte in range(len(self.flagdata)):
      flag = ord(self.flagdata[byte])
      flags_set += [self.bit_set(flag, i) for i in range(1,8)]
      if not self.more_flags(flag): break
    current_byte += byte + 1
    if debug: print "Flags Set:", flags_set, len(flags_set)
    flags = dict()
    if flag > 0 or len(flags_set) > 8:
      paramlen = unpack_uint16_t(self.flagdata[current_byte:current_byte+2])[0]
      current_byte+=2
      for i in range(len(flags_set)):
        if (flags_set[i]):
          if (i >= len(self.flag_defines)):
            print "** UNKNOWN FLAG: %d" % (i+1)
            sys.exit(-1)
          read_cb = self.flag_defines[i][1]
          (val, bytes_read) = read_cb(self.flagdata[current_byte:])
          current_byte+=bytes_read
          if debug: print "Flag %d: %s %s" % (i+1, self.flag_defines[i][0], val)
          self.flags[self.flag_defines[i][0]] = val
    # be consistent in populating srcaddr/dstaddr for deprecated addrs
    if ('srcipid' in self.flags) and ('srcaddr' not in self.flags):
      self.flags['srcaddr'] = self.flags['srcipid']
    if ('dstipid' in self.flags) and ('dstaddr' not in self.flags):
      self.flags['dstaddr'] = self.flags['dstipid']
    return current_byte

  def update_ref(self, _referenced_address):
    self.referenced_address = _referenced_address

  def unpack_address(self, b):
    """ read a warts-style ip/mac address """
    bytes_read = 0
    (length, r) = unpack_uint8_t(b[bytes_read])
    bytes_read+=r
    #addr = 0
    # an embedded (non-referenced) address
    if length != 0:
      (typ, r) = unpack_uint8_t(b[bytes_read])
      bytes_read+=r
      addr = b[bytes_read:bytes_read+length]
      bytes_read+=length
      addr_id = len(self.referenced_address)
      self.referenced_address[addr_id] = addr 
    # a referenced address
    else:
      (addr_id, r) = unpack_uint32_t(b[bytes_read:])
      bytes_read+=r
      try:
        addr = self.referenced_address[addr_id]
      except:
        print "Die: couldn't find referenced address %d" % addr_id
        sys.exit(-1)
    if len(addr) == 4:
      return (socket.inet_ntop(socket.AF_INET, addr), bytes_read)
    elif len(addr) == 16:
      return (socket.inet_ntop(socket.AF_INET6, addr), bytes_read)
    else:
      assert False

  def read_referenced_address(self, b):
    """ Resolve a warts deprecated (type 5) style referenced address """
    bytes_read = 0
    (addr_id, r) = unpack_uint32_t(b)
    bytes_read+=r
    addr = addr_id
    if addr_id in self.referenced_address:
      addr = self.referenced_address[addr_id]
    return (addr, bytes_read)


class WartsDeprecatedAddress:
  """ Read a warts deprecated (type 5) address object """
  def __init__(self, data, verbose=False):
    self.typ = obj_type['ADDRESS']
    self.data = data
    self.addr = ""
    (self.id, self.type) = struct.unpack('BB', data[:2])
    if self.type == 0x01:
      self.addr = socket.inet_ntop(socket.AF_INET, data[2:6])
    elif self.type == 0x02:
      self.addr = socket.inet_ntop(socket.AF_INET6, data[2:18])
    else:
      print >> sys.stderr, "Addr type:", self.type, "not implemented."
      assert False


class WartsList(WartsBaseObject):
  def __init__(self, data, verbose=False):
    super(WartsList, self).__init__(obj_type['LIST'], verbose)
    self.data = data
    self.flag_defines = [
     ('description', read_string),
     ('monitor', read_string),
    ]
    (self.wlistid, self.listid) = struct.unpack('!II', data[:8])
    if len(data) > 8:
      (self.name, read_len) = read_string(data[8:])
      self.flagdata = data[8+read_len:]
    flag_bytes = self.read_flags()
    if self.verbose:
      print "WlistID:", self.wlistid, "ListID:",  self.listid, \
            "Name:", self.name
      print "Flags:", self.flags


class WartsCycle(WartsBaseObject):
  def __init__(self, data, verbose=False):
    super(WartsCycle, self).__init__(obj_type['CYCLE'], verbose)
    self.data = data
    self.flag_defines = [
     ('stoptime', unpack_uint32_t),
     ('hostname', read_string),
    ]
    (self.wcycleid, self.listid, self.cycleid, self.start) = struct.unpack('!IIII', data[:16])
    self.flagdata = data[16:]
    self.read_flags()
    # be consistent in populating srcaddr/dstaddr even when deprecated addrs used
    if ('srcipid' in self.flags) and ('srcaddr' not in self.flags):
      self.flags['srcaddr'] = self.flags['srcipid']
    if ('dstipid' in self.flags) and ('dstaddr' not in self.flags):
      self.flags['dstaddr'] = self.flags['dstipid']
    if self.verbose:
      print "WcycleID:", self.wcycleid, "ListID:",  self.listid, \
            "CycleID:", self.cycleid, "Start:", self.start
      print "Flags:", self.flags

class WartsCycleStop(WartsBaseObject):
  def __init__(self, data, verbose=False):
    super(WartsCycleStop, self).__init__(obj_type['CYCLESTOP'], verbose)
    self.data = data
    (self.cycleid, self.stop) = struct.unpack('!II', data[:8])
    if self.verbose:
      print "CycleID:", self.cycleid, "Stop:", self.stop


class WartsPing(WartsBaseObject):
  def __init__(self, data, refs=None, verbose=False):
    super(WartsPing, self).__init__(obj_type['PING'], verbose)
    if refs:
      self.update_ref(refs)
    self.data = data
    self.flagdata = data
    self.hops = []
    self.flag_defines = [
     ('listid', unpack_uint32_t),
     ('cycleid', unpack_uint32_t),
     ('srcipid', read_referenced_address),
     ('dstipid', read_referenced_address),
     ('timeval', read_timeval),
     ('stopreas', unpack_uint8_t),
     ('stopdata', unpack_uint8_t),
     ('datalen', unpack_uint16_t),
     ('data', unpack_uint8_t),
     ('pcount', unpack_uint16_t),
     ('size', unpack_uint16_t),
     ('wait', unpack_uint8_t),
     ('ttl', unpack_uint8_t),
     ('rcount', unpack_uint16_t),
     ('psent', unpack_uint16_t),
     ('method', unpack_uint8_t),
     ('sport', unpack_uint16_t),
     ('dport', unpack_uint16_t),
     ('userid', unpack_uint32_t),
     ('srcaddr', self.unpack_address),
     ('dstaddr', self.unpack_address),
     ('flags', unpack_uint8_t),
     ('tos', unpack_uint8_t),
     ('tsps', self.unpack_address),
     ('icmpsum', unpack_uint16_t),
     ('pmtu', unpack_uint16_t),
     ('timeout', unpack_uint8_t),
     ('waitus', unpack_uint32_t),
    ]
    flag_bytes = self.read_flags()
    self.records = unpack_uint16_t(data[flag_bytes:])[0]
    if self.verbose:
      print "Ping Params:", self.flags
    offset = flag_bytes+2 
    for record in range(self.records):
      w = WartsPingReply(data[offset:], self.referenced_address, self.verbose)
      self.hops.append(w.flags)
      offset+=w.flag_bytes
      if self.verbose: print "Reply %d: %s" % (record+1, w.flags)


class WartsPingReply(WartsBaseObject):
  def __init__(self, data, refs, verbose=False):
    super(WartsPingReply, self).__init__(obj_type['PING'], verbose)
    self.update_ref(refs)
    self.flagdata = data
    self.flag_defines = [
     ('dstipid', read_referenced_address),
     ('flags', unpack_uint8_t),
     ('replyttl', unpack_uint8_t),
     ('replysize', unpack_uint16_t),
     ('icmp', unpack_uint16_t),
     ('rtt', unpack_uint32_t),
     ('probeid', unpack_uint16_t),
     ('replyipid', unpack_uint16_t),
     ('probeipid', unpack_uint16_t),
     ('replyproto', unpack_uint8_t),
     ('tcpflags', unpack_uint8_t),
     ('addr', self.unpack_address),
     ('v4rr', self.unpack_address),
     ('v4ts', self.unpack_address),
     ('replyipid32', unpack_uint32_t),
     ('tx', read_timeval),
     ('tsreply', unpack_uint32_t), # broken; should read 12B
    ]
    self.flag_bytes = self.read_flags()


class WartsTrace(WartsBaseObject):
  def __init__(self, data, refs=None, verbose=False):
    super(WartsTrace, self).__init__(obj_type['TRACE'], verbose)
    if refs:
      self.update_ref(refs)
    self.data = data
    self.flagdata = data
    self.hops = []
    self.flag_defines = [
     ('listid', unpack_uint32_t),
     ('cycleid', unpack_uint32_t),
     ('srcipid', self.read_referenced_address),
     ('dstipid', self.read_referenced_address),
     ('timeval', read_timeval),
     ('stopreas', unpack_uint8_t),
     ('stopdata', unpack_uint8_t),
     ('traceflg', unpack_uint8_t),
     ('attempts', unpack_uint8_t),
     ('hoplimit', unpack_uint8_t),
     ('tracetyp', unpack_uint8_t),
     ('probesiz', unpack_uint16_t),
     ('srcport', unpack_uint16_t),
     ('dstport', unpack_uint16_t),
     ('firsttl', unpack_uint8_t),
     ('iptos', unpack_uint8_t),
     ('timeout', unpack_uint8_t),
     ('loops', unpack_uint8_t),
     ('probehop', unpack_uint16_t),
     ('gaplimit', unpack_uint8_t),
     ('gaprch', unpack_uint8_t),
     ('loopfnd', unpack_uint8_t),
     ('probesent', unpack_uint16_t),
     ('minwait', unpack_uint8_t),
     ('confid', unpack_uint8_t),
     ('srcaddr', self.unpack_address),
     ('dstaddr', self.unpack_address),
     ('usrid', unpack_uint32_t),
    ]
    flag_bytes = self.read_flags()
    self.records = unpack_uint16_t(data[flag_bytes:])[0]
    if self.verbose:
      print "Flags:", self.flags
      print "Hops recorded:", self.records
    offset = flag_bytes+2 
    for record in range(self.records):
      w = WartsTraceHop(data[offset:], self.referenced_address, self.verbose)
      self.hops.append(w.flags)
      offset+=w.flag_bytes

class WartsTraceHop(WartsBaseObject):
  def __init__(self, data, refs, verbose=False):
    super(WartsTraceHop, self).__init__(obj_type['TRACE'], verbose)
    self.update_ref(refs)
    self.flagdata = data
    self.flag_defines = [
     ('addrid', self.read_referenced_address),
     ('probettl', unpack_uint8_t),
     ('replyttl', unpack_uint8_t),
     ('hopflags', unpack_uint8_t),
     ('probeid', unpack_uint8_t),
     ('rtt', unpack_uint32_t),
     ('icmp', unpack_uint16_t),       # type, code
     ('probesize', unpack_uint16_t),
     ('replysize', unpack_uint16_t),
     ('ipid', unpack_uint16_t),
     ('tos', unpack_uint8_t),
     ('mtu', unpack_uint16_t),
     ('qlen', unpack_uint16_t),
     ('qttl', unpack_uint8_t),
     ('tcpflags', unpack_uint8_t),
     ('qtos', unpack_uint8_t),
     ('icmpext', self.read_icmpext),
     ('addr', self.unpack_address),
     ('tx', read_timeval),
    ]
    self.flag_bytes = self.read_flags()
    if ('addrid' in self.flags) and ('addr' not in self.flags):
      self.flags['addr'] = self.flags['addrid']
    # IPID flag not set if IPID is zero
    if ('ipid' not in self.flags):
      self.flags['ipid'] = 0
    # the quoted TTL is assumed to be 1 unless the q-ttl flag is set
    if ('qttl' not in self.flags):
      self.flags['qttl'] = 1 
    # the 2B icmp field encodes type (1B) and code (1B).  decode.
    if ('icmp' in self.flags):
      self.flags['icmp-type'] = self.flags['icmp'] >> 8
      self.flags['icmp-code'] = self.flags['icmp'] & 0xFF
      del self.flags['icmp']
    if self.verbose:
      print "\t", self.flags

  @staticmethod
  # copied blindly/stupidly from scamper/scamper_icmpext.h
  def parse_mpls_icmpext(ie):
    u32 = struct.unpack('I', ie)[0]
    b0 = (u32 >> 0) & 0xFF
    b1 = (u32 >> 8) & 0xFF
    b2 = (u32 >> 16) & 0xFF
    b3 = (u32 >> 24) & 0xFF
    mpls_s = b2 & 0x01
    #print "MPLS_S:", mpls_s
    mpls_ttl = b3
    #print "MPLS_TTL:", mpls_ttl
    mpls_exp = (b2 >> 1) & 0x07
    #print "MPLS_EXP:", mpls_exp
    mpls_label = (b0 << 12) + (b1 << 4) + ((b2 >> 4) & 0xFF)
    #print "MPLS_Label:", mpls_label
    extension = "mpls ext ttl: %d, s: %d, exp: %d, label: %d" %  (mpls_ttl, mpls_s, mpls_exp, mpls_label)
    return extension

  @staticmethod
  def read_icmpext(b):
    """ read ICMP extension header """
    current_byte = 0
    (tot_len, bytes_read) = unpack_uint16_t(b[current_byte:current_byte+2])
    ret_string = ""
    #print "ICMP Extension Total Len:", tot_len
    current_byte+=bytes_read
    remaining = tot_len
    while remaining > 0:
      (ie_dl, bytes_read) = unpack_uint16_t(b[current_byte:current_byte+2])  # data length
      current_byte+=bytes_read
      #print "data len:", ie_dl
      (ie_cn, bytes_read) = unpack_uint8_t(b[current_byte:current_byte+1])  # class number
      current_byte+=bytes_read
      #print "class num:", ie_cn
      (ie_ct, bytes_read) = unpack_uint8_t(b[current_byte:current_byte+1])  # class type
      current_byte+=bytes_read
      #print "class type:", ie_ct
      # is MPLS?
      if ie_cn == 1 and ie_ct == 1:
        ie_dl_read = ie_dl
        while ie_dl_read >= 4:
          buf = b[current_byte:current_byte+4]
          current_byte+=4
          ie_dl_read-=4
          ret_string += WartsTraceHop.parse_mpls_icmpext(buf) + "\n"
      # we don't understand this type.  return a hexdump.
      else:
        buf = b[current_byte:current_byte+ie_dl]
        current_byte+=ie_dl
        ret_string += "buf: " + hexdump(buf)
      remaining = remaining - 4 - ie_dl
    return (ret_string, tot_len+2)


class WartsReader(object):
  def __init__(self, wartsfile, verbose=False):
    self.address_ref = dict()
    self.verbose = verbose
    # Auto-detect if warts file is using deprecated, type=5 addresses
    self.deprecated_addresses = False
    self.wartsfile = wartsfile
    self.warts_open(self.wartsfile)

  def warts_open(self, infile):
    self.fd = None
    # try reading as a bz2 file
    try:
      self.fd = bz2.BZ2File(infile, 'rb')
      self.fd.read(1)
      self.fd = bz2.BZ2File(infile, 'rb')
      return self.fd
    except IOError, e:
      pass
    # try reading as a gzip file
    try:
      self.fd = gzip.open(infile, 'rb')
      self.fd.read(1)
      self.fd = gzip.open(infile, 'rb')
      return self.fd
    except IOError, e:
      pass
    self.fd = open(infile, 'rb')
    return self.fd

  def next(self):
    while True:
      obj = self.next_object()
      if not obj: 
        return (False, False)
      if (obj.typ == obj_type['TRACE']) or (obj.typ == obj_type['PING']):
        return (obj.flags, obj.hops)

  def next_object(self):
    # read warts object header 
    self.header = self.fd.read(8)
    # sanity check
    if len(self.header) != 8:
      return None
    (magic, typ, length) = struct.unpack('!HHI', self.header)
    if self.verbose:
      print "Magic: %02X Obj: %02X Len: %02x" % (magic, typ, length)
    assert(magic == obj_type['MAGIC'])
    # read remainder of object
    data = self.fd.read(length)
    if typ == obj_type['LIST']:
      return WartsList(data, verbose=self.verbose)
    elif typ == obj_type['CYCLESTART']:
      return WartsCycle(data, verbose=self.verbose)
    elif typ == obj_type['CYCLESTOP']:
      return WartsCycleStop(data, verbose=self.verbose)
    elif typ == obj_type['CYCLE']:
      return WartsCycle(data, verbose=self.verbose)
    elif typ == obj_type['TRACE']:
      return WartsTrace(data, refs=self.address_ref, verbose=self.verbose)
    elif typ == obj_type['PING']:
      return WartsPing(data, refs=self.address_ref, verbose=self.verbose)
    elif typ == obj_type['ADDRESS']:
      self.deprecated_addresses = True
      wd = WartsDeprecatedAddress(data, verbose=self.verbose)
      addr_id = len(self.address_ref) + 1
      # "reader..can sanity check the ID number it determines by comparing
      #  the lower 8 bits of the computed ID with the ID embedded in the record"
      assert (addr_id % 255 == wd.id)
      self.address_ref[addr_id] = wd.addr 
      return wd
    else:
      print "Unsupported object: %02x Len: %d" % (typ, length)
      sys.exit(-1)


if __name__ == "__main__":
  assert len(sys.argv) == 2
  w = WartsReader(sys.argv[1], verbose=True)
  while True:
    (flags, hops) = w.next()
    if flags == False: break
