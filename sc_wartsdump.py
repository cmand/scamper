#!/usr/bin/env python
# 
# Program:      $Id: sc_wartsdump.py 1551 2015-02-11 14:14:09Z rbeverly $
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  Parse a binary warts capture according to warts.5
#
import struct
import socket
import gzip
import sys

address_ref = dict()
verbose = True
# Auto-detect if warts file is using deprecated, type=5 addresses
deprecated_addresses = False

def read_header(f):
  """ read warts object header """
  buf = f.read(8)
  if len(buf) != 8:
    return (-1, -1)
  (magic, obj, length) = struct.unpack('!HHI', buf)
  if (magic != 0x1205):
    print "Magic: %02X Obj: %02X Len: %02x" % (magic, obj, length)
    assert False
  return (obj, length)

def more_flags(b):
  """ Is high order bit set on flag byte? """
  return (b & 0x80 == 0x80)

def hexdump(buf):
  return ''.join('{:02x}'.format(ord(x)) for x in buf)
  
def read_uint8_t(f):
  return (struct.unpack('B', f.read(1)))[0]

def read_uint16_t(f):
  return (struct.unpack('!H', f.read(2)))[0]

def read_uint32_t(f):
  return (struct.unpack('!I', f.read(4)))[0]

def read_timeval(f):
  sec = read_uint32_t(f)
  usec = read_uint32_t(f)
  return (sec + usec/1000000.0)

def read_address(f):
  """ read a warts-style ip/mac address """
  length = read_uint8_t(f)
  addr = 0
  typ = 0
  # an embedded (non-referenced) address
  if length != 0:
    typ = read_uint8_t(f)
    addr = f.read(length)
    addr_id = len(address_ref)
    address_ref[addr_id] = addr 
  # a referenced address
  else:
    addr_id = read_uint32_t(f)
    assert (addr_id in address_ref)
    addr = address_ref[addr_id]
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

def read_referenced_address(f):
  """ Resolve a warts deprecated (type 5) style referenced address """
  addr_id = read_uint32_t(f)
  assert (addr_id in address_ref)
  addr = address_ref[addr_id]
  return addr

def read_old_address(f):
  """ Read a warts deprecated (type 5) style referenced address """
  # deprecated address references start at 1
  addr_id = len(address_ref) + 1
  id_mod = read_uint8_t(f)
  typ = read_uint8_t(f)
  # "reader...can sanity check the ID number it determines by comparing the
  # lower 8 bits of the computed ID with the ID that is embedded in the record"
  assert(addr_id % 255 == id_mod)
  if typ == 0x01:
    addr = f.read(4)
    quad = socket.inet_ntop(socket.AF_INET, addr) 
  elif typ == 0x02:
    addr = f.read(16)
    quad = socket.inet_ntop(socket.AF_INET6, addr) 
  else:
    print "Addr type:", typ, "not implemented"
    assert False
  address_ref[addr_id] = quad
  #print "Address ID:", addr_id, "->", quad
    
def read_icmpext(f):
  """ read ICMP extension header """
  l = read_uint16_t(f)
  ic = read_uint8_t(f)
  it = read_uint8_t(f)
  buf = f.read(l-2)
  return "class: " + str(ic) + " type: " + str(it) + " buf: " + hexdump(buf)

def read_string(f):
  """ read a null terminated string """
  s = ''
  while True:
    b = f.read(1)
    if len(b) != 1: break
    if ord(b) == 0x00: break
    s += b
  return s

def bit_set(b, i):
  """ Warts flag magic: is the i'th bit of byte b set to 1? """
  return ( (b >> (i-1)) & 0x01 == 0x01)

def read_flags(f, flag_defines):
  """ Warts flag magic. """
  flags_set = []
  while True:
    flag = read_uint8_t(f)
    #print "FLAG: %02X" % flag
    flags_set += [bit_set(flag, i) for i in range(1,8)]
    if not more_flags(flag): break
  flags = dict()
  if flag > 0 or len(flags_set) > 8:
    paramlen = read_uint16_t(f)
    #print "PARAMLEN:", paramlen
    for i in range(len(flags_set)):
      if (flags_set[i]):
        read_cb = flag_defines[i][1]
        val = read_cb(f)
        #print "Flag %d: %s %s" % (i+1, flag_defines[i][0], val)
        flags[flag_defines[i][0]] = val
  return flags

def read_trace(f):
  # deprecated (type 5) referenced addresses are trace-global
  if not deprecated_addresses:
    address_ref.clear()
  hops = []
  flags = read_flags(f, trace_flags)
  # be consistent in populating srcaddr/dstaddr even when deprecated addrs used
  if ('srcipid' in flags) and ('srcaddr' not in flags):
    flags['srcaddr'] = flags['srcipid']
  if ('dstipid' in flags) and ('dstaddr' not in flags):
    flags['dstaddr'] = flags['dstipid']
  if verbose: print "Flags:", flags
  records = read_uint16_t(f)
  if verbose: print "Hops recorded:", records
  for record in range(records):
    hflags = read_flags(f, hop_flags)
    if ('addrid' in hflags) and ('addr' not in hflags):
      hflags['addr'] = hflags['addrid']
    # IPID flag not set if IPID is zero
    if ('ipid' not in hflags):
      hflags['ipid'] = 0
    # the 2B icmp field encodes type (1B) and code (1B).  decode.
    if ('icmp' in hflags):
      hflags['icmp-type'] = hflags['icmp'] >> 8
      hflags['icmp-code'] = hflags['icmp'] & 0xFF
      del hflags['icmp']
    hops.append(hflags)
    if verbose: print "\t", hflags
  end = read_uint16_t(f)
  assert (end == 0)
  return (flags, hops)

def read_list(f):
  wlistid = read_uint32_t(f)
  listid = read_uint32_t(f)
  lname = read_string(f)
  flags = read_flags(f, list_flags)
  if verbose:
    print "ListID:", listid, "Name:", lname
    print "Flags:", flags

def read_cycle(f):
  wcycleid = read_uint32_t(f)
  listid = read_uint32_t(f)
  cycleid = read_uint32_t(f)
  start = read_uint32_t(f)
  flags = read_flags(f, cycle_flags)
  if verbose:
    print "ListID:", listid, "CycleID:", cycleid, "Start:", start
    print "Flags:", flags

def read_cycle_stop(f):
  wcycleid = read_uint32_t(f)
  stop = read_uint32_t(f)
  flags = read_flags(f, cycle_flags)
  if verbose:
    print "WCycleID:", wcycleid, "Stop:", stop
    print "Flags:", flags

def warts_open(infile):
  fd = None
  # try reading as a gzip file first
  try:
    fd = gzip.open(infile, 'rb')
    fd.read(1)
    fd= gzip.open(infile, 'rb')
  except IOError, e:
    fd = open(infile, 'rb')
  return fd

def warts_next(fd):
  global deprecated_addresses
  while True:
    (obj, length) = read_header(fd)
    if obj == -1: return (False, False)
    #print "Object: %02x Len: %d" % (obj, length)
    if obj == 0x01: read_list(fd)
    elif obj == 0x02: read_cycle(fd)
    elif obj == 0x03: read_cycle(fd)
    elif obj == 0x04: read_cycle_stop(fd)
    elif obj == 0x05: 
      deprecated_addresses = True
      read_old_address(fd)
    elif obj == 0x06: 
      return read_trace(fd)
    else: 
      assert False

# For each object, define a list of optional variables that may be
# in the record (dependent on flags indicator) and the callback 
# to read the variable
list_flags = [
 ('description', read_string),
 ('monitor', read_string),
]

cycle_flags = [
 ('stoptime', read_uint32_t),
 ('hostname', read_string),
]

trace_flags = [
 ('listid', read_uint32_t),
 ('cycleid', read_uint32_t),
 ('srcipid', read_referenced_address),
 ('dstipid', read_referenced_address),
 ('timeval', read_timeval),
 ('stopreas', read_uint8_t),
 ('stopdata', read_uint8_t),
 ('traceflg', read_uint8_t),
 ('attempts', read_uint8_t),
 ('hoplimit', read_uint8_t),
 ('tracetyp', read_uint8_t),
 ('probesiz', read_uint16_t),
 ('srcport', read_uint16_t),
 ('dstport', read_uint16_t),
 ('firsttl', read_uint8_t),
 ('iptos', read_uint8_t),
 ('timeout', read_uint8_t),
 ('loops', read_uint8_t),
 ('probehop', read_uint16_t),
 ('gaplimit', read_uint8_t),
 ('gaprch', read_uint8_t),
 ('loopfnd', read_uint8_t),
 ('probesent', read_uint16_t),
 ('minwait', read_uint8_t),
 ('confid', read_uint8_t),
 ('srcaddr', read_address),
 ('dstaddr', read_address),
 ('usrid', read_uint32_t),
]

hop_flags = [
 ('addrid', read_referenced_address),
 ('probettl', read_uint8_t),
 ('replyttl', read_uint8_t),
 ('hopflags', read_uint8_t),
 ('probeid', read_uint8_t),
 ('rtt', read_uint32_t),
 ('icmp', read_uint16_t),       # type, code
 ('probesize', read_uint16_t),
 ('replysize', read_uint16_t),
 ('ipid', read_uint16_t),
 ('tos', read_uint8_t),
 ('mtu', read_uint16_t),
 ('quotlen', read_uint16_t),
 ('quotttl', read_uint8_t),
 ('tcpflags', read_uint8_t),
 ('quottos', read_uint8_t),
 ('icmpext', read_icmpext),
 ('addr', read_address),
]


if __name__ == "__main__":
  assert len(sys.argv) == 2
  f = warts_open(sys.argv[1])
  while True:
    (flags, hops) = warts_next(f)
    if flags == False: break

