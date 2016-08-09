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
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  Parse a binary warts capture according to warts.5
#
import struct
import socket
from math import ceil
import sys

def pack_uint32_t(b):
  return (struct.pack('!I', b))

def pack_uint16_t(b):
  return (struct.pack('!H', b))

def pack_uint8_t(b):
  return (struct.pack('B', b))

def is_ipv6(addr):
  try: 
    socket.inet_pton(socket.AF_INET, addr)
    return False
  except socket.error, e:
    return True

def pack_referenced_address(addrid):
  return (struct.pack('!BI', 0, addrid))

def pack_unreferenced_address(addr):
  if is_ipv6(addr):
    buf = pack_uint8_t(16)
    buf += pack_uint8_t(0x02) # ipv6
    buf += socket.inet_pton(socket.AF_INET6, addr)
  else:
    buf = pack_uint8_t(4)
    buf += pack_uint8_t(0x01) # ipv4
    buf += socket.inet_pton(socket.AF_INET, addr)
  return buf

def pack_timestamp(val):
  sec = int(val)
  usec = (val - sec) * 1000000.0
  buf = pack_uint32_t(sec) + pack_uint32_t(usec)
  return buf

class WartsPing(object):
  def __init__(self):
    self.typ = 0x07
    self.buf = ""
    self.setflags = dict()
    self.referenced_addresses = dict()
    self.last_referenced_address_id = -1
    self.reply = None
    self.flags = [
     ('listid', pack_uint32_t),
     ('cycleid', pack_uint32_t),
     ('srcipid', None),
     ('dstipid', None),
     ('timeval', pack_timestamp),
     ('stopreas', pack_uint8_t),
     ('stopdata', pack_uint8_t),
     ('datalen', pack_uint16_t),
     ('data', pack_uint8_t),
     ('pcount', pack_uint16_t),
     ('size', pack_uint16_t),
     ('wait', pack_uint8_t),
     ('ttl', pack_uint8_t),
     ('rcount', pack_uint16_t),
     ('psent', pack_uint16_t),
     ('method', pack_uint8_t),
     ('sport', pack_uint16_t),
     ('dport', pack_uint16_t),
     ('userid', pack_uint32_t),
     ('srcaddr', self.pack_address),
     ('dstaddr', self.pack_address),
     ('flags', pack_uint8_t),
     ('tos', pack_uint8_t),
     ('tsps', None),
     ('icmpsum', pack_uint16_t),
     ('pmtu', pack_uint16_t),
     ('timeout', pack_uint8_t),
     ('waitus', pack_uint32_t),
    ]

  def reset(self):
    self.buf = ""
    self.setflags = dict()
    self.referenced_addresses = dict()
    self.last_referenced_address_id = -1
    if self.reply:
      del self.reply
      self.reply = None

  def finalize(self):
    self.buf += pack_uint16_t(self.reply.count)
    self.buf += self.reply.buf
    return self.buf

  def add_reply(self, flags):
    if not self.reply: 
      self.reply = WartsPingReply()
    self.reply.update_ref(self.referenced_addresses, self.last_referenced_address_id)
    self.reply.add(flags)
    self.reply.count+=1

  def update_ref(self, _referenced_address, _last_referenced_address_id):
    self.referenced_addresses = _referenced_address
    self.last_referenced_address_id = _last_referenced_address_id

  def add(self, flags):
    for flag in flags:
      self.setflags[flag] = flags[flag]  
    self.make_flags()

  def pack_address(self, addr):
    if addr in self.referenced_addresses:
      #print "returning RA", self.referenced_addresses[addr], "for:", addr
      return pack_referenced_address(self.referenced_addresses[addr])
    else:
      self.last_referenced_address_id+=1 
      #print "creating new addrid:", self.last_referenced_address_id, "for:", addr
      self.referenced_addresses[addr] = self.last_referenced_address_id
      return pack_unreferenced_address(addr)
 
  def make_flags(self):
    #print "total flags:", len(self.flags)
    num_flag_bytes = int(ceil(len(self.flags) / 7.0))
    #print "flag bytes:", num_flag_bytes
    flags = [0]*num_flag_bytes
    flag_buffer = ""
    for i in range(num_flag_bytes-1):
      flags[i] = 0x80
    for num, flag in enumerate(self.flags):
      (flag_name, flag_method) = flag
      if flag_name in self.setflags:
        block = num / 7
        flags[block] += 2**(num % 7) 
        b = flag_method(self.setflags[flag_name])
        hb = [hex(ord(z)) for z in b]
        #print "Writing Flag:", num, "name:", flag_name, "value:", self.setflags[flag_name], "bytes:", hb
        flag_buffer += b
    for b in flags:
      #print "Flag Byte:", hex(b)
      self.buf += pack_uint8_t(b)
    self.buf += pack_uint16_t(len(flag_buffer))
    self.buf += flag_buffer

 
class WartsPingReply(WartsPing):
  def __init__(self):
    super(WartsPingReply, self).__init__()
    self.count = 0
    self.flags = [
     ('dstipid', None),
     ('flags', pack_uint8_t),
     ('replyttl', pack_uint8_t),
     ('replysize', pack_uint16_t),
     ('icmp', pack_uint16_t),
     ('rtt', pack_uint32_t),
     ('probeid', pack_uint16_t),
     ('replyipid', pack_uint16_t),
     ('probeipid', pack_uint16_t),
     ('replyproto', pack_uint8_t),
     ('tcpflags', pack_uint8_t),
     ('addr', self.pack_address),
     ('v4rr', self.pack_address),
     ('v4ts', self.pack_address),
     ('replyipid32', pack_uint32_t),
     ('tx', pack_timestamp),
     ('tsreply', pack_uint32_t), # broken; should read 12B
    ]


class WartsWriter():
  def __init__(self, wartsfile, append=False, verbose=False):
    if not append:
      self.fd = open(wartsfile, 'wb')
    else:
      self.fd = open(wartsfile, 'ab')

  @staticmethod 
  def append_string(buf, s):
    return buf + s + '\0'
 
  def write_header(self, buf, typ):
    head = struct.pack('!HHI', 0x1205, typ, len(buf))
    self.fd.write(head + buf)
 
  def write_list(self, wlistid, listid, lname):
    content = struct.pack('!II', wlistid, listid)
    content = WartsWriter.append_string(content, lname)
    content += struct.pack('B', 0) # no flags
    self.write_header(content, 0x01)

  def write_cycle(self, wcycle, listid, cycleid, start):
    content = struct.pack('!IIII', wcycle, listid, cycleid, start)
    content += struct.pack('B', 0) # no flags
    self.write_header(content, 0x03)

  def write_object(self, obj):
    obj.finalize()
    head = struct.pack('!HHI', 0x1205, obj.typ, len(obj.buf))
    self.fd.write(head + obj.buf)
    obj.reset()
