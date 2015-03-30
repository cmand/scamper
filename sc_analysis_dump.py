#!/usr/bin/env python
# 
# Program:      $Id: sc_analysis_dump.py 1551 2015-02-11 14:14:09Z rbeverly $
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  Parse a binary warts capture according to warts.5
#
import struct
import socket
import gzip
import sys
import sc_wartsdump

scamper_stop_reasons = ['none', 'completed', 'unreach', 'icmp', 'loop', 'gaplimit', 'error', 'hoplimit', 'gss', 'halted']

def trace_to_tod(flags, hops):
  assert(flags['tracetyp'] == 4)
  # First, determine if destination replied.
  (path_complete, dest_replied, dest_rtt, request_ttl, reply_ttl) = ('I', 'N', '0', '0', '0')
  haltreason = scamper_stop_reasons[flags['stopreas']]
  if haltreason == 'none' or haltreason == 'completed':
    destination = hops.pop()
    path_complete = 'C'
    dest_replied = 'R'
    dest_rtt = str(destination['rtt']/1000.0)
    request_ttl = str(destination['probettl'])
    reply_ttl = str(destination['replyttl'])

  print "\t".join(["T", flags['srcaddr'], flags['dstaddr']]),
  print "\t".join([str(flags['listid']), str(flags['cycleid'])]),
  print "\t" + str(int(flags['timeval'])),
  # DestReplied, DestRTT, RequestTTL, ReplyTTL
  print "\t".join([dest_replied, dest_rtt, request_ttl, reply_ttl]),
  # HaltReason/HaltReasonData
  if haltreason == 'none' or haltreason == 'completed': 
    print "\tS\t0",
  elif haltreason == 'unreach':
    print "\tU\t" + str(flags['stopdata']),
  elif haltreason == 'loop':
    print "\tL\t0",
  elif haltreason == 'gaplimit':
    print "\tG\t0" + str(flags['stopdata']),
  else:
    print "\t?\t0",
  # PathComplete
  print "\t" + path_complete,
  # PerHopData
  for hop in hops:
    print "\t" + ",".join([hop['addr'], str(hop['rtt']/1000.0), '1']),
  print 

if __name__ == "__main__":
  assert len(sys.argv) == 2
  # try reading as a gzip file first
  try:
    f = gzip.open(sys.argv[1], 'rb')
    f.read(1)
    f = gzip.open(sys.argv[1], 'rb')
  except IOError, e:
    f = open(sys.argv[1], 'rb')
  while True:
    (obj, length) = sc_wartsdump.read_header(f)
    if obj == -1: break
    sc_wartsdump.verbose = False 
    #print "Object: %02x Len: %d" % (obj, length)
    if obj == 0x01: sc_wartsdump.read_list(f)
    elif obj == 0x02: sc_wartsdump.read_cycle(f)
    elif obj == 0x03: sc_wartsdump.read_cycle(f)
    elif obj == 0x04: sc_wartsdump.read_cycle_stop(f)
    elif obj == 0x05: sc_wartsdump.read_old_address(f)
    elif obj == 0x06: 
      (flags, hops) = sc_wartsdump.read_trace(f)
      trace_to_tod(flags, hops) 
    else: 
      assert False
