#!/usr/bin/env python
# 
# Program:      $Id: sc_analysis_dump.py 1551 2015-02-11 14:14:09Z rbeverly $
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  Parse a binary warts capture according to warts.5
#
import sys
from sc_warts import WartsReader

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

  print("\t".join(["T", flags['srcaddr'], flags['dstaddr']]), end=' ')
  print("\t".join([str(flags['listid']), str(flags['cycleid'])]), end=' ')
  print("\t" + str(int(flags['timeval'])), end=' ')
  # DestReplied, DestRTT, RequestTTL, ReplyTTL
  print("\t".join([dest_replied, dest_rtt, request_ttl, reply_ttl]), end=' ')
  # HaltReason/HaltReasonData
  if haltreason == 'none' or haltreason == 'completed': 
    print("\tS\t0", end=' ')
  elif haltreason == 'unreach':
    print("\tU\t" + str(flags['stopdata']), end=' ')
  elif haltreason == 'loop':
    print("\tL\t0", end=' ')
  elif haltreason == 'gaplimit':
    print("\tG\t0" + str(flags['stopdata']), end=' ')
  else:
    print("\t?\t0", end=' ')
  # PathComplete
  print("\t" + path_complete, end=' ')
  # PerHopData
  for hop in hops:
    print("\t" + ",".join([hop['addr'], str(hop['rtt']/1000.0), '1']), end=' ')
  print() 

if __name__ == "__main__":
  assert len(sys.argv) == 2
  w = WartsReader(sys.argv[1], verbose=False)
  while True:
    (flags, hops) = next(w)
    if flags == False: break
    trace_to_tod(flags, hops) 
