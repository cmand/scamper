#!/usr/bin/env python
#
# Program:      $Id: $ 
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  Replicate output of scamper's sc_warts2text
 
import sys
from sc_stats import WartsStats, basic, obj_type

def print_trace(flags, ips, rtts, meta):
  print("traceroute from %s to %s" % (flags['srcaddr'], flags['dstaddr']))
  for i, ip in enumerate(ips):
    ttl = i+1
    print("%2d  %s" % (ttl, ip), end=' ')
    if ttl in rtts: 
      print(" %2.3f ms" % (rtts[ttl]), end=' ')
    if ttl in meta:
      for v in meta[ttl]:  
        print("%s" % (v), end=' ')
    print()

def print_ping(flags, responses):
  rtts = []
  print("ping %s to %s: %d byte packets" % (flags['srcaddr'], flags['dstaddr'], flags['size']))
  rcount = set()
  for response in responses:
    rcount.add(response['probeid'])
    rtt = response['rtt']/1000.0
    rtts.append(rtt)
    print("%d bytes from %s, seq=%d ttl=%d time=%3.3f ms" % \
      (response['replysize'], response['addr'], response['probeid'],
       response['replyttl'], rtt))
  print("--- %s ping statistics ---" % flags['dstaddr'])
  loss = 100.0 - (len(rcount) * 100.0 / flags['psent'])
  print("%d packets transmitted, %d packets received, %d%% packet loss" % \
    (flags['psent'], len(rcount), loss)) 
  if len(rcount) > 0:
    print("round-trip min/avg/max/stddev = %2.3f/%2.3f/%2.3f/%2.3f ms" % \
      basic(rtts))

if __name__ == "__main__":
  assert len(sys.argv) >= 2
  target = None
  if len(sys.argv) == 3: target = sys.argv[2]

  w = WartsStats(sys.argv[1], verbose=False)
  while True:
    try:
      (typ, data) = next(w) 
      if typ == None: 
        break
      elif typ == obj_type['TRACE']: 
        (flags, ips, rtts, meta) = data
        if target and target != flags['dstaddr']: continue
        print_trace(flags, ips, rtts, meta)
      elif typ == obj_type['PING']: 
        (flags, responses) = data
        if target and target != flags['dstaddr']: continue
        print_ping(flags, responses)
    except Exception as e:
      print("Flags:", flags)
      print("** Error:", e)
      sys.exit(-1)
