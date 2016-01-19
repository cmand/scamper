#!/usr/bin/env python
#
# Program:      $Id: $ 
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  Replicate output of scamper's sc_warts2text
 
import sys
from sc_warts import WartsReader

""" Helper function """
def dict_append(d,k,v):
  if (k not in d):
    d[k] = []
  d[k].append(v)

""" Takes a list of warts hops from a WartsReader. Returns 
    sequential IP path list, along with a dictionary
    of RTTs and meta data (indexed by TTL) """
def proc_hops(hops):
  i = 0
  ips = []
  meta = dict()
  rtts = dict()
  for hop in hops:
    (ttl, rtt, addr) = (hop['probettl'], hop['rtt']/1000.0, hop['addr'])
    i+=1
    if i < ttl:
      diff = ttl - i 
      for k in range(diff):
        ips.append("*")
        i+=1
    if i > ttl:
      i-=1
      dict_append(meta, i, " %2.3f ms" % (rtt)) 
    else:
      ips.append(addr)
      rtts[i] = rtt
    if hop['icmp-type'] == 3 and hop['icmp-code'] == 1:
      dict_append(meta, i, "!H")
    if hop['icmp-type'] == 3 and hop['icmp-code'] == 0:
      dict_append(meta, i, "!N")
  return (ips, rtts, meta)


if __name__ == "__main__":
  assert len(sys.argv) == 2

  w = WartsReader(sys.argv[1], verbose=False)
  while True:
    (flags, hops) = w.next()
    if flags == False: break

    print "traceroute from %s to %s" % (flags['srcaddr'], flags['dstaddr'])
    try:
      (ips, rtts, meta) = proc_hops(hops)
      for i, ip in enumerate(ips):
        ttl = i+1
        print "%2d  %s" % (ttl, ip),
        if ttl in rtts: 
          print " %2.3f ms" % (rtts[ttl]),
        if ttl in meta:
          for v in meta[ttl]:  
            print "%s" % (v),
        print
    except Exception, e:
      print "Flags:", flags
      print "Hops:", hops 
      print "** Error:", e
      sys.exit(-1)
