#!/usr/bin/env python
#
# Program:      $Id: $ 
# Author:       Robert Beverly <rbeverly@nps.edu>
#               
import sys
from sc_warts import WartsReader

if __name__ == "__main__":
  assert len(sys.argv) == 2

  w = WartsReader(sys.argv[1], verbose=False)
  while True:
    (flags, hops) = w.next()
    if flags == False: break
    i = 0
    out = []
    for hop in hops:
      (ttl, rtt, addr) = (hop['probettl'], hop['rtt']/1000.0, hop['addr'])
      i+=1
      if i < ttl:
        diff = ttl - i 
        for k in range(diff):
          out.append("*")
          i+=1
      if i > ttl:
        i-=1
        out[i-1] += "  %2.3f ms" % (rtt)
      else:
        out.append("%s  %2.3f ms" % (addr, rtt))
      if hop['icmp-type'] == 3 and hop['icmp-code'] == 1:
        out[i-1] += " !H"
      if hop['icmp-type'] == 3 and hop['icmp-code'] == 0:
        out[i-1] += " !N"

    print "traceroute from %s to %s" % (flags['srcaddr'], flags['dstaddr'])
    for i, o in enumerate(out):
      print "%2d  %s" % (i+1, o)
