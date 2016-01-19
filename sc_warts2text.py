#!/usr/bin/env python
#
# Program:      $Id: $ 
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  Replicate output of scamper's sc_warts2text
 
import sys
from sc_stats import WartsStats

if __name__ == "__main__":
  assert len(sys.argv) == 2

  w = WartsStats(sys.argv[1], verbose=False)
  while True:
    try:
      (flags, ips, rtts, meta) = w.next_trace()
      if flags == None: break
      print "traceroute from %s to %s" % (flags['srcaddr'], flags['dstaddr'])
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
      print "** Error:", e
      sys.exit(-1)
