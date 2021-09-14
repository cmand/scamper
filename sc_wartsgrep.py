#!/usr/bin/env python
# 
# Program:      $Id: sc_wartsgrep.py $
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  Create a new warts file containing only those entries we grep for
#
import sys
from sc_warts import WartsReader
from sc_warts_writer import *

def usage(prog):
  print("Usage: %s ip_dst in_warts_file out_wartsfile")
  sys.exit(-1)

if __name__ == "__main__":
  if len(sys.argv) != 4:
    usage(sys.argv[0])

  ip = sys.argv[1]
  r = WartsReader(sys.argv[2])
  w = WartsWriter(sys.argv[3])
  w.write_list(1,0,'sc_wartsgrep_output')
  w.write_cycle(1,1,1,0)
  p = WartsPing()
  while True:
    (flags, hops) = next(r)
    if flags == False: break
    if flags['dstaddr'] != ip: continue
    del flags['cycleid']
    p.add(flags)
    for hop in hops:
      p.add_reply(hop)
    w.write_object(p)
