#!/usr/bin/env python
#
# Program:      $Id: $ 
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  Example use of sc_warts library.  
#               Counts the number of different destinations probed
#
import sys
from sc_warts import WartsReader

if __name__ == "__main__":
  assert len(sys.argv) == 2

  w = WartsReader(sys.argv[1], verbose=False)
  dsts = set()
  while True:
    (flags, hops) = next(w)
    if flags == False: break
    dsts.add(flags['dstaddr'])
  print("Found %d probed destinations in %s." % (len(dsts), sys.argv[1]))
