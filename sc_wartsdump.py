#!/usr/bin/env python
# 
# Program:      $Id: sc_wartsdump.py 1551 2015-02-11 14:14:09Z rbeverly $
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  Parse a binary warts capture according to warts.5
#
import sys
from sc_warts import WartsReader

if __name__ == "__main__":
  assert len(sys.argv) == 2

  w = WartsReader(sys.argv[1], verbose=True)
  while True:
    (flags, hops) = next(w)
    if flags == False: break
