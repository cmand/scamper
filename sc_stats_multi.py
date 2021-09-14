#!/usr/bin/env python
# 
# Program:      $Id: $
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  Multiprocessor version of sc_stats
#
import sys, os
import time
from sc_stats import WartsStats
from multiprocessing import Pool, Manager, Lock

def init():
  global results, lock, dsts, ints, edges
  manager = Manager()
  lock = manager.Lock()
  results = manager.dict()
  results['files'] = 0
  results['probes'] = 0
  results['tvalmax'] = 0
  results['tvalmin'] = 9999999999
  dsts = manager.dict()
  ints = manager.dict()
  edges = manager.dict()

def dictadd(d,k,v=1):
  if k not in d:
    d[k] = 0
  d[k]+=v

def doone(infile, _verbose=False):
  print("Doing:", infile, file=sys.stderr)
  w = WartsStats(infile, verbose=_verbose)
  (one_dsts, one_ints, one_edges, cnt) = w.stats(verbose=_verbose)
  with lock:
    print("assimilating", infile, file=sys.stderr)
    results['files']+=1
    results['probes']+=cnt
    if w.ts_end > results['tvalmax']: results['tvalmax'] = w.ts_end
    if w.ts_begin < results['tvalmin']: results['tvalmin'] = w.ts_begin
  with lock:
    for i in one_dsts:
      dictadd(dsts, i)
  with lock:
    for i in one_ints:
      dictadd(ints, i)
  with lock:
    for i in one_edges:
      dictadd(edges, i)
    print("done assimilating", infile, file=sys.stderr)

if __name__ == "__main__":
  assert len(sys.argv) == 2
  indir = sys.argv[1]
  wartsfiles = []
  if os.path.isdir(indir):
    for root, subdirs, files in os.walk(indir):
      for filename in sorted(files):
        wartsfile = os.path.join(root, filename)
        if wartsfile.find('.warts') != -1:
          wartsfiles.append(wartsfile)
  else:
    print("%s is not a directory." % indir, file=sys.stderr)
    sys.exit(-1)

  init()
  pool = Pool()
  pool.map(doone, wartsfiles)
  pool.close()
  pool.join()
  print("Wartsfiles parsed: %d" % results['files'])
  print("Traces executed: %d" % results['probes'])
  print("Unique targets: %d" % (len(dsts)))
  print("Interfaces discovered: %d" % (len(ints)))
  print("Edges discovered: %d" % (len(edges)))
  print("Trace start: %s end: %s (%2.6f sec)" % \
    (WartsStats.epochtostr(results['tvalmin']), 
     WartsStats.epochtostr(results['tvalmax']),
     results['tvalmax'] - results['tvalmin']))
