#!/usr/bin/env python
# 
# Program:      $Id: $
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  More advanced stats/processing routines for wartsfiles.
#               Extends base WartsReader class.
#
import sys
import time
from sc_warts import WartsReader

class WartsStats(WartsReader):
  def __init__(self, wartsfile, verbose=False):
    super(WartsStats, self).__init__(wartsfile, verbose)
    self.ts_begin = 0
    self.ts_end = 0

  """ Helper function """
  @staticmethod
  def dict_append(d,k,v):
    if (k not in d):
      d[k] = []
    d[k].append(v)

  @staticmethod
  def epochtostr(epoch):
    return time.strftime('%Y-%m-%d %H:%M:%S %Z', time.localtime(int(epoch)))

  def tsbegin(self):
    return self.epochtostr(self.ts_begin)

  def tsend(self):
    return self.epochtostr(self.ts_end)

  def elapsed(self):
    return self.ts_end - self.ts_begin


  """ Takes a list of warts hops from a WartsReader. Returns 
      sequential IP path list, along with a dictionary
      of RTTs and meta data (indexed by TTL) """
  def next_trace(self):
    (flags, hops) = self.next()
    if flags == False:
      return (None, None, None, None)

    ts = flags['timeval']
    if ts > self.ts_end: self.ts_end = ts
    if not self.ts_begin: self.ts_begin = ts
    if ts < self.ts_begin: self.ts_begin = ts

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
        self.dict_append(meta, i, " %2.3f ms" % (rtt)) 
      else:
        ips.append(addr)
        rtts[i] = rtt
      if 'icmp-type' in hop:
        if hop['icmp-type'] == 3 and hop['icmp-code'] == 1:
          self.dict_append(meta, i, "!H")
        if hop['icmp-type'] == 3 and hop['icmp-code'] == 0:
          self.dict_append(meta, i, "!N")
    return (flags, ips, rtts, meta)

  @staticmethod
  def addhop(lasthop, hop, interfaces, edges, ignore_anon=True):
    interfaces.add(hop)
    if lasthop:
      if not (ignore_anon and (hop == '*' or lasthop == '*')):
        e1 = (lasthop, hop)
        e2 = (hop, lasthop)
        if (e1 not in edges) and (e2 not in edges):
          edges.add(e1)

  def stats(self, verbose=False, count=0):
    dests = set()  # Destinations / Targets
    ints = set()   # Interfaces
    edges = set()  # Edges
    cnt = 0
    while True:
      (flags, ips, rtts, meta) = self.next_trace()
      if flags == None: break
      cnt+=1
      dests.add(flags['dstaddr'])
      lasthop = None
      for i, ip in enumerate(ips):
        self.addhop(lasthop, ip, ints, edges)
        lasthop = ip
      if verbose and (cnt % 1000 == 0):
        print >> sys.stderr, ">> %s (traces:%d/dests:%d/ints:%d/edges:%d)" % \
          (self.wartsfile, cnt, len(dests), len(ints), len(edges))
      if cnt == count: break
    return (dests, ints, edges)

if __name__ == "__main__":
  assert len(sys.argv) == 2
  w = WartsStats(sys.argv[1], verbose=False)
  (dests, ints, edges) = w.stats(verbose=True)
  print "Probed targets: %d" % (len(dests))
  print "Interfaces discovered: %d" % (len(ints))
  print "Edges discovered: %d" % (len(edges))
  print "Trace start: %s end: %s (%2.6f sec)" % \
    (w.tsbegin(), w.tsend(), w.elapsed())
