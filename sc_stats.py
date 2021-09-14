#!/usr/bin/env python
# 
# Program:      $Id: $
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  More advanced stats/processing routines for wartsfiles.
#               Extends base WartsReader class.
#
import sys
import time
from math import sqrt
from sc_warts import WartsReader, obj_type

def basic(vals):
  n = len(vals)/1.0
  mean = sum(vals)/n
  ss = sum((x-mean)**2 for x in vals)
  stddev = 0.0
  if n > 1:
    stddev = sqrt(ss/n)
  return (min(vals), mean, max(vals), stddev)

class WartsStats(WartsReader):
  def __init__(self, wartsfile, verbose=False):
    super(WartsStats, self).__init__(wartsfile, verbose)
    self.ts_begin = 0
    self.ts_end = 0
    self.dests = set()  # Destinations / Targets
    self.ints = set()   # Interfaces
    self.edges = set()  # Edges
    self.cnt = 0

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
  def do_trace(self, obj):
    (flags, hops) = (obj.flags, obj.hops)

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
        elif hop['icmp-type'] == 3 and hop['icmp-code'] == 0:
          self.dict_append(meta, i, "!N")
        elif hop['icmp-type'] == 3 and hop['icmp-code'] == 13:
          self.dict_append(meta, i, "!X")
        elif hop['icmp-type'] == 3 and hop['icmp-code'] == 2:
          self.dict_append(meta, i, "!P")
#        elif hop['icmp-type'] == 3:
#          self.dict_append(meta, i, "<" + str(hop['icmp-code']) + ">")
    # add gapped hops
    if 'probehop' in flags:
      for q in range(i, flags['probehop']):
        ips.append("*")
    return (flags, ips, rtts, meta)

  def do_ping(self, obj):
    (flags, responses) = (obj.flags, obj.hops)
    return (flags, responses)

  def __next__(self):
    obj = None
    while True:
      obj = self.next_object()
      if not obj:
        return (None, None)
      elif obj.typ == obj_type['PING']:
        return (obj.typ, self.do_ping(obj))
      elif obj.typ == obj_type['TRACE']:
        return (obj.typ, self.do_trace(obj))

  @staticmethod
  def addhop(lasthop, hop, interfaces, edges, ignore_anon=True):
    interfaces.add(hop)
    if lasthop:
      # don't add edges to ourselves
      if lasthop == hop:
        return
      # don't add edges between anonymous hops
      if not (ignore_anon and (hop == '*' or lasthop == '*')):
        e1 = (lasthop, hop)
        e2 = (hop, lasthop)
        if (e1 not in edges) and (e2 not in edges):
          edges.add(e1)

  def stats(self, verbose=False, count=0):
    while True:
      (typ, data) = next(self)
      if typ == None: 
        break
      if typ != obj_type['TRACE']:
        continue
      (flags, ips, rtts, meta) = data
      if flags == None: break
      self.cnt+=1
      self.dests.add(flags['dstaddr'])
      lasthop = None
      for i, ip in enumerate(ips):
        self.addhop(lasthop, ip, self.ints, self.edges)
        lasthop = ip
      if verbose and (self.cnt % 1000 == 0):
        print(">> %s (traces:%d/dests:%d/ints:%d/edges:%d)" % \
          (self.wartsfile, self.cnt, len(self.dests), len(self.ints), len(self.edges)), file=sys.stderr)
      if self.cnt == count: break

  def dump(self):
    print("File: %s:" % self.wartsfile)
    print("\tProbes: %d" % self.cnt)
    print("\tUnique targets: %d" % (len(self.dests)))
    print("\tInterfaces discovered: %d" % (len(self.ints)))
    print("\tEdges discovered: %d" % (len(self.edges)))
    print("\tTrace start: %s end: %s (%2.6f sec)" % \
      (self.tsbegin(), self.tsend(), self.elapsed()))

if __name__ == "__main__":
  count = 0
  assert len(sys.argv) >= 2
  w1 = WartsStats(sys.argv[1], verbose=False)
  w1.stats(verbose=True, count=count) 
  if len(sys.argv) == 2:
    w1.dump()
  if len(sys.argv) == 3:
    w2 = WartsStats(sys.argv[2], verbose=False)
    w2.stats(verbose=True, count=count) 
    w1.dump()
    w2.dump()
    print("Trace comparison:")
    print("\tInterfaces in both %s and %s: %d" % (w1.wartsfile, w2.wartsfile, len(w1.ints & w2.ints)))
    print("\tInterfaces in %s not in %s: %d" % (w1.wartsfile, w2.wartsfile, len(w1.ints - w2.ints)))
    print("\tInterfaces in %s not in %s: %d" % (w2.wartsfile, w1.wartsfile, len(w2.ints - w1.ints)))
    print("\tEdges in both %s and %s: %d" % (w1.wartsfile, w2.wartsfile, len(w1.edges & w2.edges)))
    print("\tEdges in %s not in %s: %d" % (w1.wartsfile, w2.wartsfile, len(w1.edges - w2.edges)))
    print("\tEdges in %s not in %s: %d" % (w2.wartsfile, w1.wartsfile, len(w2.edges - w1.edges)))
