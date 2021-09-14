#!/usr/bin/env python
#
# Program:      $Id: sc_attach.py 1537 2015-02-06 21:53:51Z rbeverly $
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  Base class to interact with Scamper over its control socket 
#
import sys
from socket import *
from binascii import a2b_uu
from time import sleep
import threading
import select

class Scamper:
  def __init__(self, outfile, host='localhost', port=31337, verbose=False):
    self.server = (host, port)
    self.verbose = verbose
    try:
      self.fd_out = open(outfile, 'wb')
    except Exception as e:
      print("Couldn't open warts file:", e)
      sys.exit(-1)

  def __del__(self):
    print("Done.")
    if self.sfd:
      self.sfd.close()
    if self.fd_out:
      self.fd_out.close()
    #self.listener.join()

  @staticmethod
  def readline(sock):
    ret = ''
    while True:
      c = sock.recv(1)
      if c == '\n' or c == '':
        break
      else:
        ret +=c
    return ret

  @staticmethod
  def hexdump(buf):
    for i in range(len(buf)):
      print("%02X" % ord(buf[i]), end=' ')
    print()

  @staticmethod
  def rob_uu_decode(text):
    res = ''
    lines = text.strip().split('\n')
    for line in lines:
      decoded_line = a2b_uu(line) 
      res += decoded_line
    return res
 
  def connect(self):
    print("Connecting:", self.server)
    try:
      self.sfd = socket(AF_INET, SOCK_STREAM)
      self.sfd.connect(self.server) 
    except Exception as e:
      print("Error connecting:", e)
      sys.exit(-1)
    self.listener = threading.Thread(target=self.fetch_scamper_result)
    self.listener.start()
    # give thread time to startup before doing work
    sleep(1)

  def attach(self):
    self.sfd.send('ATTACH\n')

  def fetch_scamper_result(self):
    print("Listener.")
    self.timeouts = 0
    while True:
      if self.timeouts > 10:
        break
      fdready = select.select([self.sfd], [], [], 1)
      if len(fdready[0]) == 0:
        print("timeout.")
        self.timeouts+=1
        continue
      line = ''
      while True:
        line = Scamper.readline(self.sfd)
        if line.find('ERR') != -1:
          print("** error response:", line)
          raise Exception('shit, talk to rob')
        elif line.find('MORE') != -1:
          continue
        elif line.find('DATA') != -1:
          break
      cmds = line.strip().split()
      datalen = int(cmds[1])
      data = self.sfd.recv(datalen)  
      decoded_data = Scamper.rob_uu_decode(data) 
      if self.verbose:
        Scamper.hexdump(decoded_data)
      self.fd_out.write(decoded_data)
    return decoded_data

  def execute(self, cmd):
    self.sfd.send(cmd + '\n')

  def executeFile(self, fname):
    for line in open(fname):
      dst = line.strip()  
      #opts = '-P icmp-paris -w 10'
      opts = ''
      print("Tracing to:", dst)
      self.execute('trace ' + dst + ' ' + opts)

if __name__ == "__main__":
  scamper = Scamper('rob.warts', '10.10.10.1', 31337, verbose=True)
  scamper.connect()
  scamper.attach()
  scamper.execute('trace 10.10.10.221')
  #scamper.execute('trace 172.20.186.26')
  #scamper.executeFile('targets.dat')
  del scamper
  sys.exit(0)
