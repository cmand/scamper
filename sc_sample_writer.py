#!/usr/bin/env python
# Program:      $Id: $
# Author:       Robert Beverly <rbeverly@nps.edu>
# Description:  Example use of sc_warts_writer library.
#
import sys
import time
from sc_warts_writer import WartsWriter, WartsTrace

if __name__ == "__main__":
    assert len(sys.argv) == 2

    now = time.time()
    w = WartsWriter(sys.argv[1])
    w.write_list(1, 1, "sc_sample_writer demo")
    w.write_cycle(1, 1, 1, now)
    tr = WartsTrace()
    tr.add(
        {
            "listid": 1,
            "srcport": 1234,
            "dstport": 80,
            "srcaddr": "1.2.3.4",
            "dstaddr": "5.6.7.8",
            "attempts": 2,
            "tracetyp": 2,
            "probehop": 7,
            "probesent": 5,
            "firsttl": 4,
            "timeval": now + 1,
        }
    )

    # hopflags (SCAMPER_TRACE_HOP_FLAG_REPLY_TTL)
    reply = {
        "addr": "4.4.4.4",
        "rtt": 23456,
        "ipid": 1234,
        "probesize": 60,
        "replysize": 54,
        "probettl": 4,
        "replyttl": 60,
        "tos": 0,
        "icmp": 4,
        "hopflags": 0x10,
    }
    tr.add_reply(reply)
    reply = {
        "addr": "6.6.6.6",
        "rtt": 834567,
        "ipid": 1234,
        "probesize": 60,
        "replysize": 54,
        "probettl": 6,
        "replyttl": 58,
        "tos": 0,
        "icmp": 4,
        "hopflags": 0x10,
    }
    tr.add_reply(reply)
    w.write_object(tr)

    # finish
    w.write_cycle_stop(1, now + 10)
