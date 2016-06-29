# Scamper Tools

Scamper is a scalable, efficient, and feature-rich Internet packet
prober from CAIDA (http://www.caida.org/tools/measurement/scamper/).

Scamper is written in C and stores data in a binary "warts" format.

These tools replicate the functionality of scamper's utilities by
providing native python implementations.  The following files 
are included:

* sc_warts.py:         warts file processing library
* sc_stats.py:         extends warts class to provide stats
* sc_warts2text.py:     parse warts file, produce text output
* sc_wartsdump.py:     parse binary warts files
* sc_analysis_dump.py: covert scamper traces to easily parsed text
* sc_sample.py:        sample python using warts class (for developers)
* sc_attach.py:        interact with scamper over control socket
