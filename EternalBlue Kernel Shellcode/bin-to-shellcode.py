#!/usr/bin/env python

import sys

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print "usage: %s file.bin\n" % (sys.argv[0],)
		sys.exit(0)

	shellcode = ""

	for b in open(sys.argv[1], "rb").read():
		shellcode += b.encode("hex")
		
	print shellcode