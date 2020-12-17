#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Markus Thilo'
__version__ = '0.8-20201217'
__license__ = 'GPL-3'

from lib.zeekstats import Zeek
from lib.iprunner import IPRunner
from lib.basicinout import CSVGenerator
from lib.netvis import NetVis
from argparse import ArgumentParser, FileType
from sys import stdout as StdOut
from sys import stderr as StdErr
from sys import exit as SysExit

ZEEK_NO_PORTS = ('z', 'zeek', 'zeek_no_ports')
ZEEK_PORTS = ('zp', 'zeek_ports')
IPRUNNER = ('i', 'ip', 'iprunner')
LIST = '''
z / zeek / zeek_no_ports:
	Display conn.log from ZEEK ignoring ports.

zp / zeek_ports:
	Display conn.log from ZEEK, differentiate by server ports (id.resp_p).
	For this no visualisation is available.

i / ip / iprunner:
	Display TSV file from IPRUNNER.
	For files created with -s or -g no visualisation is available.
'''

if __name__ == '__main__':	# start here if called as application
	argparser = ArgumentParser(description='Visualize netflow data')

	argparser.add_argument('-b', '--blacklist', nargs=1, type=FileType('rt'),
		help='File with blacklisted IP addresses', metavar='FILE'
	)
	argparser.add_argument('-c', '--noheadline', action='store_true',
		help='Give headlines = column names on CSV output'
	)
	argparser.add_argument('-g', '--grep', dest='grep',
		help='Target IP address', metavar='IP_ADDRESS/LINK',
		type=str
	)
	argparser.add_argument('-i', '--reverse', action='store_true',
		help='Reverse order on TSV output'
	)
	argparser.add_argument('-m', '--max', type=int,
		help='Maximum number of IP addresses to visualize', metavar='INTEGER'
	)
	argparser.add_argument('-r', '--readable', action='store_true',
		help='Give better readable sizes'
	)
	argparser.add_argument('-t', '--in', dest='filetype', default='z',
		help='Type of input an calculation - use -t l or -t list to get details', metavar='SWITCH'
	)
	argparser.add_argument('-u', '--unixtime', action='store_true',
		help='Unix timestamps (seconds and microseconds) on CSV output'
	)
	argparser.add_argument('-v', '--vis', action='store_true',
		help='Generate HTML/JavaScript for VISJS (default is TSV output)'
	)
	argparser.add_argument('-w', '--outfile', type=FileType('w'), default=StdOut,
		help='File to write', metavar='FILE'
	)
	argparser.add_argument('infiles', nargs='*', type=FileType('rt'),
		help='File(s) to read,', metavar='FILE'
	)
	args = argparser.parse_args()
	if args.filetype.lower() in ('l', 'list'):
		print(LIST)
		SysExit(0)
	if args.infiles == []:
		print('Error: At least one input file is required.', file=StdErr)
		SysExit(1)
	if args.filetype.lower() in ZEEK_NO_PORTS:
		stats = Zeek(
			args.infiles,
			ports = False,
			grep=args.grep,
			blacklist=args.blacklist
		)
	elif args.filetype.lower() in ZEEK_PORTS:
		stats = Zeek(
			args.infiles,
			ports = True,
			grep=args.grep,
			blacklist=args.blacklist
		)
	elif args.filetype.lower() in IPRUNNER:
		stats = IPRunner(
			args.infiles,
			grep=args.grep,
			blacklist=args.blacklist
		)
	else:
		print('Error: Unknown input file type.', file=StdErr)
		SysExit(1)
	if args.vis:
		if not stats.vis_available:
			print('Error: Visualisation is not available.', file=StdErr)
			SysExit(1)
		netvis = NetVis(args.outfile, stats, maxnodes=args.max)
		netvis.write()
	else:
		csv = CSVGenerator(
			args.outfile,
			stats,
			noheadline=args.noheadline,
			maxout=args.max,
			reverse=args.reverse,
			unixtime=args.unixtime,
			humanreadable=args.readable
		)
		csv.write()
	SysExit(0)

