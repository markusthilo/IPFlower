#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Markus Thilo'
__version__ = '0.8-20201015'
__license__ = 'GPL-3'

from lib.zeekstats import CalcZeek
from lib.iprunner import IPRunner
from lib.tsv import TSVGenerator
from lib.netvis import NetVis
from argparse import ArgumentParser, FileType
from ipaddress import ip_address
from sys import stdout as StdOut
from sys import stderr as StdErr
from sys import exit as SysExit

if __name__ == '__main__':	# start here if called as application
	argparser = ArgumentParser(description='Visualize netflow data')
	argparser.add_argument('-i', '--in', dest='filetype', default='z',
		help='Type of input file(s), default is zeek', metavar='SWITCH'
	)
	argparser.add_argument('-g', '--grep', dest='grep',
		help='Target IP address', metavar='IP_ADDRESS/LINK',
		type=lambda addr: ip_address(addr)
	)
	argparser.add_argument('-b', '--blacklist', nargs=1, type=FileType('rt'),
		help='File with blacklisted IP addresses', metavar='FILE'
	)
	argparser.add_argument('-m', '--max', type=int,
		help='Maximum number of IP addresses to visualize', metavar='INTEGER'
	)
	argparser.add_argument('-o', '--out', default='t',
		help='Output Format, default is tsv', metavar='SWITCH'
	)
	argparser.add_argument('-c', '--colnames', action='store_true',
		help='Give headlines = column names on TSV output'
	)
	argparser.add_argument('-r', '--reverse', action='store_true',
		help='Reverse order on TSV output'
	)
	argparser.add_argument('-u', '--unixtime', action='store_true',
		help='Unix timestamps (seconds and microseconds) on TSV output'
	)
	argparser.add_argument('-w', '--outfile', type=FileType('w'), default=StdOut,
		help='File to write', metavar='FILE'
	)
	argparser.add_argument('infiles', nargs='+', type=FileType('rt'),
		help='File(s) to read, at least one is required', metavar='FILE'
	)
	args = argparser.parse_args()
	if args.filetype.lower() in ('z', 'zeek', 'zeek-log'):
		stats = CalcZeek(
			args.infiles,
			grep=args.grep,
			blacklist=args.blacklist
		)
	elif args.filetype.lower() in ('p', 'iprunner', 'pcap'):
		stats = IPRunner(
			args.infiles,
			grep=args.grep,
			blacklist=args.blacklist
		)
	else:
		print('Error: Unknown input file type.', file=StdErr)
		SysExit(1)
	if args.out.lower() in ('t', 'tsv'):
		tsv = TSVGenerator(
			stats,
			colnames=args.colnames,
			maxout=args.max,
			reverse=args.reverse,
			unixtime=args.unixtime,
		)
		tsv.write(args.outfile)
	elif args.out.lower() in ('n', 'nv', 'netvis'):
		netvis = NetVis(stats, maxout=args.max)
		netvis.write(args.outfile)
	else:
		print(stats.data)	# debug!!!!!!!
		print('Error: Unknown -o / --out argument.', file=StdErr)
		SysExit(1)
	SysExit(0)

