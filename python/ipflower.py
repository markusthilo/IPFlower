#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Markus Thilo'
__version__ = '0.8-20201126'
__license__ = 'GPL-3'

from lib.zeekstats import CalcZeek
from lib.iprunner import IPRunner
from lib.basicinout import CSVGenerator
from lib.netvis import NetVis
from argparse import ArgumentParser, FileType
from sys import stdout as StdOut
from sys import stderr as StdErr
from sys import exit as SysExit
from configparser import ConfigParser
from pathlib import Path

CONFIG = {
	geolite2dir: '.',
	geolite2country: 'GeoLite2-Country.mmdb',
	geolite2asn: 'GeoLite2-ASN.mmdb',
	visjsdir: 'visjs'
}

if __name__ == '__main__':	# start here if called as application
	argparser = ArgumentParser(description='Visualize netflow data')

	argparser.add_argument('-b', '--blacklist', nargs=1, type=FileType('rt'),
		help='File with blacklisted = suppressed IP addresses', metavar='FILE'
	)
	argparser.add_argument('-c', '--config', nargs=1, type=FileType('rt'),
		help='Cofiguration File', metavar='FILE'
	)
	argparser.add_argument('-d', '--outdir', type=FileType('w'), default=StdOut,
		help='File to write', metavar='FILE'
	)
	argparser.add_argument('-g', '--grep', dest='grep',
		help='Target IP address', metavar='IP_ADDRESS/LINK',
		type=str
	)
	argparser.add_argument('-i', '--in', dest='filetype', default='z',
		help='Type of input file(s), default is zeek', metavar='SWITCH'
	)
	argparser.add_argument('-m', '--max', type=int,
		help='Maximum number of IP addresses to visualize', metavar='INTEGER'
	)
	argparser.add_argument('-n', '--noheadline', action='store_true',
		help='Give headlines = column names on CSV output'
	)
	argparser.add_argument('-o', '--out', default='t',
		help='Output Format, default is tsv', metavar='SWITCH'
	)
	argparser.add_argument('-r', '--reverse', action='store_true',
		help='Reverse order on TSV output'
	)
	argparser.add_argument('-u', '--unixtime', action='store_true',
		help='Unix timestamps (seconds and microseconds) on CSV output'
	)
	argparser.add_argument('-w', '--outfile', type=FileType('w'), default=StdOut,
		help='File to write', metavar='FILE'
	)
	argparser.add_argument('-y', '--bytes', action='store_true',
		help='Data volume in pure bytes (no B, KB, MB etc.) on CSV output'
	)
	argparser.add_argument('infiles', nargs='+', type=FileType('rt'),
		help='File(s) to read, at least one is required', metavar='FILE'
	)
	args = argparser.parse_args()
	if args.filetype.lower() in ('z', 'zeek', 'zeek-log'):
		stats = CalcZeek(
			args.infiles,
			config,
			grep=args.grep,
			blacklist=args.blacklist
		)
	elif args.filetype.lower() in ('i', 'iprunner', 'ip'):
		stats = IPRunner(
			args.infiles,
			config,
			grep=args.grep,
			blacklist=args.blacklist
		)
	else:
		print('Error: Unknown input file type.', file=StdErr)
		SysExit(1)
	if 		
		
		
		
		
	if args.out.lower() in ('t', 'tsv'):
		csv = CSVGenerator(
			stats,
			headline=not args.noheadline,
			maxout=args.max,
			reverse=args.reverse,
			unixtime=args.unixtime,
		)
		csv.write(args.outfile)
	elif args.out.lower() in ('n', 'nv', 'netvis'):
		netvis = NetVis(stats, maxnodes=args.max)
		netvis.write(args.outfile)
	else:
		print(stats.data)	# debug!!!!!!!
		print('Error: Unknown -o / --out argument.', file=StdErr)
		SysExit(1)
	SysExit(0)

